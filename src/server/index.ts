import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import db, { appendAudit, DATA_DIR_PATH, sha256hex } from '../db';
import { validateUrl } from '../ssrf';
import { checkSiteLive } from '../siteCheck';
import { discoverConnectedHosts } from '../worker';
import { computePortfolioIntelligence } from '../intelligence';
import { generateSecurityBriefing } from '../llm';

const app = express();
const PORT = process.env.PORT || 3000;

// Trust exactly one proxy hop (Render/most PaaS put one reverse proxy in front).
// Without this, req.ip is the proxy address, which breaks per-IP rate limiting
// and records the wrong client IP in the audit log. We intentionally do NOT use
// `true` (trust all), which would let a client spoof X-Forwarded-For.
app.set('trust proxy', 1);

// Hard limits to prevent asset-flood resource exhaustion (a defender can only
// meaningfully monitor a handful of sites; an attacker who reaches the admin
// role must not be able to register thousands and drown the worker).
const MAX_ACTIVE_ASSETS = 25;
const MAX_ASSET_NAME_LEN = 200;

// Clamp a client-supplied page size to a sane range so a single request can't
// ask for an unbounded result set.
const MAX_PAGE_SIZE = 100;
function clampLimit(raw: unknown, fallback = 50): number {
  const n = parseInt(String(raw ?? ''), 10);
  if (isNaN(n) || n < 1) return fallback;
  return Math.min(n, MAX_PAGE_SIZE);
}

// Precomputed bcrypt hash of a random string, used as a decoy when a username
// is not found so failed logins spend the same time as real ones (anti-enumeration).
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);

// Public-facing label for the risk engine — the concrete AI provider/model is
// never disclosed to clients.
const PUBLIC_AI_LABEL = 'KavachAI';

// Security Middleware: Helmet with strict Content Security Policy (CSP).
// The Vite build emits external module scripts only, so no 'unsafe-inline'
// is needed for script-src — keeping it out is what makes the CSP an actual
// XSS control rather than decoration.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"], // no unsafe-inline: built assets are external files
        // Inline style attributes (React style={{...}}) require 'unsafe-inline'
        // for style-src; this does not open a script-execution path.
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

// CORS: the SPA is served same-origin by this very process, so cross-origin
// credentialed access is never legitimate in production. Reflecting an
// arbitrary Origin with credentials:true (the previous behaviour) is a
// standing CSRF/data-exfil hazard. Restrict to an explicit allow-list; the
// Vite dev server origin is permitted only outside production.
const corsAllowList = new Set<string>(
  (process.env.CORS_ORIGINS || 'http://localhost:5173')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean)
);
app.use(
  cors({
    credentials: true,
    origin: (origin, callback) => {
      // Same-origin / non-browser requests send no Origin header — always allow.
      if (!origin) return callback(null, true);
      if (process.env.NODE_ENV !== 'production' && corsAllowList.has(origin)) {
        return callback(null, true);
      }
      // In production the SPA is same-origin, so any cross-origin request is rejected.
      return callback(null, false);
    },
  })
);
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser(process.env.SESSION_SECRET || 'fallback_session_secret_128_bit_random_string'));

// Global Session Store (in-memory, mapped to standard cookie session behavior)
interface Session {
  userId: number;      // for per-user access scoping
  username: string;
  role: 'admin' | 'viewer';
  expiresAt: number;   // absolute expiry (hard cap)
  lastSeenAt: number;  // updated per request; drives the idle timeout
  uaHash: string;      // binds the session to the client that created it
}
export const sessionStore = new Map<string, Session>();

// Session timing is configurable via environment (with safe defaults):
//   SESSION_TTL_HOURS     absolute lifetime cap (default 12h)
//   SESSION_IDLE_MINUTES  idle timeout; no activity for this long invalidates it (default 30m)
const SESSION_TTL_MS = (parseInt(process.env.SESSION_TTL_HOURS || '12', 10) || 12) * 60 * 60 * 1000;
const SESSION_IDLE_MS = (parseInt(process.env.SESSION_IDLE_MINUTES || '30', 10) || 30) * 60 * 1000;

// Fingerprint the requesting client. Binding the session to a hash of the
// User-Agent means a stolen/copied cookie replayed from a different browser or
// tool (Burp, curl, another machine) will not match and is rejected. This is
// defense-in-depth, not a substitute for httpOnly/Secure/SameSite.
function uaFingerprint(req: Request): string {
  return sha256hex(String(req.headers['user-agent'] || ''));
}

// Session cleanup interval
setInterval(() => {
  const now = Date.now();
  for (const [sid, session] of sessionStore.entries()) {
    if (session.expiresAt < now || now - session.lastSeenAt > SESSION_IDLE_MS) {
      sessionStore.delete(sid);
    }
  }
}, 60 * 1000);

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        username: string;
        role: 'admin' | 'viewer';
      };
    }
  }
}

// Global API rate limit (resource-exhaustion defense, spec §6.5). Applies to
// every /api route; the stricter per-login limiter is layered on top below.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120, // 120 requests/min/IP
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: { code: 'TOO_MANY_REQUESTS', message: 'Rate limit exceeded. Slow down.' } });
  },
});
app.use('/api', apiLimiter);

// Global Deny-by-Default Middleware.
// Only /api/auth/login and /api/health are public. Everything else under /api
// requires a valid session. Non-/api paths (the static SPA) pass through.
// There is deliberately NO token-based bypass for screenshots: the previous
// `?token=` path let anyone holding SESSION_SECRET read captures out-of-band
// and turned the cookie-signing secret into a bearer credential.
app.use((req: Request, res: Response, next: NextFunction) => {
  const publicPaths = ['/api/auth/login', '/api/auth/register', '/api/health'];
  if (publicPaths.includes(req.path) || !req.path.startsWith('/api')) {
    // Public API endpoints or static content pass through; all other /api
    // routes fall through to the session check below.
    return next();
  }

  const sid = req.signedCookies.sid;
  if (!sid) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
  }

  const session = sessionStore.get(sid);
  const now = Date.now();
  const invalid =
    !session ||
    session.expiresAt < now ||                       // past hard cap
    now - session.lastSeenAt > SESSION_IDLE_MS ||     // idle too long
    session.uaHash !== uaFingerprint(req);            // cookie replayed from a different client

  if (invalid) {
    if (session) sessionStore.delete(sid);
    res.clearCookie('sid');
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Session expired or invalid' } });
  }

  session.lastSeenAt = now; // sliding idle window
  req.user = { id: session.userId, username: session.username, role: session.role };
  next();
});

// Helpers for per-user access scoping. Admins see everything; viewers see only
// the assets explicitly assigned to them. Every read route that exposes
// asset-linked data must go through these, or it becomes an IDOR.
function accessibleAssetIds(user: { id: number; role: string }): number[] | 'all' {
  if (user.role === 'admin') return 'all';
  const rows = db.prepare('SELECT asset_id FROM asset_assignments WHERE user_id = ?').all(user.id) as any[];
  return rows.map((r) => r.asset_id);
}

function canAccessAsset(user: { id: number; role: string }, assetId: number): boolean {
  if (user.role === 'admin') return true;
  const row = db
    .prepare('SELECT 1 FROM asset_assignments WHERE user_id = ? AND asset_id = ?')
    .get(user.id, assetId);
  return !!row;
}

type CreateAssetOutcome =
  | { ok: true; assetId: number; nextCaptureAt: string }
  | { ok: false; status: number; code: string; message: string };

// Central asset creation: enforces the count cap, duplicate-URL rejection,
// SSRF validation, and the parked/dead-site block, then inserts + audits.
// Used by admin create and by request approval so both paths are identical.
async function createMonitoredAsset(params: {
  name: string;
  url: string;
  interval: number;
  actor: string;
  parentAssetId?: number | null;
  liveCheck?: boolean; // default true; false = SSRF-validate only (used for discovered children)
}): Promise<CreateAssetOutcome> {
  const activeCount = (db.prepare('SELECT COUNT(*) AS c FROM assets WHERE is_deleted = 0').get() as any).c;
  if (activeCount >= MAX_ACTIVE_ASSETS) {
    return { ok: false, status: 409, code: 'ASSET_LIMIT_REACHED', message: `Maximum of ${MAX_ACTIVE_ASSETS} monitored assets reached` };
  }
  const duplicate = db.prepare('SELECT id FROM assets WHERE is_deleted = 0 AND url = ?').get(params.url);
  if (duplicate) {
    return { ok: false, status: 409, code: 'DUPLICATE_URL', message: 'An asset with this URL is already registered' };
  }

  if (params.liveCheck === false) {
    // Discovered children came from an already-rendered real page; skip the
    // heavy parked-render and just SSRF-validate the origin.
    const v = await validateUrl(params.url);
    if (!v.valid) {
      return { ok: false, status: 400, code: 'INVALID_SITE', message: v.error || 'URL failed validation' };
    }
  } else {
    const live = await checkSiteLive(params.url);
    if (!live.ok) {
      return { ok: false, status: 400, code: live.parked ? 'PARKED_DOMAIN' : 'INVALID_SITE', message: live.reason || 'URL failed validation' };
    }
  }

  const nextCaptureAt = new Date(Date.now() + 5000).toISOString();
  const result = db.prepare(
    'INSERT INTO assets (name, url, interval_seconds, next_capture_at, parent_asset_id) VALUES (?, ?, ?, ?, ?)'
  ).run(params.name, params.url, params.interval, nextCaptureAt, params.parentAssetId ?? null);
  const assetId = Number(result.lastInsertRowid);
  appendAudit(params.actor, 'asset.create', 'assets', assetId, {
    name: params.name,
    url: params.url,
    interval_seconds: params.interval,
    parent_asset_id: params.parentAssetId ?? null,
  });
  return { ok: true, assetId, nextCaptureAt };
}

// RBAC Role Enforcement Middleware
function requireRole(role: 'admin' | 'viewer') {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    }
    if (role === 'admin' && req.user.role !== 'admin') {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Administrator role required' } });
    }
    next();
  };
}

// Rate Limiter for login
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // Limit each IP to 5 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: { code: 'TOO_MANY_REQUESTS', message: 'Too many login attempts. Please try again in a minute.' } });
  },
});

// 1. POST /api/auth/login [public]
app.post('/api/auth/login', loginLimiter, (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Username and password required' } });
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Username and password must be strings' } });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as any;
    // Always run a bcrypt comparison, even when the user does not exist, so the
    // response time does not reveal whether a username is valid (no enumeration).
    const passwordOk = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_BCRYPT_HASH);
    if (!user || !passwordOk) {
      appendAudit(typeof username === 'string' ? username : 'anonymous', 'user.login_failed', 'users', null, { ip: req.ip });
      return res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' } });
    }

    // Only approved (active) accounts may sign in. Self-registered viewers start
    // 'pending' until an admin approves them.
    if (user.status && user.status !== 'active') {
      appendAudit(user.username, 'user.login_blocked', 'users', user.id, { status: user.status });
      const message =
        user.status === 'pending'
          ? 'Your account is awaiting administrator approval.'
          : 'This account has been disabled.';
      return res.status(403).json({ error: { code: 'ACCOUNT_NOT_ACTIVE', message } });
    }

    // Generate random 128-bit (16 bytes) session ID
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const expiresAt = now + SESSION_TTL_MS; // absolute cap (configurable)
    sessionStore.set(sessionId, {
      userId: user.id,
      username: user.username,
      role: user.role,
      expiresAt,
      lastSeenAt: now,
      uaHash: uaFingerprint(req),
    });

    res.cookie('sid', sessionId, {
      signed: true,
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: SESSION_TTL_MS,
    });

    appendAudit(user.username, 'user.login', 'users', user.id, { ip: req.ip });
    return res.json({ data: { username: user.username, role: user.role } });
  } catch (err: any) {
    console.error('Login error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 1b. POST /api/auth/register [public] — self-service viewer signup. The account
// is created 'pending' and cannot log in until an admin approves it.
const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: { code: 'TOO_MANY_REQUESTS', message: 'Too many registration attempts. Try again shortly.' } });
  },
});

app.post('/api/auth/register', registerLimiter, (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Username and password are required' } });
  }
  const uname = username.trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(uname) || uname.length > 254) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Please provide a valid email address as your username' } });
  }
  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Password must be at least 8 characters' } });
  }

  try {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(uname);
    if (existing) {
      // Do not reveal whether the account exists; respond the same either way.
      return res.status(202).json({ data: { status: 'pending', message: 'Registration received. An administrator must approve your account before you can sign in.' } });
    }
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, 'viewer', 'pending')").run(uname, hash);
    appendAudit('system', 'user.register', 'users', Number(result.lastInsertRowid), { username: uname, role: 'viewer' });
    return res.status(202).json({ data: { status: 'pending', message: 'Registration received. An administrator must approve your account before you can sign in.' } });
  } catch (err: any) {
    console.error('Register error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 2. POST /api/auth/logout [V]
app.post('/api/auth/logout', (req: Request, res: Response) => {
  const sid = req.signedCookies.sid;
  if (sid) {
    sessionStore.delete(sid);
  }
  res.clearCookie('sid');
  if (req.user) {
    appendAudit(req.user.username, 'user.logout', 'users', null, {});
  }
  return res.json({ data: { success: true } });
});

// 2b. POST /api/auth/logout-all [V] — revoke every active session for the
// current user (e.g. after suspected cookie theft). Because sessions are held
// server-side, revocation is immediate: any stolen/copied cookie stops working
// on its next request.
app.post('/api/auth/logout-all', (req: Request, res: Response) => {
  if (req.user) {
    let revoked = 0;
    for (const [sid, session] of sessionStore.entries()) {
      if (session.username === req.user.username) {
        sessionStore.delete(sid);
        revoked++;
      }
    }
    appendAudit(req.user.username, 'user.logout_all', 'users', null, { revoked });
  }
  res.clearCookie('sid');
  return res.json({ data: { success: true } });
});

// 3. GET /api/auth/me [V]
app.get('/api/auth/me', (req: Request, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Not logged in' } });
  }
  return res.json({ data: { username: req.user.username, role: req.user.role } });
});

// 3b. GET /api/notifications [V] — small counts for nav badges / alerts.
// Admin: pending monitoring requests. Viewer: high-severity ("considerable
// risk") alerts on their own assigned sites only.
app.get('/api/notifications', (req: Request, res: Response) => {
  try {
    if (req.user!.role === 'admin') {
      const pendingRequests = (db.prepare("SELECT COUNT(*) AS c FROM monitoring_requests WHERE status = 'pending'").get() as any).c;
      return res.json({ data: { pendingRequests } });
    }
    const access = accessibleAssetIds(req.user!);
    let highRiskAlerts = 0;
    if (access !== 'all' && access.length > 0) {
      const ph = access.map(() => '?').join(',');
      highRiskAlerts = (db.prepare(`SELECT COUNT(*) AS c FROM alert_events WHERE severity = 'high' AND asset_id IN (${ph})`).get(...access) as any).c;
    }
    return res.json({ data: { highRiskAlerts } });
  } catch (err: any) {
    console.error('Notifications error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 4. GET /api/assets [V]
app.get('/api/assets', (req: Request, res: Response) => {
  try {
    const access = accessibleAssetIds(req.user!);
    let assets: any[];
    if (access === 'all') {
      assets = db.prepare(`
        SELECT id, name, url, is_active, interval_seconds, created_at, parent_asset_id
        FROM assets WHERE is_deleted = 0 ORDER BY id ASC
      `).all() as any[];
    } else if (access.length === 0) {
      assets = [];
    } else {
      const placeholders = access.map(() => '?').join(',');
      assets = db.prepare(`
        SELECT id, name, url, is_active, interval_seconds, created_at, parent_asset_id
        FROM assets WHERE is_deleted = 0 AND id IN (${placeholders}) ORDER BY id ASC
      `).all(...access) as any[];
    }

    const result = assets.map((asset) => {
      // Find latest snapshot details
      const latestSnapshot = db.prepare(`
        SELECT id, captured_at, http_status, fetch_error
        FROM snapshots
        WHERE asset_id = ?
        ORDER BY captured_at DESC
        LIMIT 1
      `).get(asset.id) as any;

      let latest_snapshot = null;
      let vuln_state: string[] = [];

      if (latestSnapshot) {
        const diffResult = db.prepare(`
          SELECT visual_changed, text_changed
          FROM diff_results
          WHERE snapshot_id = ?
        `).get(latestSnapshot.id) as any;

        const failedChecks = db.prepare(`
          SELECT check_type
          FROM vuln_check_results
          WHERE snapshot_id = ? AND passed = 0
        `).all(latestSnapshot.id) as any[];

        vuln_state = failedChecks.map(c => c.check_type);

        latest_snapshot = {
          id: latestSnapshot.id,
          captured_at: latestSnapshot.captured_at,
          http_status: latestSnapshot.http_status,
          fetch_error: latestSnapshot.fetch_error,
          visual_changed: diffResult ? diffResult.visual_changed : 0,
          text_changed: diffResult ? diffResult.text_changed : 0,
        };
      }

      return {
        ...asset,
        latest_snapshot,
        vuln_state,
      };
    });

    return res.json({ data: result });
  } catch (err: any) {
    console.error('Fetch assets error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 5. POST /api/assets [A]
app.post('/api/assets', requireRole('admin'), async (req: Request, res: Response) => {
  const { name, url, interval_seconds } = req.body;
  if (!name || !url || typeof name !== 'string' || typeof url !== 'string') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Name and URL are required' } });
  }
  if (name.length > MAX_ASSET_NAME_LEN) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: `Name must be at most ${MAX_ASSET_NAME_LEN} characters` } });
  }

  const interval = interval_seconds ? parseInt(interval_seconds, 10) : 180;
  if (isNaN(interval) || interval < 120 || interval > 300) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Interval must be between 120 and 300 seconds' } });
  }

  try {
    const outcome = await createMonitoredAsset({ name, url, interval, actor: req.user!.username });
    if (!outcome.ok) {
      return res.status(outcome.status).json({ error: { code: outcome.code, message: outcome.message } });
    }
    return res.status(201).json({
      data: {
        id: outcome.assetId,
        name,
        url,
        is_active: 1,
        is_deleted: 0,
        interval_seconds: interval,
        next_capture_at: outcome.nextCaptureAt,
      },
    });
  } catch (err: any) {
    console.error('Create asset error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 6. PATCH /api/assets/:id [A]
app.patch('/api/assets/:id', requireRole('admin'), (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  if (isNaN(assetId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }

  const { name, is_active } = req.body;
  if (name === undefined && is_active === undefined) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'At least one of name or is_active is required' } });
  }

  try {
    const asset = db.prepare('SELECT * FROM assets WHERE id = ? AND is_deleted = 0').get(assetId) as any;
    if (!asset) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } });
    }

    const updatedName = name !== undefined ? name : asset.name;
    const updatedActive = is_active !== undefined ? (is_active ? 1 : 0) : asset.is_active;

    db.prepare(`
      UPDATE assets
      SET name = ?, is_active = ?
      WHERE id = ?
    `).run(updatedName, updatedActive, assetId);

    appendAudit(req.user!.username, 'asset.update', 'assets', assetId, {
      name: updatedName,
      is_active: updatedActive,
      prev_name: asset.name,
      prev_active: asset.is_active,
    });

    return res.json({
      data: {
        id: assetId,
        name: updatedName,
        url: asset.url, // URL is immutable
        is_active: updatedActive,
        interval_seconds: asset.interval_seconds,
        next_capture_at: asset.next_capture_at,
      },
    });
  } catch (err: any) {
    console.error('Update asset error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 7. DELETE /api/assets/:id [A]
app.delete('/api/assets/:id', requireRole('admin'), (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  if (isNaN(assetId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }

  try {
    const asset = db.prepare('SELECT * FROM assets WHERE id = ? AND is_deleted = 0').get(assetId) as any;
    if (!asset) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } });
    }

    // Soft-delete the asset AND any child sites discovered under it, so children
    // never linger as orphans (invisible, but still counting against the cap).
    db.prepare('UPDATE assets SET is_deleted = 1, is_active = 0 WHERE id = ? OR parent_asset_id = ?')
      .run(assetId, assetId);

    appendAudit(req.user!.username, 'asset.delete', 'assets', assetId, { name: asset.name });

    return res.json({ data: { success: true } });
  } catch (err: any) {
    console.error('Delete asset error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 8. GET /api/assets/:id/snapshots [V]
app.get('/api/assets/:id/snapshots', (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  if (isNaN(assetId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }
  if (!canAccessAsset(req.user!, assetId)) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } });
  }

  const limit = clampLimit(req.query.limit);
  const before = req.query.before ? parseInt(req.query.before as string, 10) : null;

  try {
    let query = `
      SELECT id, asset_id, captured_at, http_status, fetch_error, phash, html_sha256
      FROM snapshots
      WHERE asset_id = ?
    `;
    const params: any[] = [assetId];

    if (before) {
      query += ` AND id < ?`;
      params.push(before);
    }

    query += ` ORDER BY captured_at DESC LIMIT ?`;
    params.push(limit);

    const snapshots = db.prepare(query).all(...params) as any[];

    const result = snapshots.map((s) => {
      const diff = db.prepare('SELECT visual_distance, visual_changed, text_changed FROM diff_results WHERE snapshot_id = ?').get(s.id) as any;
      const vulns = db.prepare('SELECT check_type, passed FROM vuln_check_results WHERE snapshot_id = ?').all(s.id) as any[];
      return {
        ...s,
        diff_result: diff || null,
        vuln_checks: vulns,
      };
    });

    return res.json({ data: result });
  } catch (err: any) {
    console.error('Fetch snapshots error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 9. GET /api/snapshots/:id [V]
app.get('/api/snapshots/:id', (req: Request, res: Response) => {
  const snapshotId = parseInt(req.params.id, 10);
  if (isNaN(snapshotId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid snapshot ID' } });
  }

  try {
    const snapshot = db.prepare('SELECT * FROM snapshots WHERE id = ?').get(snapshotId) as any;
    if (!snapshot) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } });
    }
    if (!canAccessAsset(req.user!, snapshot.asset_id)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Snapshot not found' } });
    }

    const diffResult = db.prepare('SELECT * FROM diff_results WHERE snapshot_id = ?').get(snapshotId) as any;
    const vulnResults = db.prepare('SELECT * FROM vuln_check_results WHERE snapshot_id = ?').all(snapshotId) as any[];

    // Parse headers JSON safely
    let headers = {};
    try {
      headers = JSON.parse(snapshot.response_headers || '{}');
    } catch {
      // ignore
    }

    // Never expose absolute server file paths to clients (info disclosure /
    // recon aid). Replace them with booleans; the screenshot/html endpoints are
    // addressed by snapshot id, not by path.
    const { screenshot_path, html_path, ...safeSnapshot } = snapshot;

    return res.json({
      data: {
        ...safeSnapshot,
        response_headers: headers,
        screenshot_available: !!screenshot_path,
        html_available: !!html_path,
        diff_result: diffResult || null,
        vuln_results: vulnResults,
      },
    });
  } catch (err: any) {
    console.error('Fetch snapshot detail error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 10. GET /api/snapshots/:id/screenshot [V]
app.get('/api/snapshots/:id/screenshot', (req: Request, res: Response) => {
  // Auth is already enforced by the global deny-by-default middleware; req.user
  // is guaranteed present here. No token bypass exists.
  const snapshotId = parseInt(req.params.id, 10);
  if (isNaN(snapshotId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid snapshot ID' } });
  }

  try {
    const snapshot = db.prepare('SELECT asset_id, screenshot_path FROM snapshots WHERE id = ?').get(snapshotId) as any;
    if (!snapshot || !snapshot.screenshot_path) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Screenshot not found' } });
    }
    if (!canAccessAsset(req.user!, snapshot.asset_id)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Screenshot not found' } });
    }

    const filePath = snapshot.screenshot_path;
    const absolutePath = path.resolve(filePath);
    const absoluteScreensDir = path.resolve(path.join(DATA_DIR_PATH, 'screens'));

    // Path traversal defense. Append path.sep so a sibling dir sharing the
    // prefix (e.g. /data/screens-evil) can never satisfy the check.
    if (absolutePath !== absoluteScreensDir && !absolutePath.startsWith(absoluteScreensDir + path.sep)) {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Path traversal blocked' } });
    }

    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({ error: { code: 'FILE_MISSING', message: 'Screenshot file does not exist on disk' } });
    }

    return res.sendFile(absolutePath);
  } catch (err: any) {
    console.error('Serve screenshot error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 11. GET /api/snapshots/:id/html [V]
app.get('/api/snapshots/:id/html', (req: Request, res: Response) => {
  const snapshotId = parseInt(req.params.id, 10);
  if (isNaN(snapshotId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid snapshot ID' } });
  }

  try {
    const snapshot = db.prepare('SELECT asset_id, html_path FROM snapshots WHERE id = ?').get(snapshotId) as any;
    if (!snapshot || !snapshot.html_path) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'HTML capture not found' } });
    }
    if (!canAccessAsset(req.user!, snapshot.asset_id)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'HTML capture not found' } });
    }

    const filePath = snapshot.html_path;
    const absolutePath = path.resolve(filePath);
    const absoluteHtmlDir = path.resolve(path.join(DATA_DIR_PATH, 'html'));

    // Path traversal defense (exact dir or a child under it, never a prefix sibling).
    if (absolutePath !== absoluteHtmlDir && !absolutePath.startsWith(absoluteHtmlDir + path.sep)) {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Path traversal blocked' } });
    }

    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({ error: { code: 'FILE_MISSING', message: 'HTML file does not exist on disk' } });
    }

    // Serve strictly as plain text, no execution risk
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.sendFile(absolutePath);
  } catch (err: any) {
    console.error('Serve HTML error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 12. GET /api/alerts [V]
app.get('/api/alerts', (req: Request, res: Response) => {
  const { severity, kind, asset_id, limit, before } = req.query;

  const resultLimit = clampLimit(limit);
  const beforeId = before ? parseInt(before as string, 10) : null;

  try {
    let query = `
      SELECT id, asset_id, snapshot_id, kind, title, severity, ai_explanation, ai_remediation, ai_model, ai_error, created_at
      FROM alert_events
      WHERE 1=1
    `;
    const params: any[] = [];

    // Access scoping: viewers only see alerts for assets assigned to them.
    const access = accessibleAssetIds(req.user!);
    if (access !== 'all') {
      if (access.length === 0) {
        return res.json({ data: [] });
      }
      query += ` AND asset_id IN (${access.map(() => '?').join(',')})`;
      params.push(...access);
    }

    if (severity) {
      query += ` AND severity = ?`;
      params.push(severity);
    }
    if (kind) {
      query += ` AND kind = ?`;
      params.push(kind);
    }
    if (asset_id) {
      query += ` AND asset_id = ?`;
      params.push(parseInt(asset_id as string, 10));
    }
    if (beforeId) {
      query += ` AND id < ?`;
      params.push(beforeId);
    }

    query += ` ORDER BY created_at DESC LIMIT ?`;
    params.push(resultLimit);

    const alerts = db.prepare(query).all(...params) as any[];

    // Include asset information, and sanitize AI metadata so the concrete
    // provider/model and any raw upstream error never reach a client. This also
    // scrubs older rows that were stored before the engine was made generic.
    const alertsWithAssets = alerts.map((alert) => {
      const asset = db.prepare('SELECT name, url FROM assets WHERE id = ?').get(alert.asset_id) as any;
      return {
        ...alert,
        ai_model: alert.ai_model ? PUBLIC_AI_LABEL : null,
        ai_error: alert.ai_error ? 'AI risk scoring was unavailable for this alert.' : null,
        asset_name: asset ? asset.name : 'Unknown Asset',
        asset_url: asset ? asset.url : '',
      };
    });

    return res.json({ data: alertsWithAssets });
  } catch (err: any) {
    console.error('Fetch alerts error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 13. GET /api/audit [A]
app.get('/api/audit', requireRole('admin'), (req: Request, res: Response) => {
  const limit = clampLimit(req.query.limit);
  const before = req.query.before ? parseInt(req.query.before as string, 10) : null;

  try {
    let query = `
      SELECT seq, created_at, actor, action, entity_type, entity_id, details_json, prev_hash, entry_hash
      FROM audit_log
    `;
    const params: any[] = [];

    if (before) {
      query += ` WHERE seq < ?`;
      params.push(before);
    }

    query += ` ORDER BY seq DESC LIMIT ?`;
    params.push(limit);

    const logs = db.prepare(query).all(...params) as any[];
    const result = logs.map((log) => {
      let details = {};
      try {
        details = JSON.parse(log.details_json);
      } catch {
        // ignore
      }
      return {
        ...log,
        details,
      };
    });

    return res.json({ data: result });
  } catch (err: any) {
    console.error('Fetch audit log error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 14. GET /api/audit/verify [A]
app.get('/api/audit/verify', requireRole('admin'), (req: Request, res: Response) => {
  try {
    const logs = db.prepare(`
      SELECT seq, created_at, actor, action, entity_type, entity_id, details_json, prev_hash, entry_hash
      FROM audit_log
      ORDER BY seq ASC
    `).all() as any[];

    if (logs.length === 0) {
      return res.json({ data: { valid: true } });
    }

    let expectedPrevHash = '0'.repeat(64);

    for (let i = 0; i < logs.length; i++) {
      const row = logs[i];
      const seq = row.seq;

      // 1. Assert seq sequence contains no gaps and starts at 1
      if (seq !== i + 1) {
        return res.json({ data: { valid: false, first_bad_seq: seq } });
      }

      // 2. Validate prev_hash equals matches the actual computed prevHash
      if (row.prev_hash !== expectedPrevHash) {
        return res.json({ data: { valid: false, first_bad_seq: seq } });
      }

      // 3. Recompute hash canonical and entry hash
      const canonical = [
        'v1',
        seq,
        row.created_at,
        row.actor,
        row.action,
        row.entity_type ?? '',
        row.entity_id?.toString() ?? '',
        sha256hex(row.details_json),
        row.prev_hash,
      ].join('|');

      const computedEntryHash = sha256hex(canonical);

      if (row.entry_hash !== computedEntryHash) {
        return res.json({ data: { valid: false, first_bad_seq: seq } });
      }

      expectedPrevHash = row.entry_hash;
    }

    return res.json({ data: { valid: true } });
  } catch (err: any) {
    console.error('Verify audit log chain error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 15. GET /api/health [public]
app.get('/api/health', (req: Request, res: Response) => {
  return res.json({ ok: true });
});

// ---- User management (admin) ----

// 16. GET /api/users [A]
app.get('/api/users', requireRole('admin'), (req: Request, res: Response) => {
  const users = db.prepare('SELECT id, username, role, status, created_at FROM users ORDER BY id ASC').all();
  return res.json({ data: users });
});

// 17. PATCH /api/users/:id [A] — approve (active) or disable an account
app.patch('/api/users/:id', requireRole('admin'), (req: Request, res: Response) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid user ID' } });
  }
  const { status } = req.body;
  if (status !== 'active' && status !== 'disabled') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: "status must be 'active' or 'disabled'" } });
  }
  const target = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(userId) as any;
  if (!target) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'User not found' } });
  }
  if (target.role === 'admin') {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Cannot change an administrator account' } });
  }
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, userId);
  if (status === 'disabled') {
    for (const [sid, s] of sessionStore.entries()) {
      if (s.userId === userId) sessionStore.delete(sid);
    }
  }
  appendAudit(req.user!.username, 'user.status_update', 'users', userId, { username: target.username, status });
  return res.json({ data: { id: userId, status } });
});

// ---- Monitoring requests ----

// 18. POST /api/requests [V] — a viewer asks for a site to be monitored
app.post('/api/requests', (req: Request, res: Response) => {
  const { name, url, note, interval_seconds } = req.body;
  if (typeof name !== 'string' || typeof url !== 'string' || !name.trim() || !url.trim()) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Name and URL are required' } });
  }
  if (name.length > MAX_ASSET_NAME_LEN) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: `Name must be at most ${MAX_ASSET_NAME_LEN} characters` } });
  }
  const interval = interval_seconds ? parseInt(interval_seconds, 10) : 180;
  if (isNaN(interval) || interval < 120 || interval > 300) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Interval must be between 120 and 300 seconds' } });
  }
  const noteVal = typeof note === 'string' ? note.slice(0, 1000) : null;
  const result = db.prepare(
    'INSERT INTO monitoring_requests (user_id, name, url, note, interval_seconds) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user!.id, name, url, noteVal, interval);
  appendAudit(req.user!.username, 'request.create', 'monitoring_requests', Number(result.lastInsertRowid), { name, url });
  return res.status(201).json({ data: { id: Number(result.lastInsertRowid), status: 'pending' } });
});

// 19. GET /api/requests/mine [V] — a viewer's own requests
app.get('/api/requests/mine', (req: Request, res: Response) => {
  const rows = db.prepare(
    'SELECT id, name, url, note, interval_seconds, status, created_at, resolved_at FROM monitoring_requests WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user!.id);
  return res.json({ data: rows });
});

// 20. GET /api/requests [A] — all requests (optionally ?status=pending)
app.get('/api/requests', requireRole('admin'), (req: Request, res: Response) => {
  const status = req.query.status as string | undefined;
  let rows;
  if (status === 'pending' || status === 'approved' || status === 'rejected') {
    rows = db.prepare(
      'SELECT r.id, r.name, r.url, r.note, r.interval_seconds, r.status, r.created_at, r.resolved_at, r.resolved_by, r.user_id, u.username AS requester FROM monitoring_requests r JOIN users u ON u.id = r.user_id WHERE r.status = ? ORDER BY r.created_at DESC'
    ).all(status);
  } else {
    rows = db.prepare(
      'SELECT r.id, r.name, r.url, r.note, r.interval_seconds, r.status, r.created_at, r.resolved_at, r.resolved_by, r.user_id, u.username AS requester FROM monitoring_requests r JOIN users u ON u.id = r.user_id ORDER BY r.created_at DESC'
    ).all();
  }
  return res.json({ data: rows });
});

// 21. POST /api/requests/:id/approve [A] — create the asset and grant the requester access
app.post('/api/requests/:id/approve', requireRole('admin'), async (req: Request, res: Response) => {
  const reqId = parseInt(req.params.id, 10);
  if (isNaN(reqId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid request ID' } });
  }
  const mr = db.prepare('SELECT * FROM monitoring_requests WHERE id = ?').get(reqId) as any;
  if (!mr) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Request not found' } });
  }
  if (mr.status !== 'pending') {
    return res.status(409).json({ error: { code: 'ALREADY_RESOLVED', message: 'This request has already been resolved' } });
  }
  try {
    const outcome = await createMonitoredAsset({ name: mr.name, url: mr.url, interval: mr.interval_seconds, actor: req.user!.username });
    if (!outcome.ok) {
      return res.status(outcome.status).json({ error: { code: outcome.code, message: outcome.message } });
    }
    db.prepare('INSERT OR IGNORE INTO asset_assignments (asset_id, user_id) VALUES (?, ?)').run(outcome.assetId, mr.user_id);
    db.prepare("UPDATE monitoring_requests SET status = 'approved', asset_id = ?, resolved_by = ?, resolved_at = ? WHERE id = ?")
      .run(outcome.assetId, req.user!.username, new Date().toISOString(), reqId);
    appendAudit(req.user!.username, 'request.approve', 'monitoring_requests', reqId, { asset_id: outcome.assetId, user_id: mr.user_id });
    return res.json({ data: { id: reqId, status: 'approved', asset_id: outcome.assetId } });
  } catch (err: any) {
    console.error('Approve request error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 22. POST /api/requests/:id/reject [A]
app.post('/api/requests/:id/reject', requireRole('admin'), (req: Request, res: Response) => {
  const reqId = parseInt(req.params.id, 10);
  if (isNaN(reqId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid request ID' } });
  }
  const mr = db.prepare('SELECT status FROM monitoring_requests WHERE id = ?').get(reqId) as any;
  if (!mr) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Request not found' } });
  }
  if (mr.status !== 'pending') {
    return res.status(409).json({ error: { code: 'ALREADY_RESOLVED', message: 'This request has already been resolved' } });
  }
  db.prepare("UPDATE monitoring_requests SET status = 'rejected', resolved_by = ?, resolved_at = ? WHERE id = ?")
    .run(req.user!.username, new Date().toISOString(), reqId);
  appendAudit(req.user!.username, 'request.reject', 'monitoring_requests', reqId, {});
  return res.json({ data: { id: reqId, status: 'rejected' } });
});

// ---- Asset assignments (admin) ----

// 23. GET /api/assets/:id/assignments [A]
app.get('/api/assets/:id/assignments', requireRole('admin'), (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  if (isNaN(assetId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }
  const rows = db.prepare(
    'SELECT a.user_id, u.username FROM asset_assignments a JOIN users u ON u.id = a.user_id WHERE a.asset_id = ?'
  ).all(assetId);
  return res.json({ data: rows });
});

// 24. POST /api/assets/:id/assignments [A] { user_id }
app.post('/api/assets/:id/assignments', requireRole('admin'), (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  const userId = parseInt(req.body.user_id, 10);
  if (isNaN(assetId) || isNaN(userId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Valid asset ID and user_id are required' } });
  }
  const asset = db.prepare('SELECT id FROM assets WHERE id = ? AND is_deleted = 0').get(assetId);
  if (!asset) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } });
  }
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
  if (!user) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'User not found' } });
  }
  db.prepare('INSERT OR IGNORE INTO asset_assignments (asset_id, user_id) VALUES (?, ?)').run(assetId, userId);
  appendAudit(req.user!.username, 'assignment.create', 'assets', assetId, { user_id: userId });
  return res.status(201).json({ data: { asset_id: assetId, user_id: userId } });
});

// 25. DELETE /api/assets/:id/assignments/:userId [A]
app.delete('/api/assets/:id/assignments/:userId', requireRole('admin'), (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  const userId = parseInt(req.params.userId, 10);
  if (isNaN(assetId) || isNaN(userId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid IDs' } });
  }
  db.prepare('DELETE FROM asset_assignments WHERE asset_id = ? AND user_id = ?').run(assetId, userId);
  appendAudit(req.user!.username, 'assignment.delete', 'assets', assetId, { user_id: userId });
  return res.json({ data: { success: true } });
});

// ---- Connected-site discovery ----

// 26. GET /api/assets/:id/discover [A] — render the asset's page and return the
// distinct connected sites that are not already monitored.
app.get('/api/assets/:id/discover', requireRole('admin'), async (req: Request, res: Response) => {
  const assetId = parseInt(req.params.id, 10);
  if (isNaN(assetId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }
  const asset = db.prepare('SELECT id, url FROM assets WHERE id = ? AND is_deleted = 0').get(assetId) as any;
  if (!asset) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Asset not found' } });
  }
  try {
    const found = await discoverConnectedHosts(asset.url, { depth: 1 });
    const existing = db.prepare('SELECT url FROM assets WHERE is_deleted = 0').all() as any[];
    const existingHosts = new Set(
      existing.map((e) => { try { return new URL(e.url).hostname.toLowerCase(); } catch { return ''; } })
    );
    const suggestions = found.filter((f) => !existingHosts.has(f.host));
    return res.json({ data: { suggestions } });
  } catch (err: any) {
    console.error('Discover error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 27. POST /api/assets/:id/children [A] { urls: string[] } — add selected
// connected sites as children of this asset (grouped under it in the UI).
app.post('/api/assets/:id/children', requireRole('admin'), async (req: Request, res: Response) => {
  const parentId = parseInt(req.params.id, 10);
  if (isNaN(parentId)) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Invalid asset ID' } });
  }
  const parent = db.prepare('SELECT id FROM assets WHERE id = ? AND is_deleted = 0').get(parentId) as any;
  if (!parent) {
    return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Parent asset not found' } });
  }
  const urls: unknown = req.body.urls;
  if (!Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: { code: 'BAD_REQUEST', message: 'Provide a non-empty urls array' } });
  }
  const added: any[] = [];
  const skipped: any[] = [];
  for (const u of urls.slice(0, MAX_ACTIVE_ASSETS)) {
    if (typeof u !== 'string') { skipped.push({ url: String(u), reason: 'Invalid URL' }); continue; }
    let host = u;
    try { host = new URL(u).hostname; } catch { /* keep raw */ }
    const outcome = await createMonitoredAsset({
      name: host,
      url: u,
      interval: 180,
      actor: req.user!.username,
      parentAssetId: parentId,
      liveCheck: false,
    });
    if (outcome.ok) added.push({ id: outcome.assetId, url: u });
    else skipped.push({ url: u, reason: outcome.message });
  }
  return res.status(201).json({ data: { added, skipped } });
});

// ---- Security intelligence ----

// 28. GET /api/intelligence [V] — deterministic posture scores, compliance and
// trend signals for the caller's accessible assets (ranked riskiest first).
app.get('/api/intelligence', (req: Request, res: Response) => {
  try {
    const access = accessibleAssetIds(req.user!);
    const data = computePortfolioIntelligence(access === 'all' ? 'all' : access);
    return res.json({ data });
  } catch (err: any) {
    console.error('Intelligence error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// 29. POST /api/intelligence/briefing [V] — on-demand AI intelligence briefing
// built from the same scoped portfolio. Honest fallback when AI is unavailable.
app.post('/api/intelligence/briefing', async (req: Request, res: Response) => {
  try {
    const access = accessibleAssetIds(req.user!);
    const data = computePortfolioIntelligence(access === 'all' ? 'all' : access);
    const result = await generateSecurityBriefing({ summary: data.summary, assets: data.assets });
    if (!result.ok) {
      return res.json({ data: { available: false, model: result.model, message: 'AI briefing is not available right now. The posture scores, compliance and trend signals below are computed without AI and remain accurate.' } });
    }
    return res.json({ data: { available: true, briefing: result.briefing, model: result.model } });
  } catch (err: any) {
    console.error('Briefing error:', err);
    return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
  }
});

// Serve frontend build static files in production
app.use(express.static(path.join(__dirname, '../../frontend/dist')));

// Fallback SPA routing
app.get('*', (req: Request, res: Response, next: NextFunction) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(__dirname, '../../frontend/dist/index.html'));
});

// Error handling middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled express error:', err);
  // Ensure no stack traces are leaked
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' } });
});

export function startServer() {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

export default app;
