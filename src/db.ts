import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();

// Ensure data directory exists
const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const screensDir = path.join(dataDir, 'screens');
const htmlDir = path.join(dataDir, 'html');
if (!fs.existsSync(screensDir)) {
  fs.mkdirSync(screensDir, { recursive: true });
}
if (!fs.existsSync(htmlDir)) {
  fs.mkdirSync(htmlDir, { recursive: true });
}

export const DATA_DIR_PATH = dataDir;

// Initialize SQLite DB
const dbPath = path.join(dataDir, 'app.db');
const db = new Database(dbPath);

// Enable WAL journal mode and foreign keys
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','viewer')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    interval_seconds INTEGER NOT NULL DEFAULT 180 CHECK (interval_seconds BETWEEN 120 AND 300),
    next_capture_at TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  CREATE TABLE IF NOT EXISTS snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         INTEGER NOT NULL REFERENCES assets(id),
    captured_at      TEXT NOT NULL,
    http_status      INTEGER,
    fetch_error      TEXT,
    response_headers TEXT NOT NULL DEFAULT '{}',
    screenshot_path  TEXT,
    html_path        TEXT,
    phash            TEXT,
    html_sha256      TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_snapshots_asset ON snapshots(asset_id, captured_at DESC);

  CREATE TABLE IF NOT EXISTS diff_results (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id        INTEGER NOT NULL REFERENCES snapshots(id),
    prev_snapshot_id   INTEGER REFERENCES snapshots(id),
    visual_distance    INTEGER,
    visual_changed     INTEGER NOT NULL DEFAULT 0,
    text_changed       INTEGER NOT NULL DEFAULT 0,
    text_diff_summary  TEXT,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );

  CREATE TABLE IF NOT EXISTS vuln_check_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
    check_type   TEXT NOT NULL CHECK (check_type IN
                   ('header_csp','header_hsts','header_xfo','header_xcto',
                    'exposed_path','outdated_js')),
    passed       INTEGER NOT NULL,
    details      TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS idx_vuln_snapshot ON vuln_check_results(snapshot_id);

  CREATE TABLE IF NOT EXISTS alert_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         INTEGER NOT NULL REFERENCES assets(id),
    snapshot_id      INTEGER NOT NULL REFERENCES snapshots(id),
    kind             TEXT NOT NULL CHECK (kind IN ('change','vuln','availability')),
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('high','medium','low','unscored')),
    ai_explanation   TEXT,
    ai_remediation   TEXT,
    ai_model         TEXT,
    ai_error         TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_feed ON alert_events(created_at DESC);

  CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY,
    created_at   TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    entity_type  TEXT,
    entity_id    INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL UNIQUE
  );

  CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

  CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

  -- Which viewers may see which assets (per-website access control).
  CREATE TABLE IF NOT EXISTS asset_assignments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   INTEGER NOT NULL REFERENCES assets(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(asset_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_assignments_user ON asset_assignments(user_id);
  CREATE INDEX IF NOT EXISTS idx_assignments_asset ON asset_assignments(asset_id);

  -- Viewer-submitted requests to monitor a site; the admin approves or rejects.
  CREATE TABLE IF NOT EXISTS monitoring_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    name             TEXT NOT NULL,
    url              TEXT NOT NULL,
    note             TEXT,
    interval_seconds INTEGER NOT NULL DEFAULT 180,
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    asset_id         INTEGER REFERENCES assets(id),
    resolved_by      TEXT,
    resolved_at      TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_requests_status ON monitoring_requests(status, created_at DESC);
`);

// Lightweight forward migration: add users.status to a pre-existing database.
// Self-registered viewers start 'pending' and cannot log in until an admin
// sets them 'active'. Existing rows default to 'active'.
function ensureColumn(table: string, column: string, ddl: string) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as any[];
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  }
}
ensureColumn('users', 'status', "status TEXT NOT NULL DEFAULT 'active'");
// Child sites discovered from a parent are grouped under it via parent_asset_id.
ensureColumn('assets', 'parent_asset_id', 'parent_asset_id INTEGER');

// One-time reconciliation (idempotent, runs each boot): soft-delete child assets
// whose parent is deleted or missing. Such orphans were previously invisible in
// the UI yet still counted against the asset cap. Children of a live parent are
// untouched.
db.exec(`
  UPDATE assets
  SET is_deleted = 1, is_active = 0
  WHERE is_deleted = 0
    AND parent_asset_id IS NOT NULL
    AND parent_asset_id NOT IN (SELECT id FROM assets WHERE is_deleted = 0)
`);

// SHA-256 helper
export function sha256hex(str: string): string {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// Append Audit Log using serialized transaction
export function appendAudit(
  actor: string,
  action: string,
  entityType: string | null,
  entityId: number | null,
  details: any
) {
  const tx = db.transaction(() => {
    const last = db.prepare(
      'SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1'
    ).get() as { seq: number; entry_hash: string } | undefined;

    const seq = last ? last.seq + 1 : 1;
    const prevHash = last ? last.entry_hash : '0'.repeat(64);
    const createdAt = new Date().toISOString();
    const detailsJson = JSON.stringify(details ?? {});

    const canonical = [
      'v1',
      seq,
      createdAt,
      actor,
      action,
      entityType ?? '',
      entityId?.toString() ?? '',
      sha256hex(detailsJson),
      prevHash
    ].join('|');

    const entryHash = sha256hex(canonical);

    db.prepare(`
      INSERT INTO audit_log
      (seq, created_at, actor, action, entity_type, entity_id, details_json, prev_hash, entry_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(seq, createdAt, actor, action, entityType, entityId, detailsJson, prevHash, entryHash);
  });
  
  tx();
}

// Seed / reconcile the two accounts. Keyed by ROLE (not username) so that when
// the configured username or password changes, the existing account is updated
// in place — this is what removes a previously-seeded weak default like
// admin/admin123 instead of leaving it in the database as a second admin.
export function seedUsers() {
  const accounts: Array<{ role: 'admin' | 'viewer'; username: string; password: string }> = [
    {
      role: 'admin',
      username: process.env.ADMIN_USERNAME || 'admin123@gmail.com',
      password: process.env.ADMIN_PASSWORD || 'admin123',
    },
    {
      role: 'viewer',
      username: process.env.VIEWER_USERNAME || 'viewer123@gmail.com',
      password: process.env.VIEWER_PASSWORD || 'viewer123',
    },
  ];

  for (const acct of accounts) {
    const hash = bcrypt.hashSync(acct.password, 12);
    const existing = db.prepare('SELECT id FROM users WHERE role = ?').get(acct.role) as
      | { id: number }
      | undefined;

    if (existing) {
      db.prepare("UPDATE users SET username = ?, password_hash = ?, status = 'active' WHERE id = ?")
        .run(acct.username, hash, existing.id);
    } else {
      const result = db.prepare("INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, 'active')")
        .run(acct.username, hash, acct.role);
      appendAudit('system', 'user.create', 'users', Number(result.lastInsertRowid), {
        username: acct.username,
        role: acct.role,
      });
    }
  }
}

export default db;
