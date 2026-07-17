# PS-005 — Website Defacement & Vulnerability Monitor: Architecture Spec

**Status of inputs — read before implementing.** One "already decided" input was not actually decided: the BYOK provider/model placeholder is still `[TEAM: FILL IN]`. This spec proceeds with a working assumption of **Gemini Flash via the Google GenAI SDK** (model string `gemini-3.5-flash` — verify the exact current string at https://ai.google.dev/gemini-api/docs before submission). It is the right shape for this job (fast, cheap, good at strict-JSON output), and it is isolated behind a single module (`src/llm.ts`) so swapping providers is a one-file change plus a README edit. No other input creates an architectural problem. One caveat, not a blocker: "no manual restarts for 24h" is satisfied here by a crash-safe, idempotent process plus the platform's automatic restart-on-failure policy — that combination is more reliable over 18 attacked hours than pretending the process will never die.

---

## 1. Architecture Overview

One deployable unit: a single Node.js/TypeScript process that runs three things side by side, sharing one SQLite database and one data directory on a persistent volume.

**Components:**

1. **HTTP API server (Express)** — serves the JSON API and the built frontend as static files. Handles auth (session cookies), RBAC middleware, asset CRUD, alert feed, snapshot browsing, audit log read/verify.
2. **Snapshot worker (in-process scheduler)** — a loop inside the same process. Every tick it selects active assets due for capture, then runs the pipeline per asset: **capture** (Playwright screenshot + raw HTML + response headers) → **diff** (perceptual hash vs. previous screenshot, text diff vs. previous HTML) → **vuln checks** (headers, sensitive paths, JS library versions) → **AI risk scoring** (only if something changed or a check newly failed) → **alert insert** → **audit log append**.
3. **Frontend (React SPA, Vite build)** — four screens: Login, Dashboard (alert feed + asset list), Asset Detail (snapshot history, latest diff, vuln status), Audit Log (with chain-verify button). No SSR, no realtime sockets; the feed polls `GET /api/alerts` every 15 s.
4. **SQLite database (better-sqlite3, WAL mode)** — all entities. Single-writer semantics are a feature here: audit-log hash chaining needs serialized writes anyway.
5. **File store** — screenshots (`/data/screens/{snapshotId}.png`) and raw HTML (`/data/html/{snapshotId}.html`) on the volume; DB stores paths + hashes only.
6. **LLM client module** — one function, one provider, strict JSON contract, timeout + one retry + honest fallback (see §Pipeline detail in section 3 notes).

**How they talk:** the worker and the API never talk over the network — they share the DB module in-process. The frontend talks only to the JSON API. The only outbound traffic is (a) Playwright/fetch to registered asset URLs and (b) HTTPS to the Gemini API.

**Why one process:** during Phase 3 you will be debugging at 3am with attackers filing issues on a 20-minute clock. One process = one log stream, one deploy, one restart, zero inter-service auth to get wrong. At 2 demo assets × one capture every ~3 minutes, there is no scale argument for splitting it.

**Scheduler mechanics (unattended-24h requirement):**
- `setInterval` master tick every 30 s; each active asset has `next_capture_at`; tick captures any asset that is due, then sets `next_capture_at = now + interval + jitter(±20s)`. Assets are staggered on creation so they never capture simultaneously.
- Every pipeline stage is wrapped in try/catch; a failure on one asset logs and continues — it can never kill the loop.
- Playwright browser is launched once; each capture uses a fresh context that is always closed in `finally`. If a capture throws a browser-level error, the browser is killed and relaunched on the next tick (bounded memory over 24 h).
- Process-level `uncaughtException`/`unhandledRejection` handlers log and `process.exit(1)`; the platform restart policy brings it back in seconds. Startup is idempotent (migrations use `CREATE TABLE IF NOT EXISTS`; the worker resumes from `next_capture_at` values in the DB).

## 2. Tech Stack (single pick, with reasoning)

**Pick: TypeScript end-to-end. Node 20 + Express 4 + better-sqlite3 (WAL) + Playwright (Chromium) + sharp (image decode for dHash) + `diff` (npm) for text diffs + `@google/genai` for the Gemini BYOK call + React 18 + Vite + plain CSS. Deployed as one Docker container on Railway with a mounted volume at `/data` and restart-policy `on-failure`.**

Reasoning:

- **Hosting must support a persistent process — serverless is disqualified.** Vercel/Netlify/Cloudflare Workers cannot run an 18-hour background loop with a resident headless browser; cron-triggered serverless functions would cold-start Chromium every capture, blow duration limits on slow targets, and have no persistent disk for screenshots or SQLite. Railway (Render works identically; Railway picked for faster volume + Dockerfile setup) runs the container as a normal long-lived process, gives a persistent volume, and auto-restarts on crash — exactly the shape this app is.
- **One language.** Four students + parallel coding agents sharing one `types.ts` beats a Python worker + JS frontend split. Every team member can read every line at 3am.
- **SQLite over Postgres.** No connection strings or DB credentials to leak, no network DB to attack, no pool exhaustion under attacker load, trivially snapshot-able for debugging (`cp /data/app.db`). `better-sqlite3` is synchronous, which makes the audit-log transaction (§5) trivially correct. At this write volume (a few rows per minute) it is nowhere near its limits.
- **Playwright over Puppeteer/raw fetch.** Screenshot capture is a must-ship feature; Playwright's official Docker base image (`mcr.microsoft.com/playwright:v1.x-jammy`) eliminates the classic "Chromium missing libnss3" deploy failure — the single most common hackathon deployment death.
- **Perceptual hash implemented in-repo (dHash, 64-bit) via sharp** rather than a phash dependency: ~25 lines, deterministic, debuggable (resize to 9×8 grayscale, compare adjacent pixels, 64-bit fingerprint, Hamming distance between snapshots). No native-build roulette from a niche npm package.
- **No queue, no Redis, no ORM, no WebSockets.** Each would be another thing to break during the live game and none is needed at this scale. Polling every 15 s is indistinguishable from realtime in the demo.

## 3. Data Model

SQLite schema — this is the frozen contract for all workstreams:

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,              -- bcrypt, cost 12
  role          TEXT NOT NULL CHECK (role IN ('admin','viewer')),
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- Seeded at startup from env (ADMIN_PASSWORD, VIEWER_PASSWORD). No signup endpoint exists.

CREATE TABLE IF NOT EXISTS assets (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT NOT NULL,
  url             TEXT NOT NULL,            -- validated: http/https, public IP only (see §6)
  is_active       INTEGER NOT NULL DEFAULT 1,   -- 0/1
  is_deleted      INTEGER NOT NULL DEFAULT 0,   -- soft delete: history + audit refs survive
  interval_seconds INTEGER NOT NULL DEFAULT 180 CHECK (interval_seconds BETWEEN 120 AND 300),
  next_capture_at TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS snapshots (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id         INTEGER NOT NULL REFERENCES assets(id),
  captured_at      TEXT NOT NULL,
  http_status      INTEGER,                 -- NULL if fetch itself failed
  fetch_error      TEXT,                    -- error string when capture failed
  response_headers TEXT NOT NULL DEFAULT '{}',  -- JSON object, lowercased header names
  screenshot_path  TEXT,                    -- /data/screens/{id}.png
  html_path        TEXT,                    -- /data/html/{id}.html
  phash            TEXT,                    -- 16 hex chars (64-bit dHash), NULL if screenshot failed
  html_sha256      TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_asset ON snapshots(asset_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS diff_results (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id        INTEGER NOT NULL REFERENCES snapshots(id),
  prev_snapshot_id   INTEGER REFERENCES snapshots(id),   -- NULL for first snapshot (baseline)
  visual_distance    INTEGER,               -- Hamming distance 0–64, NULL if either phash missing
  visual_changed     INTEGER NOT NULL DEFAULT 0,  -- distance > PHASH_THRESHOLD (default 10)
  text_changed       INTEGER NOT NULL DEFAULT 0,  -- html_sha256 differs
  text_diff_summary  TEXT,                  -- unified-diff hunks, truncated to 8 KB
  created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS vuln_check_results (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
  check_type   TEXT NOT NULL CHECK (check_type IN
                 ('header_csp','header_hsts','header_xfo','header_xcto',
                  'exposed_path','outdated_js')),
  passed       INTEGER NOT NULL,            -- 0 = finding present, 1 = clean
  details      TEXT NOT NULL DEFAULT '{}'   -- JSON: e.g. {"path":"/.env","status":200}
);
CREATE INDEX IF NOT EXISTS idx_vuln_snapshot ON vuln_check_results(snapshot_id);

-- Risk score is folded into the alert (1:1 in every must-ship flow; a separate table adds a join, not a feature).
CREATE TABLE IF NOT EXISTS alert_events (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id         INTEGER NOT NULL REFERENCES assets(id),
  snapshot_id      INTEGER NOT NULL REFERENCES snapshots(id),
  kind             TEXT NOT NULL CHECK (kind IN ('change','vuln','availability')),
  title            TEXT NOT NULL,           -- short, generated by our code, not the LLM
  severity         TEXT NOT NULL CHECK (severity IN ('high','medium','low','unscored')),
  ai_explanation   TEXT,                    -- plain-English risk explanation from LLM
  ai_remediation   TEXT,                    -- single suggestion from LLM
  ai_model         TEXT,                    -- e.g. 'gemini-3.5-flash' 
  ai_error         TEXT,                    -- set when severity='unscored' (LLM failed — never faked)
  created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_feed ON alert_events(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  seq          INTEGER PRIMARY KEY,         -- app-assigned, strictly prev.seq + 1 (see §5)
  created_at   TEXT NOT NULL,               -- ISO-8601 UTC, assigned in-app (part of hashed content)
  actor        TEXT NOT NULL,               -- username or 'system'
  action       TEXT NOT NULL,               -- 'user.login','user.login_failed','asset.create',
                                            -- 'asset.update','asset.delete','alert.create'
  entity_type  TEXT,
  entity_id    INTEGER,
  details_json TEXT NOT NULL DEFAULT '{}',  -- stored verbatim; hashed via its digest (see §5)
  prev_hash    TEXT NOT NULL,               -- entry_hash of seq-1; 64 zeros for seq=1
  entry_hash   TEXT NOT NULL UNIQUE
);

-- Enforce append-only at the DB layer, not just by convention:
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

**Relationships:** Asset 1—N Snapshot; Snapshot 1—1 DiffResult; Snapshot 1—N VulnCheckResult; Snapshot 1—N AlertEvent (usually 0 or 1); AuditLog is a flat chain referencing entities loosely by (entity_type, entity_id) so soft-deleted assets never break it.

**Pipeline decision rules (worker, per capture):**
1. Alert of kind `change` when `visual_changed OR text_changed` (skipped for the asset's first snapshot — that's the baseline).
2. Alert of kind `vuln` only on a **pass→fail transition** per check_type vs. the previous snapshot (prevents the feed being spammed every 3 minutes by Juice Shop's permanently missing CSP; the current failing state stays visible on the Asset Detail page).
3. Alert of kind `availability` on transition to `http_status >= 500` or fetch failure.
4. LLM is called **only when an alert is being created** (cost + prompt-injection surface control). Input: the diff summary, the failed checks' details, HTTP status, asset name/URL. Contract: respond with JSON only — `{"severity":"high|medium|low","explanation":"...","remediation":"..."}`. 20 s timeout, one retry; on failure the alert is still inserted with `severity='unscored'` and `ai_error` set. Nothing is ever mocked as AI output — this is the honest-fallback path for the BYOK rule.

## 4. API Surface

All routes JSON under `/api`, session-cookie auth, responses `{ "data": ... }` or `{ "error": { "code", "message" } }`. `[A]` = admin-only, `[V]` = any authenticated user (viewer or admin). There are deliberately **no** unauthenticated routes except `POST /api/auth/login` and `GET /api/health`.

```text
Auth
  POST   /api/auth/login          [public]  {username, password} → sets httpOnly session cookie
                                            rate-limited: 5/min/IP; audit-logged incl. failures
  POST   /api/auth/logout         [V]       clears session
  GET    /api/auth/me             [V]       → {username, role}

Assets
  GET    /api/assets              [V]       list (is_deleted=0) + latest snapshot summary + current vuln state
  POST   /api/assets              [A]       {name, url, interval_seconds?} — URL validated per §6.1
  PATCH  /api/assets/:id          [A]       {name?, is_active?} — URL is immutable after creation (SSRF surface)
  DELETE /api/assets/:id          [A]       soft delete (is_deleted=1, is_active=0)

Snapshots
  GET    /api/assets/:id/snapshots            [V]  paginated metadata, newest first (?limit=50&before=<id>)
  GET    /api/snapshots/:id                    [V]  full record: headers, phash, diff result, vuln results
  GET    /api/snapshots/:id/screenshot         [V]  image/png (path looked up from DB by id — never from input)
  GET    /api/snapshots/:id/html               [V]  Content-Type: text/plain; X-Content-Type-Options: nosniff
                                                    (raw captured HTML must never be served as text/html)

Alerts
  GET    /api/alerts              [V]       newest first; ?severity=high|medium|low|unscored
                                            &kind=change|vuln|availability &asset_id= &limit=&before=

Audit log
  GET    /api/audit               [V]       paginated, newest first (read-only for everyone by design)
  GET    /api/audit/verify        [V]       walks the full chain, recomputes every hash →
                                            {valid: true} | {valid: false, first_bad_seq}

Ops
  GET    /api/health              [public]  {"ok": true} only — no version, no uptime, no scheduler
                                            internals (don't hand attackers a recon endpoint)
```

That is the complete surface — 13 routes. Every must-ship feature maps onto it; anything an agent wants to add beyond this list is scope creep and should be rejected.

## 5. Audit Log Hash Chain — Exact Mechanism

**Hash function:** SHA-256, lowercase hex, via Node's built-in `crypto`. **Genesis `prev_hash`:** 64 `'0'` characters.

**Canonical serialization** (the exact bytes that get hashed — fixed field order, pipe-delimited, with the free-form JSON reduced to its digest so a `|` inside `details_json` can never create an ambiguous encoding):

```
canonical = "v1" + "|" + seq + "|" + created_at + "|" + actor + "|" + action
          + "|" + (entity_type ?? "") + "|" + (entity_id?.toString() ?? "")
          + "|" + sha256hex(details_json)      // digest of the verbatim stored JSON string
          + "|" + prev_hash

entry_hash = sha256hex(canonical)
```

**Write procedure** — one function, `appendAudit(actor, action, entityType, entityId, details)`, the *only* code path that touches the table:

```ts
function appendAudit(actor, action, entityType, entityId, details) {
  const tx = db.transaction(() => {                         // better-sqlite3: BEGIN..COMMIT, and
    const last = db.prepare(                                // WAL single-writer serializes appends
      'SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    const seq       = last ? last.seq + 1 : 1;
    const prevHash  = last ? last.entry_hash : '0'.repeat(64);
    const createdAt = new Date().toISOString();             // assigned in-app: it is hashed content,
    const detailsJson = JSON.stringify(details ?? {});      // so it cannot be a DB-side default
    const canonical = ['v1', seq, createdAt, actor, action,
                       entityType ?? '', entityId?.toString() ?? '',
                       sha256hex(detailsJson), prevHash].join('|');
    const entryHash = sha256hex(canonical);
    db.prepare(`INSERT INTO audit_log
      (seq, created_at, actor, action, entity_type, entity_id, details_json, prev_hash, entry_hash)
      VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(seq, createdAt, actor, action, entityType, entityId, detailsJson, prevHash, entryHash);
  });
  tx();
}
```

Correctness properties a coding agent must preserve:
1. **Read-last and insert happen in one transaction.** better-sqlite3 is synchronous and SQLite WAL allows one writer at a time, so two concurrent appends cannot both read the same `last` row. The `UNIQUE` constraint on `entry_hash` plus `seq` as primary key are belt-and-braces: a race would fail the insert rather than fork the chain.
2. **`seq` is app-assigned (`last.seq + 1`), not AUTOINCREMENT**, because `seq` is inside the hashed content and must be known before hashing.
3. **`created_at` is assigned in application code** for the same reason.
4. **`details_json` is stored verbatim and hashed via its digest.** Verification re-hashes the stored string exactly — no re-serialization, so JSON key-order ambiguity cannot cause false tamper alarms.
5. **Verification** (`GET /api/audit/verify`): walk rows ordered by `seq`; check `seq` values are 1,2,3,… with no gaps; check row 1 has the genesis `prev_hash`; for each row recompute `canonical` from stored fields and compare to `entry_hash`; check each row's `prev_hash` equals the previous row's `entry_hash`. First mismatch → `{valid:false, first_bad_seq}`. Any retroactive edit or deletion breaks at least one of these checks; the UPDATE/DELETE triggers in §3 additionally block casual tampering at the SQL layer.

**Demo note:** chain verification is a 10-second live proof — `sqlite3 /data/app.db "UPDATE ..."` fails on the trigger; disabling the trigger and editing a row makes `/api/audit/verify` pinpoint the exact seq. Rehearse this for judging.

## 6. Security Posture for Our Own App (Phase 3 targets)

The five things attackers will go after in *this specific design*, most likely first:

**6.1 SSRF via the asset registry (the app's defining risk — we are literally a URL-fetching service).** An attacker who obtains admin capability (or finds any RBAC gap) registers `http://localhost:PORT/api/...`, `http://169.254.169.254/`, or a hostname that DNS-rebinds to a private IP; our worker then fetches internal surfaces for them with screenshots attached.
*Defense:* validate on `POST /api/assets` — scheme must be http/https; resolve the hostname and reject loopback, RFC-1918, link-local, and other reserved ranges. Crucially, **re-resolve and re-check at every capture time** (kills DNS rebinding), and make `url` immutable after creation (no PATCH path to swap a clean URL for a dirty one). Worker follows max 3 redirects, re-validating each hop's target. Playwright contexts get a route filter that aborts any request to a private IP.

**6.2 Stored XSS through content we ourselves collect.** Attackers can't write to our DB directly, but they *can* deface the public demo asset — so captured HTML, text diffs, page titles, and even response header values are attacker-controlled data that our dashboard displays. A `<script>` payload in the diff summary that executes in an admin's browser is game over.
*Defense:* React only, `dangerouslySetInnerHTML` banned repo-wide (add an ESLint rule); diffs rendered as plain text in `<pre>`; raw HTML served only as `text/plain` + `nosniff` (per §4); screenshots rendered as `<img>` from the PNG endpoint (pixels, not markup); our own app sends a strict CSP (`default-src 'self'`), which also stops us failing our own header check in the demo. **Same principle applies to the LLM:** defaced page content flows into the risk-scoring prompt, so treat it as prompt injection — the response is parsed against the strict JSON schema, severity is validated against the enum, explanation/remediation are rendered as plain text, and nothing the model says is ever executed or fetched.

**6.3 Auth and RBAC bypass.** Two juicy targets: the login endpoint (brute force — there are exactly two accounts) and any admin route missing its role check.
*Defense:* bcrypt cost 12; login rate-limit 5/min/IP with a uniform "invalid credentials" error (no username enumeration); failures audit-logged (attacker brute-forcing becomes demo material); session = signed httpOnly, `SameSite=Lax`, `Secure` cookie with random 128-bit id, server-side store, 12 h expiry. RBAC is **deny-by-default**: a global middleware rejects any `/api` request without a session, and mutating routes declare `requireRole('admin')` explicitly — an agent forgetting a check fails closed (401), not open. `SameSite=Lax` + no state-changing GETs is the CSRF story; keep it that way.

**6.4 Path traversal / IDOR on file serving.** `GET /api/snapshots/:id/screenshot` is the classic spot for `../../` games.
*Defense:* the route accepts only an integer id, looks the path up from the snapshots row, and additionally asserts the resolved absolute path starts with the data dir. No filename ever originates from request input. IDOR is moot within scope (single-tenant, both roles may read everything) — state that in the README so issue-filers can't claim it as a vuln.

**6.5 Resource exhaustion.** Cheap attacks that hurt the reliability score: hammering the API, registering an asset pointing at a 500 MB page or a tarpit server, or bloating the disk until SQLite writes fail.
*Defense:* global rate limit (e.g. 120 req/min/IP) plus the stricter login limit; JSON body limit 32 KB; capture hard limits — 30 s page timeout, stored HTML truncated at 2 MB, viewport-only screenshot; retention job deletes snapshot *files* (never DB rows, never audit rows) older than 24 h; scheduler processes assets sequentially so a slow target delays, but cannot pile up, captures.

Cross-cutting: secrets only via env vars (`GEMINI_API_KEY`, `SESSION_SECRET`, `ADMIN_PASSWORD`, `VIEWER_PASSWORD`); `.env` gitignored **before the first commit** — the repo goes public with its full history at Phase 3, so a key committed in hour 1 and deleted in hour 5 is still leaked. Rotate the API key at the Phase 2/3 boundary regardless. No stack traces in HTTP responses (generic 500 + server-side log). `helmet` for our own security headers.

## 7. Build Sequencing for Parallel Agents

**Phase 0 — contract freeze (first 30 min, one person + one agent, blocks everything):**
Repo skeleton; `src/types.ts` (interfaces mirroring §3) and `src/db.ts` (schema DDL from §3, migrations, `appendAudit` from §5 verbatim); `Dockerfile` (Playwright base image) that boots a hello-world Express server; push to Railway with volume mounted **now** — deployment proven in minute 40, not minute 340. After this freeze, §3 and §4 are immutable; any change requires all agents to acknowledge.

**Phase 1 — three independent workstreams (hours 0.5–4), no shared files beyond the frozen `types.ts`/`db.ts`:**

- **Agent A — API server** (`src/server/`): Express app, session auth, RBAC middleware, all 13 routes from §4, rate limiting, helmet/CSP, user seeding, static serving of `frontend/dist`. Testable with curl alone.
- **Agent B — worker pipeline** (`src/worker/`): scheduler loop, Playwright capture, dHash + Hamming, text diff, the six vuln checks, LLM client (`src/llm.ts`), alert-creation rules from §3. Testable headlessly against the two demo assets with zero frontend.
- **Agent C — frontend** (`frontend/`): the four screens against the §4 contract, developed against fixture JSON until A lands; Vite dev proxy to the API afterward.

A↔B share only the DB file (via `db.ts`) — no runtime interface to negotiate. C↔A share only the §4 contract.

**Phase 2 — integration (hours 4–5), in this order:**
1. **A+B**: run server with worker enabled; confirm snapshots/alerts/audit rows appear for both demo assets.
2. **C onto A**: build frontend into `frontend/dist`, serve statically; click through all four screens as both roles.
3. **Deploy to Railway**; deface the throwaway demo site; watch capture → diff → LLM score → alert → audit append end-to-end in production.

**Phase 3 — hardening + submission (hours 5–6):** fourth teammate (or Agent D) runs an adversarial pass against §6 as a checklist — viewer attempting every admin route, SSRF payloads on asset creation, script-payload defacement of the demo site to confirm XSS-safe rendering, `/api/audit/verify` tamper demo; then README (§8), key rotation plan, final deploy, and a DB/volume backup snapshot as the Phase 3 rollback point.

Rationale: the only true serialization point is the 30-minute contract freeze; everything after is embarrassingly parallel, and integration risk is front-loaded by deploying the walking skeleton in minute 40.

## 8. README Outline

1. **Overview** — one-paragraph pitch + screenshot of the alert feed; the two demo assets and what each demonstrates (defacement vs. real vuln findings).
2. **Architecture Summary** — the §1 component list condensed to ~10 lines + the single-process rationale in two sentences (this feeds the design-quality score).
3. **AI / BYOK Disclosure** — provider (Anthropic), model string (`gemini-3.5-flash` — confirm exact string), exactly where the LLM is invoked (risk scoring of already-collected diff + vuln data only), the strict-JSON contract, and the honest failure mode (`severity: unscored`, never mocked). Written to make the build-violation check trivial to pass.
4. **Running Locally** — prerequisites (Node 20, `npx playwright install chromium`), `.env.example` with every variable and a one-line description, `npm run dev`, seeded credentials for both roles.
5. **Deployment** — Railway: Dockerfile, volume at `/data`, env vars, restart policy; how the scheduler survives restarts (idempotent startup, `next_capture_at` persisted).
6. **Security Design & Known Limitations** — condensed §6 (shows judges the threat model) plus explicit assumptions: single-tenant by design, both roles read all data (IDOR out of scope), 24 h screenshot-file retention, vuln checks limited to the six listed types with a small hardcoded JS-version list, no notification integrations.
7. **Audit Log Verification** — two-line explanation of the hash chain + the exact curl for `/api/audit/verify` and the tamper demo script (judge candy).
8. **Team & Attribution** — members, AI coding tools used (Antigravity/Gemini 3 Pro/Claude Sonnet), event rules acknowledgment.
