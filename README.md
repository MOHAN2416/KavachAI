# KavachAI — Website Defacement and Vulnerability Monitor

KavachAI is a continuous monitoring platform that watches web assets for
unauthorized changes and security weaknesses, and explains the risk of each
finding in plain language. It is built for teams that need early warning when a
public website is defaced, goes down, or develops a security gap, without
standing up heavy infrastructure.

## Overview

Modern websites change constantly, and not every change is intentional. A
defacement, an injected script, a newly exposed configuration file, or a
suddenly missing security header can all indicate a compromise. KavachAI
registers the sites you care about, captures each one on a regular schedule,
and compares every capture against the previous one. When it detects a visual
change, a content change, a new vulnerability, or an availability failure, it
raises an alert, assigns a severity, and provides a short, human-readable
explanation and remediation suggestion.

Every meaningful action in the system is recorded in a tamper-evident audit log
that can be verified on demand, so operators can prove the integrity of the
monitoring record itself.

## Key features

- Scheduled monitoring of any number of registered web assets, each on its own
  capture interval.
- Visual change detection using perceptual image hashing of full-page
  screenshots.
- Content change detection with a readable summary of what changed in the page
  source.
- Automated security checks covering common response-header protections,
  publicly exposed sensitive files, and outdated client-side libraries with
  known vulnerabilities.
- Availability monitoring that flags server errors and unreachable sites.
- AI-assisted risk scoring that turns raw findings into a severity rating, a
  plain-language explanation, and a remediation suggestion.
- A tamper-evident, cryptographically chained audit log with one-click
  verification.
- Role-based access with separate administrator and viewer accounts.

## How it works

KavachAI runs as a single service with three cooperating parts that share one
database and one storage directory.

A background monitor wakes on a fixed schedule and processes any asset that is
due for capture. For each asset it loads the page in a managed headless browser,
records a screenshot, the rendered page source, and the response metadata. It
then compares the new capture against the previous one to determine whether the
page has changed visually or textually, runs its security checks, and evaluates
whether any condition warrants an alert. Alerts are raised only on meaningful
transitions rather than on every capture, so the feed stays signal-rich instead
of repetitive.

When an alert is created, the collected findings are passed to the AI risk
engine, which returns a severity, an explanation, and a remediation suggestion.
The AI engine is used strictly to interpret data the system has already
collected; it never fetches anything on its own and never invents findings. If
the engine is unavailable, the alert is still recorded and simply marked as not
scored, so no event is ever lost or fabricated.

A web application provides the user interface and the API. Operators sign in,
review the live alert feed, inspect individual assets and their capture history,
and verify the audit log. The interface polls for new alerts automatically.

## Technology

- Backend: Node.js and TypeScript with an Express web server.
- Data: an embedded SQL database stored on a persistent volume, with page
  screenshots and captured source kept on disk.
- Capture: a managed headless browser for rendering and screenshotting pages.
- AI: a bring-your-own-key large language model, isolated behind a single
  module and configured entirely through environment variables.
- Frontend: a React single-page application.
- Packaging: a single container image suitable for any host that can run a
  long-lived process with a persistent volume.

## Prerequisites

- Node.js 20 LTS. Newer major versions may require native build tooling; version
  20 installs prebuilt binaries cleanly on all platforms.
- A browser runtime for capture. When running from source, install it once with
  `npx playwright install chromium`. The container image already includes it.
- An API key for the AI risk engine (optional for basic operation; without it,
  alerts are recorded but left unscored).

## Installation

Clone the repository and install dependencies for both the backend and the
frontend.

```
git clone <repository-url>
cd <repository-directory>
npm install
npm --prefix frontend install
npx playwright install chromium
```

Do not set `NODE_ENV=production` during installation, or development
dependencies required for the build will be skipped.

## Configuration

Copy `.env.example` to `.env` and fill in the values. Never commit `.env`; it is
excluded from version control by design.

| Variable          | Required | Description                                                                 |
|-------------------|----------|-----------------------------------------------------------------------------|
| `AI_API_KEY`      | No       | API key for the AI risk engine. If unset, alerts are recorded but unscored. |
| `SESSION_SECRET`  | Yes      | A long random string used to sign session cookies.                          |
| `ADMIN_PASSWORD`  | Yes      | Password for the seeded administrator account.                              |
| `VIEWER_PASSWORD` | Yes      | Password for the seeded viewer account.                                     |
| `PORT`            | No       | HTTP port for the server. Defaults to 3000.                                 |
| `DATA_DIR`        | No       | Directory for the database and captured files. Defaults to `./data`.        |
| `CORS_ORIGINS`    | No       | Comma-separated allowed origins for development. Not used in production.     |
| `NODE_ENV`        | No       | Set to `production` at runtime for secure cookies and same-origin behavior. |

The administrator and viewer accounts are created automatically on first start
from the passwords above. There is no self-service sign-up.

## Running locally

For development, run the backend and the frontend separately. The frontend dev
server proxies API calls to the backend.

```
npm run dev
npm --prefix frontend run dev
```

Then open the frontend dev URL shown in the terminal and sign in.

For a production-style run, build everything and start the single service, which
serves both the API and the compiled frontend.

```
npm run build
npm start
```

Then open `http://localhost:3000`.

## Running with the container image

The container image bundles the browser runtime, which avoids platform-specific
setup and is the most reliable way to run locally or in production.

```
docker build -t kavachai .
docker run -p 3000:3000 --env-file .env -v "$(pwd)/data:/data" kavachai
```

The volume mapping keeps the database and captured files across restarts.

## Deployment

KavachAI is designed to run as a single long-lived service with a persistent
volume, on any platform that supports containers or a persistent Node process.

1. Provision a service backed by the container image, or by a Node build from
   source.
2. Attach a persistent volume and point `DATA_DIR` at it (for example, `/data`).
3. Set the environment variables listed in the configuration section. Provide
   secrets only through the platform's environment settings, never in the
   repository.
4. Enable automatic restart on failure. Startup is idempotent, so the service
   resumes its schedule from persisted state after any restart.

## Usage

Sign in with one of the seeded accounts. After signing in you land on the
dashboard.

- Dashboard: the left side shows the live alert feed, filterable by severity and
  by alert type. The right side lists the monitored assets with their current
  status. Administrators can add a new asset from here.
- Adding an asset: administrators provide a display name, a public target URL,
  and a capture interval. The URL must resolve to a publicly reachable address.
  The asset begins capturing shortly after it is created.
- Asset detail: select any asset to see its latest screenshot, the current
  results of each security check, the visual and content difference against the
  previous capture, and a full capture history. Administrators can pause, resume,
  or remove an asset from this screen.
- Alerts: each alert shows the affected asset, its type and severity, and, when
  available, an explanation and remediation suggestion. An alert marked as not
  scored indicates the AI engine was unavailable at the time; the underlying
  finding is still valid and can be reviewed manually.
- Audit log: view the complete record of system actions. Use the verification
  control to recompute the entire integrity chain; the interface confirms
  whether the record is intact or identifies exactly where it was altered.

## User roles

- Administrator: full access, including creating, updating, pausing, and
  removing monitored assets, in addition to all read access.
- Viewer: read-only access to the dashboard, asset details, alerts, and the
  audit log.

Both roles can read all monitored data; the platform is single-tenant by design.

## Security and integrity

KavachAI is built with a defense-in-depth posture. Access requires
authentication by default, privileged actions are restricted by role, requests
are rate limited, and the application serves a strict content security policy.
Because the platform fetches user-supplied URLs, it validates every target and
rejects requests aimed at internal or reserved network ranges, and it re-checks
targets at capture time. Captured content is always treated as untrusted and is
rendered as inert text or images, never executed. The audit log is append-only
and cryptographically chained so that any retroactive change is detectable.

## Known limitations

- The platform is single-tenant; all authenticated users can read all monitored
  data.
- Captured screenshots and page source are retained for a limited window to
  bound storage use; alert and audit records are retained.
- Security checks cover a defined set of common issues and a curated list of
  client-side libraries rather than an exhaustive scan.
- The AI risk engine requires a valid API key; without one, alerts are recorded
  but left unscored.

## Attribution

Add team members, tooling used, and any event or license acknowledgments here.
