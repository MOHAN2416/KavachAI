import dotenv from 'dotenv';
import { seedUsers } from './db';
import { startServer } from './server';
import { startWorker } from './worker';

dotenv.config();

// Crash-safety (spec §1): log and exit so the platform restart policy brings the
// process back. Startup is idempotent (CREATE TABLE IF NOT EXISTS, next_capture_at
// resumed from the DB), so exiting on an unexpected fault is safe and bounded.
process.on('uncaughtException', (err) => {
  console.error('FATAL uncaughtException:', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('FATAL unhandledRejection:', reason);
  process.exit(1);
});

// 0. Validate critical configuration before doing anything else. In production
// the app must never fall back to built-in default secrets/passwords. Missing
// or weak secrets are a hard startup failure there; in development they are only
// a warning so local runs stay frictionless.
function validateStartupConfig() {
  const isProd = process.env.NODE_ENV === 'production';
  const problems: string[] = [];

  const secret = process.env.SESSION_SECRET || '';
  if (!secret || secret.length < 16) {
    problems.push('SESSION_SECRET must be set to a long random string (>= 16 chars).');
  }

  const weak = new Set(['', 'admin123', 'viewer123', 'password', 'changeme']);
  if (weak.has(process.env.ADMIN_PASSWORD || '')) {
    problems.push('ADMIN_PASSWORD must be set to a strong, non-default value.');
  }
  if (weak.has(process.env.VIEWER_PASSWORD || '')) {
    problems.push('VIEWER_PASSWORD must be set to a strong, non-default value.');
  }

  if (!process.env.AI_API_KEY && !process.env.GEMINI_API_KEY) {
    console.warn('WARN: no AI API key configured (AI_API_KEY). Alerts will be recorded but left unscored.');
  }

  if (problems.length > 0) {
    const header = isProd
      ? 'FATAL: insecure configuration in production:'
      : 'WARN: insecure configuration (allowed in development only):';
    console.error(`${header}\n - ${problems.join('\n - ')}`);
    if (isProd) {
      process.exit(1);
    }
  }
}
validateStartupConfig();

// 1. Seed users (admin, viewer) in DB if they do not exist
try {
  seedUsers();
  console.log('Database users seeded successfully.');
} catch (err) {
  console.error('Failed to seed database users:', err);
}

// 2. Start background worker capture scheduler
try {
  startWorker();
} catch (err) {
  console.error('Failed to start background worker:', err);
}

// 3. Start Express HTTP API Server
try {
  startServer();
} catch (err) {
  console.error('Failed to start Express HTTP server:', err);
  process.exit(1);
}
