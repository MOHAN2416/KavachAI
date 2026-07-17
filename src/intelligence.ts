import db from './db';

// Human labels and risk weights for each vuln check. Weights drive how much a
// failing check subtracts from the 0-100 posture score.
const CHECK_LABELS: Record<string, string> = {
  header_csp: 'Content-Security-Policy',
  header_hsts: 'HSTS (HTTPS enforcement)',
  header_xfo: 'X-Frame-Options (clickjacking)',
  header_xcto: 'X-Content-Type-Options (nosniff)',
  exposed_path: 'Exposed sensitive files',
  outdated_js: 'Outdated JS libraries',
};
const CHECK_WEIGHT: Record<string, number> = {
  header_csp: 8, header_hsts: 8, header_xfo: 6, header_xcto: 6, exposed_path: 25, outdated_js: 15,
};
const COMPLIANCE_ITEMS = ['header_csp', 'header_hsts', 'header_xfo', 'header_xcto', 'exposed_path', 'outdated_js'];

export interface AssetIntel {
  id: number;
  name: string;
  url: string;
  parent_asset_id: number | null;
  score: number;
  grade: string;
  available: boolean;
  failedChecks: Array<{ type: string; label: string }>;
  compliance: { passed: number; total: number; pct: number; failing: string[] };
  signals: string[];
  alerts24h: { high: number; medium: number; low: number; change: number; availability: number };
}

function grade(score: number): string {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

function assetIntel(asset: any): AssetIntel {
  const latest = db.prepare(
    'SELECT id, http_status, fetch_error FROM snapshots WHERE asset_id = ? ORDER BY captured_at DESC LIMIT 1'
  ).get(asset.id) as any;

  let score = 100;
  const failedChecks: Array<{ type: string; label: string }> = [];
  const failing: string[] = [];
  let passedCount = 0;

  const available = !latest
    ? true
    : !(latest.http_status === null || latest.http_status >= 500 || latest.fetch_error);

  if (latest) {
    for (const ct of COMPLIANCE_ITEMS) {
      const row = db.prepare(
        'SELECT passed FROM vuln_check_results WHERE snapshot_id = ? AND check_type = ?'
      ).get(latest.id, ct) as any;
      if (row) {
        if (row.passed === 1) {
          passedCount++;
        } else {
          failedChecks.push({ type: ct, label: CHECK_LABELS[ct] });
          failing.push(CHECK_LABELS[ct]);
          score -= CHECK_WEIGHT[ct] || 5;
        }
      }
    }
    if (!available) score -= 20;
  }

  // Recent alert activity (last 24h).
  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const alertRows = db.prepare(
    'SELECT kind, severity, COUNT(*) AS c FROM alert_events WHERE asset_id = ? AND created_at >= ? GROUP BY kind, severity'
  ).all(asset.id, since) as any[];
  const alerts24h = { high: 0, medium: 0, low: 0, change: 0, availability: 0 };
  for (const r of alertRows) {
    if (r.severity === 'high') alerts24h.high += r.c;
    else if (r.severity === 'medium') alerts24h.medium += r.c;
    else if (r.severity === 'low') alerts24h.low += r.c;
    if (r.kind === 'change') alerts24h.change += r.c;
    if (r.kind === 'availability') alerts24h.availability += r.c;
  }
  score -= alerts24h.high * 12 + alerts24h.medium * 5 + alerts24h.low * 2;
  score = Math.max(0, Math.min(100, Math.round(score)));

  // Trend / emerging-threat signals.
  const signals: string[] = [];
  if (alerts24h.high > 0) signals.push(`${alerts24h.high} high-severity finding${alerts24h.high > 1 ? 's' : ''} in the last 24h`);
  if (alerts24h.change >= 2) signals.push(`Repeated content changes (${alerts24h.change} in 24h) — possible active defacement`);
  if (alerts24h.availability >= 2) signals.push(`Recurring availability failures (${alerts24h.availability} in 24h)`);
  if (latest) {
    const prev = db.prepare(
      'SELECT id FROM snapshots WHERE asset_id = ? AND id < ? ORDER BY captured_at DESC LIMIT 1'
    ).get(asset.id, latest.id) as any;
    if (prev) {
      const prevFailed = (db.prepare(
        'SELECT COUNT(*) AS c FROM vuln_check_results WHERE snapshot_id = ? AND passed = 0'
      ).get(prev.id) as any).c;
      if (failedChecks.length > prevFailed) {
        signals.push('Security posture degrading (more failing checks than the previous capture)');
      }
    }
  }
  if (!available) signals.push('Currently unreachable or returning server errors');

  const total = COMPLIANCE_ITEMS.length;
  return {
    id: asset.id,
    name: asset.name,
    url: asset.url,
    parent_asset_id: asset.parent_asset_id ?? null,
    score,
    grade: grade(score),
    available,
    failedChecks,
    compliance: { passed: passedCount, total, pct: Math.round((passedCount / total) * 100), failing },
    signals,
    alerts24h,
  };
}

export interface PortfolioIntel {
  summary: { count: number; avgScore: number; highRisk: number; avgCompliance: number; totalSignals: number };
  assets: AssetIntel[];
}

// Compute the whole intelligence payload for the given asset scope ('all' for
// admins, or an explicit list of asset IDs for a viewer). Assets are ranked
// riskiest-first.
export function computePortfolioIntelligence(filter: number[] | 'all'): PortfolioIntel {
  let assets: any[];
  if (filter === 'all') {
    assets = db.prepare('SELECT id, name, url, parent_asset_id FROM assets WHERE is_deleted = 0 ORDER BY id ASC').all() as any[];
  } else if (filter.length === 0) {
    assets = [];
  } else {
    const ph = filter.map(() => '?').join(',');
    assets = db.prepare(`SELECT id, name, url, parent_asset_id FROM assets WHERE is_deleted = 0 AND id IN (${ph})`).all(...filter) as any[];
  }

  const items = assets.map(assetIntel);
  const ranked = [...items].sort((a, b) => a.score - b.score); // riskiest first
  const count = items.length;
  const avgScore = count ? Math.round(items.reduce((s, a) => s + a.score, 0) / count) : 100;
  const avgCompliance = count ? Math.round(items.reduce((s, a) => s + a.compliance.pct, 0) / count) : 100;
  const highRisk = items.filter((a) => a.score < 50).length;
  const totalSignals = items.reduce((s, a) => s + a.signals.length, 0);

  return { summary: { count, avgScore, highRisk, avgCompliance, totalSignals }, assets: ranked };
}
