import { chromium, Browser } from 'playwright';
import sharp from 'sharp';
import * as diff from 'diff';
import dns from 'dns';
import net from 'net';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import db, { appendAudit, DATA_DIR_PATH, sha256hex } from '../db';
import { isPrivateIP, validateUrl } from '../ssrf';
import { scoreAssetRisk } from '../llm';

let globalBrowser: Browser | null = null;

// Initialize Playwright Browser
async function getBrowserInstance(): Promise<Browser> {
  if (globalBrowser) {
    try {
      // Test if browser is still responsive
      await globalBrowser.version();
      return globalBrowser;
    } catch {
      console.warn('Existing browser unresponsive, closing and restarting...');
      try {
        await globalBrowser.close();
      } catch {}
      globalBrowser = null;
    }
  }
  globalBrowser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  return globalBrowser;
}

// Render a page once (with JavaScript executed) for the pre-registration
// liveness / parking check. Returns the final URL, page title, visible text and
// HTML so that a JS-rendered "for sale" lander can be detected. Returns null if
// the page could not be loaded at all (treated as temporarily-down, not parked).
export async function renderPageForCheck(
  url: string,
  timeoutMs = 15000
): Promise<{ status: number | null; finalUrl: string; title: string; text: string; html: string } | null> {
  let context: any = null;
  try {
    const browser = await getBrowserInstance();
    context = await browser.newContext({ viewport: { width: 1280, height: 720 }, ignoreHTTPSErrors: true });
    const page = await context.newPage();

    // Same SSRF route filter used during capture.
    await page.route('**/*', async (route: any, request: any) => {
      try {
        const parsed = new URL(request.url());
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return route.abort('blockedbyclient');
        const host = parsed.hostname;
        if (host) {
          const litHost = host.replace(/^\[|\]$/g, '');
          if (net.isIP(litHost)) {
            if (isPrivateIP(litHost)) return route.abort('blockedbyclient');
          } else {
            const lookups = await dns.promises.lookup(host, { all: true });
            if (!lookups.length || lookups.some((l) => isPrivateIP(l.address))) return route.abort('blockedbyclient');
          }
        }
      } catch {
        return route.abort('failed');
      }
      return route.continue();
    });

    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    // Give a client-side lander a moment to render its "for sale" content.
    await page.waitForTimeout(2500).catch(() => {});
    const status = response ? response.status() : null;
    const finalUrl = page.url();
    const title = (await page.title().catch(() => '')) as string;
    const text = (await page.evaluate(() => {
      const d = (globalThis as any).document;
      return d && d.body ? d.body.innerText : '';
    }).catch(() => '')) as string;
    const html = (await page.content().catch(() => '')) as string;
    await page.close().catch(() => {});
    await context.close().catch(() => {});
    context = null;
    return {
      status,
      finalUrl,
      title: title || '',
      text: (text || '').slice(0, 40000),
      html: (html || '').slice(0, 80000),
    };
  } catch {
    return null;
  } finally {
    if (context) {
      try { await context.close(); } catch {}
    }
  }
}

// 64-bit grayscale difference hash (dHash)
async function calculateDHash(imagePath: string): Promise<string | null> {
  try {
    const { data } = await sharp(imagePath)
      .resize(9, 8, { fit: 'fill' })
      .grayscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    let binaryHash = '';
    for (let row = 0; row < 8; row++) {
      for (let col = 0; col < 8; col++) {
        const left = data[row * 9 + col];
        const right = data[row * 9 + col + 1];
        binaryHash += left < right ? '1' : '0';
      }
    }

    let hexHash = '';
    for (let i = 0; i < 64; i += 4) {
      const bits = binaryHash.substring(i, i + 4);
      hexHash += parseInt(bits, 2).toString(16);
    }
    return hexHash;
  } catch (err) {
    console.error('Failed to calculate dHash:', err);
    return null;
  }
}

// Hamming distance between two 16-character hex dHash values
function getHammingDistance(hash1: string, hash2: string): number {
  let distance = 0;
  for (let i = 0; i < 16; i++) {
    const val = parseInt(hash1[i], 16) ^ parseInt(hash2[i], 16);
    let v = val;
    while (v > 0) {
      if (v & 1) distance++;
      v = v >> 1;
    }
  }
  return distance;
}

// Sensitive paths probed on each asset, with a content signature that must
// match before we flag them (avoids false positives from soft-404 pages that
// return 200 with a full HTML body). A signature of null means "any 200 with a
// non-HTML-looking, reasonably small body counts".
const SENSITIVE_PATHS: Array<{ path: string; signature: RegExp | null }> = [
  { path: '/.env', signature: /(^|\n)\s*[A-Z0-9_]+\s*=|DB_|SECRET|API_?KEY|PASSWORD|TOKEN/i },
  { path: '/.git/config', signature: /\[core\]|\[remote|repositoryformatversion/i },
  { path: '/.git/HEAD', signature: /ref:\s*refs\//i },
  { path: '/.aws/credentials', signature: /aws_access_key_id|aws_secret_access_key/i },
  { path: '/.npmrc', signature: /_authToken|registry=/i },
  { path: '/config.php', signature: /<\?php|define\(/i },
  { path: '/wp-config.php', signature: /DB_PASSWORD|DB_NAME|<\?php/i },
  { path: '/.htpasswd', signature: /^[^\s:]+:\$?[0-9a-zA-Z./$]+/m },
  { path: '/backup.sql', signature: /INSERT INTO|CREATE TABLE|DROP TABLE/i },
  { path: '/database.sql', signature: /INSERT INTO|CREATE TABLE/i },
  { path: '/.DS_Store', signature: null },
  { path: '/phpinfo.php', signature: /phpinfo\(\)|PHP Version/i },
  { path: '/server-status', signature: /Apache Server Status|Server uptime/i },
];

function looksLikeHtml(text: string): boolean {
  const head = text.slice(0, 512).toLowerCase();
  return head.includes('<!doctype html') || head.includes('<html');
}

// Exposed path vulnerability check for a single sensitive path.
async function checkExposedPath(
  baseUrl: string,
  entry: { path: string; signature: RegExp | null }
): Promise<{ exposed: boolean; details: any }> {
  try {
    const targetUrl = new URL(entry.path, baseUrl).toString();
    const check = await validateUrl(targetUrl);
    if (!check.valid) {
      return { exposed: false, details: {} };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    // 'manual' so an http->https or other redirect yields a 3xx we can ignore
    // instead of throwing; a real browser UA so hosts/CDNs don't block the probe.
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36' },
    });
    clearTimeout(timeout);

    if (res.status !== 200) {
      return { exposed: false, details: {} };
    }

    const text = (await res.text()).slice(0, 65536); // cap read at 64KB
    let exposed = false;
    if (entry.signature) {
      exposed = entry.signature.test(text);
    } else {
      // No signature: count only if the body is small and not a normal HTML page.
      exposed = !looksLikeHtml(text) && text.length < 4096;
    }

    if (exposed) {
      return {
        exposed: true,
        details: { path: entry.path, status: 200, summary: `Sensitive file exposed at ${entry.path}` },
      };
    }
    return { exposed: false, details: {} };
  } catch {
    return { exposed: false, details: {} };
  }
}

// Minimum non-vulnerable version for each library we can fingerprint client-side.
// Kept small and hardcoded on purpose (documented scope limitation in README).
const LIBRARY_MIN_SAFE: Record<string, { min: [number, number, number]; label: string; note: string }> = {
  jQuery:    { min: [3, 5, 0],   label: 'jQuery',        note: 'XSS in jQuery.htmlPrefilter (CVE-2020-11022/11023)' },
  Lodash:    { min: [4, 17, 21], label: 'Lodash',        note: 'Prototype pollution / ReDoS (CVE-2021-23337 et al.)' },
  Angular:   { min: [1, 8, 0],   label: 'AngularJS',     note: 'End-of-life AngularJS with known sandbox-escape XSS' },
  Bootstrap: { min: [4, 3, 1],   label: 'Bootstrap',     note: 'XSS in data-target/tooltip (CVE-2019-8331)' },
  Moment:    { min: [2, 29, 4],  label: 'Moment.js',     note: 'Path traversal / ReDoS (CVE-2022-31129)' },
  Vue:       { min: [2, 6, 0],   label: 'Vue',           note: 'Older 2.x lines miss template-injection fixes' },
  Handlebars:{ min: [4, 7, 7],   label: 'Handlebars',    note: 'Prototype pollution / RCE (CVE-2019-19919 et al.)' },
};

function parseVersion(ver: string): [number, number, number] {
  const parts = ver.replace(/[^0-9.]/g, '').split('.').map((x) => parseInt(x, 10));
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

function isBelow(v: [number, number, number], min: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (v[i] < min[i]) return true;
    if (v[i] > min[i]) return false;
  }
  return false; // equal → safe
}

// Check outdated JS library versions
function checkOutdatedLibraries(libs: Array<{ name: string; version: string }>): { passed: number; details: any } {
  const outdated: Array<{ name: string; version: string; rule: string; note: string }> = [];

  for (const lib of libs) {
    const ver = lib.version || '';
    if (!ver) continue;
    const rule = LIBRARY_MIN_SAFE[lib.name];
    if (!rule) continue;
    if (isBelow(parseVersion(ver), rule.min)) {
      outdated.push({
        name: rule.label,
        version: ver,
        rule: `Requires ${rule.label} >= ${rule.min.join('.')}`,
        note: rule.note,
      });
    }
  }

  if (outdated.length > 0) {
    return { passed: 0, details: { outdated } };
  }
  return { passed: 1, details: {} };
}

// Detect library + version from <script src> URLs (the common case: libraries
// loaded from a CDN as versioned files, which do NOT create a window global).
const SCRIPT_LIB_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'jQuery',     re: /jquery[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Lodash',     re: /lodash[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Angular',    re: /angular(?:js)?[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Bootstrap',  re: /bootstrap[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Moment',     re: /moment(?:js)?[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Vue',        re: /vue[-._/@]?(\d+\.\d+\.\d+)/i },
  { name: 'Handlebars', re: /handlebars[-._/@]?(\d+\.\d+\.\d+)/i },
];

function detectLibsFromScriptUrls(urls: string[]): Array<{ name: string; version: string }> {
  const found: Array<{ name: string; version: string }> = [];
  for (const url of urls) {
    for (const p of SCRIPT_LIB_PATTERNS) {
      const m = url.match(p.re);
      if (m) found.push({ name: p.name, version: m[1] });
    }
  }
  return found;
}

// Merge globally-detected libs with script-URL-detected ones, de-duplicated by
// name (a runtime global version is preferred over a URL-parsed one).
function mergeDetectedLibs(
  globals: Array<{ name: string; version: string }>,
  scripts: Array<{ name: string; version: string }>
): Array<{ name: string; version: string }> {
  const byName = new Map<string, { name: string; version: string }>();
  for (const l of [...globals, ...scripts]) {
    if (l && l.name && l.version && !byName.has(l.name)) byName.set(l.name, l);
  }
  return Array.from(byName.values());
}

// Render one page (with JS) and return every host it connects to — from network
// requests and from <a href> links.
async function collectHostsFromPage(url: string, timeoutMs = 15000, waitMs = 2500): Promise<Set<string>> {
  let context: any = null;
  const hosts = new Set<string>();
  try {
    const browser = await getBrowserInstance();
    context = await browser.newContext({ viewport: { width: 1280, height: 720 }, ignoreHTTPSErrors: true });
    const page = await context.newPage();

    page.on('request', (req: any) => {
      try {
        const u = new URL(req.url());
        if (u.protocol === 'http:' || u.protocol === 'https:') hosts.add(u.hostname.toLowerCase());
      } catch { /* ignore */ }
    });

    await page.route('**/*', async (route: any, request: any) => {
      try {
        const parsed = new URL(request.url());
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return route.abort('blockedbyclient');
        const host = parsed.hostname;
        if (host) {
          const litHost = host.replace(/^\[|\]$/g, '');
          if (net.isIP(litHost)) {
            if (isPrivateIP(litHost)) return route.abort('blockedbyclient');
          } else {
            const lookups = await dns.promises.lookup(host, { all: true });
            if (!lookups.length || lookups.some((l) => isPrivateIP(l.address))) return route.abort('blockedbyclient');
          }
        }
      } catch {
        return route.abort('failed');
      }
      return route.continue();
    });

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    await page.waitForTimeout(waitMs).catch(() => {});

    const linkHrefs = (await page.evaluate(() => {
      const d = (globalThis as any).document;
      if (!d) return [] as string[];
      return Array.from(d.querySelectorAll('a[href]')).map((a: any) => a.href);
    }).catch(() => [])) as string[];
    for (const href of linkHrefs) {
      try {
        const u = new URL(href);
        if (u.protocol === 'http:' || u.protocol === 'https:') hosts.add(u.hostname.toLowerCase());
      } catch { /* ignore */ }
    }

    await page.close().catch(() => {});
    await context.close().catch(() => {});
    context = null;
  } catch {
    /* return whatever was collected before failure */
  } finally {
    if (context) {
      try { await context.close(); } catch {}
    }
  }
  return hosts;
}

// Discover distinct hosts a page connects to. With depth >= 2, it also renders
// each first-level host (bounded by maxChildRenders) and folds in the hosts THEY
// connect to — i.e. the sub-domains of the discovered sites. Excludes the
// parent's own host and anything that fails validation.
export async function discoverConnectedHosts(
  url: string,
  opts: { depth?: number; maxChildRenders?: number } = {}
): Promise<Array<{ host: string; url: string }>> {
  const depth = opts.depth ?? 1;
  const maxChildRenders = opts.maxChildRenders ?? 8;
  let parentHost = '';
  try { parentHost = new URL(url).hostname.toLowerCase(); } catch {}

  const allHosts = new Set<string>();
  const level1 = await collectHostsFromPage(url, 15000, 2500);
  level1.forEach((h) => allHosts.add(h));

  if (depth >= 2) {
    // Recurse one level into the discovered hosts to gather their sub-domains.
    const children = Array.from(level1).filter((h) => h && h !== parentHost).slice(0, maxChildRenders);
    for (const h of children) {
      const childUrl = `https://${h}/`;
      try {
        const v = await validateUrl(childUrl);
        if (!v.valid) continue;
        const sub = await collectHostsFromPage(childUrl, 12000, 1800);
        sub.forEach((x) => allHosts.add(x));
      } catch { /* skip this child */ }
    }
  }

  const results: Array<{ host: string; url: string }> = [];
  let checked = 0;
  for (const h of allHosts) {
    if (!h || h === parentHost) continue;
    if (checked >= 120) break; // bound the number of DNS validations
    checked++;
    const candidateUrl = `https://${h}/`;
    const v = await validateUrl(candidateUrl);
    if (v.valid) results.push({ host: h, url: candidateUrl });
  }
  results.sort((a, b) => a.host.localeCompare(b.host));
  return results;
}

// Capture Single Asset Pipeline
async function captureAsset(asset: any) {
  console.log(`Starting capture for asset: ${asset.name} (${asset.url})`);
  
  const capturedAt = new Date().toISOString();
  let pageContext = null;
  let browserInstance = null;

  let httpStatus: number | null = null;
  let fetchError: string | null = null;
  let responseHeaders = '{}';
  let screenshotPath: string | null = null;
  let htmlPath: string | null = null;
  let phash: string | null = null;
  let htmlSha256: string | null = null;
  let currentHtmlContent = '';

  const snapshotIdPlaceholder = db.prepare('SELECT max(id) as maxId FROM snapshots').get() as any;
  const nextSnapshotId = (snapshotIdPlaceholder?.maxId || 0) + 1;

  try {
    // 1. SSRF Check: resolve IP at capture time
    const validation = await validateUrl(asset.url);
    if (!validation.valid) {
      throw new Error(`SSRF Blocked at capture: ${validation.error}`);
    }

    browserInstance = await getBrowserInstance();
    pageContext = await browserInstance.newContext({
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true,
    });

    // Enforce Playwright request interception (mitigate page-initiated SSRF)
    const page = await pageContext.newPage();
    await page.route('**/*', async (route, request) => {
      try {
        const reqUrl = request.url();
        const parsed = new URL(reqUrl);
        // Only http/https may leave the browser; block file:, data-nav, etc.
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          return route.abort('blockedbyclient');
        }
        const host = parsed.hostname;
        if (host) {
          const litHost = host.replace(/^\[|\]$/g, '');
          if (net.isIP(litHost)) {
            if (isPrivateIP(litHost)) return route.abort('blockedbyclient');
          } else {
            // Re-resolve every request (kills DNS rebinding) and reject if ANY
            // resolved address is private/reserved.
            const lookups = await dns.promises.lookup(host, { all: true });
            if (!lookups.length || lookups.some((l) => isPrivateIP(l.address))) {
              return route.abort('blockedbyclient');
            }
          }
        }
      } catch {
        // Safe abort on resolution failure
        return route.abort('failed');
      }
      return route.continue();
    });

    // Track main-frame navigation redirects. Two independent concerns:
    //  - blockedRedirect: a redirect pointed at a private/invalid address (real
    //    SSRF attempt) -> always block.
    //  - redirectCount: a long-but-legitimate chain (http->https->www->locale->
    //    trailing slash) is normal on the real web, so the count limit is
    //    generous. The per-request route filter above is the primary SSRF guard.
    let redirectCount = 0;
    let blockedRedirect = false;
    page.on('response', async (response) => {
      const request = response.request();
      const status = response.status();
      if (request.isNavigationRequest() && request.frame() === page.mainFrame() && status >= 300 && status <= 399) {
        redirectCount++;
        const redirectUrl = response.headers()['location'];
        if (redirectUrl) {
          try {
            const absoluteRedirectUrl = new URL(redirectUrl, response.url()).toString();
            const check = await validateUrl(absoluteRedirectUrl);
            if (!check.valid) blockedRedirect = true;
          } catch (urlErr) {
            blockedRedirect = true; // fail closed on a malformed redirect target
          }
        }
      }
    });

    // Load URL with 30s timeout
    const response = await page.goto(asset.url, {
      waitUntil: 'networkidle',
      timeout: 30000,
    });

    if (blockedRedirect) {
      throw new Error('SSRF Blocked: a redirect pointed at a private or invalid address');
    }
    if (redirectCount > 8) {
      throw new Error(`Too many redirects (${redirectCount}); capture aborted`);
    }

    if (!response) {
      throw new Error('No response received from asset target');
    }

    httpStatus = response.status();
    const rawHeaders = response.headers();
    // Normalize header keys to lowercase
    const normalizedHeaders: Record<string, string> = {};
    for (const key of Object.keys(rawHeaders)) {
      normalizedHeaders[key.toLowerCase()] = rawHeaders[key];
    }
    responseHeaders = JSON.stringify(normalizedHeaders);

    // Save screenshot
    const sPath = path.join(DATA_DIR_PATH, 'screens', `${nextSnapshotId}.png`);
    await page.screenshot({ path: sPath, fullPage: false });
    screenshotPath = sPath;

    // Calculate dHash
    phash = await calculateDHash(sPath);

    // Save HTML (limit to 2MB)
    currentHtmlContent = await page.content();
    if (currentHtmlContent.length > 2 * 1024 * 1024) {
      currentHtmlContent = currentHtmlContent.substring(0, 2 * 1024 * 1024) + '\n<!-- Capture truncated to 2MB -->';
    }
    const hPath = path.join(DATA_DIR_PATH, 'html', `${nextSnapshotId}.html`);
    fs.writeFileSync(hPath, currentHtmlContent, 'utf-8');
    htmlPath = hPath;
    htmlSha256 = sha256hex(currentHtmlContent);

    // Outdated JS evaluation — detect from runtime globals AND from versioned
    // <script src> URLs (CDN-loaded libraries that create no global).
    const detected = await page.evaluate(() => {
      const w = window as any;
      const d = (globalThis as any).document;
      const globals: any[] = [];
      try {
        if (w.jQuery) globals.push({ name: 'jQuery', version: w.jQuery.fn?.jquery });
        if (w.angular) globals.push({ name: 'Angular', version: w.angular.version?.full });
        if (w._ && w._.VERSION) globals.push({ name: 'Lodash', version: w._.VERSION });
        if (w.bootstrap && w.bootstrap.Tooltip?.VERSION) globals.push({ name: 'Bootstrap', version: w.bootstrap.Tooltip.VERSION });
        if (w.moment && typeof w.moment.version === 'string') globals.push({ name: 'Moment', version: w.moment.version });
        if (w.Vue && w.Vue.version) globals.push({ name: 'Vue', version: w.Vue.version });
        if (w.Handlebars && w.Handlebars.VERSION) globals.push({ name: 'Handlebars', version: w.Handlebars.VERSION });
      } catch {}
      let scripts: string[] = [];
      try {
        scripts = d ? Array.from(d.querySelectorAll('script[src]')).map((s: any) => s.src || '') : [];
      } catch {}
      return { globals, scripts };
    });
    const detectedLibs = mergeDetectedLibs(
      (detected && detected.globals) || [],
      detectLibsFromScriptUrls((detected && detected.scripts) || [])
    );

    // Close page
    await page.close();
    await pageContext.close();

    // 2. Perform Vulnerability Checks
    const vulnCheckResults: Array<{ check_type: string; passed: number; details: any }> = [];

    // Header checks
    const csp = normalizedHeaders['content-security-policy'];
    vulnCheckResults.push({
      check_type: 'header_csp',
      passed: csp ? 1 : 0,
      details: csp ? { policy: csp } : { error: 'Content-Security-Policy header is missing' },
    });

    const hsts = normalizedHeaders['strict-transport-security'];
    vulnCheckResults.push({
      check_type: 'header_hsts',
      passed: hsts ? 1 : 0,
      details: hsts ? { hsts } : { error: 'Strict-Transport-Security header is missing' },
    });

    const xfo = normalizedHeaders['x-frame-options'];
    vulnCheckResults.push({
      check_type: 'header_xfo',
      passed: xfo ? 1 : 0,
      details: xfo ? { xfo } : { error: 'X-Frame-Options header is missing' },
    });

    const xcto = normalizedHeaders['x-content-type-options'];
    vulnCheckResults.push({
      check_type: 'header_xcto',
      passed: xcto && xcto.toLowerCase().includes('nosniff') ? 1 : 0,
      details: xcto ? { xcto } : { error: 'X-Content-Type-Options is missing or not set to nosniff' },
    });

    // Exposed path checks — probe the sensitive-path list and collect any hits.
    const exposedFindings: any[] = [];
    for (const entry of SENSITIVE_PATHS) {
      const result = await checkExposedPath(asset.url, entry);
      if (result.exposed) {
        exposedFindings.push(result.details);
      }
    }
    vulnCheckResults.push({
      check_type: 'exposed_path',
      passed: exposedFindings.length === 0 ? 1 : 0,
      details: exposedFindings.length === 0 ? {} : { findings: exposedFindings },
    });

    // Outdated JS check
    const jsCheck = checkOutdatedLibraries(detectedLibs);
    vulnCheckResults.push({
      check_type: 'outdated_js',
      passed: jsCheck.passed,
      details: jsCheck.details,
    });

    // 3. Diff comparison with previous snapshot
    const prevSnapshot = db.prepare(`
      SELECT id, screenshot_path, html_path, phash, html_sha256
      FROM snapshots
      WHERE asset_id = ?
      ORDER BY captured_at DESC
      LIMIT 1
    `).get(asset.id) as any;

    let visualDistance: number | null = null;
    let visualChanged = 0;
    let textChanged = 0;
    let textDiffSummary: string | null = null;

    if (prevSnapshot) {
      // Visual Diff
      if (phash && prevSnapshot.phash) {
        visualDistance = getHammingDistance(phash, prevSnapshot.phash);
        if (visualDistance > 10) {
          visualChanged = 1;
        }
      }

      // Text Diff
      if (htmlSha256 !== prevSnapshot.html_sha256) {
        textChanged = 1;
        let prevHtml = '';
        if (prevSnapshot.html_path && fs.existsSync(prevSnapshot.html_path)) {
          prevHtml = fs.readFileSync(prevSnapshot.html_path, 'utf-8');
        }
        textDiffSummary = diff.createTwoFilesPatch(
          `prev_snapshot_${prevSnapshot.id}.html`,
          `snapshot_${nextSnapshotId}.html`,
          prevHtml,
          currentHtmlContent
        );
        if (textDiffSummary.length > 8192) {
          textDiffSummary = textDiffSummary.substring(0, 8192) + '\n... [Diff truncated to 8KB]';
        }
      }
    }

    // 4. Save results in DB transaction
    const saveTx = db.transaction(() => {
      // Insert Snapshot
      db.prepare(`
        INSERT INTO snapshots (id, asset_id, captured_at, http_status, fetch_error, response_headers, screenshot_path, html_path, phash, html_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(nextSnapshotId, asset.id, capturedAt, httpStatus, null, responseHeaders, screenshotPath, htmlPath, phash, htmlSha256);

      // Insert Diff
      db.prepare(`
        INSERT INTO diff_results (snapshot_id, prev_snapshot_id, visual_distance, visual_changed, text_changed, text_diff_summary)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(nextSnapshotId, prevSnapshot ? prevSnapshot.id : null, visualDistance, visualChanged, textChanged, textDiffSummary);

      // Insert Vuln checks
      for (const check of vulnCheckResults) {
        db.prepare(`
          INSERT INTO vuln_check_results (snapshot_id, check_type, passed, details)
          VALUES (?, ?, ?, ?)
        `).run(nextSnapshotId, check.check_type, check.passed, JSON.stringify(check.details));
      }
    });
    saveTx();

    // 5. Evaluate Alerts (Transition boundaries)
    let triggeredAlerts: Array<{ kind: 'change' | 'vuln' | 'availability'; title: string; failed_checks: any[] }> = [];

    if (prevSnapshot) {
      // Change Alert
      if (visualChanged || textChanged) {
        triggeredAlerts.push({
          kind: 'change',
          title: `Unauthorized change detected on ${asset.name}`,
          failed_checks: [],
        });
      }

      // Vuln Alerts (Transition pass -> fail only)
      for (const check of vulnCheckResults) {
        if (check.passed === 0) {
          const prevCheck = db.prepare(`
            SELECT passed FROM vuln_check_results
            WHERE snapshot_id = ? AND check_type = ?
          `).get(prevSnapshot.id, check.check_type) as { passed: number } | undefined;

          // If it was passing previously (or didn't exist, which we treat as baseline not alerting, i.e. alert only on active transition), we alert
          if (prevCheck && prevCheck.passed === 1) {
            triggeredAlerts.push({
              kind: 'vuln',
              title: `Vulnerability introduced: ${check.check_type.replace('header_', '').toUpperCase()} finding`,
              failed_checks: [check],
            });
          }
        }
      }

      // Availability Alert (Transition to fail)
      const prevFailed = prevSnapshot.http_status === null || prevSnapshot.http_status >= 500;
      const currFailed = httpStatus === null || httpStatus >= 500;
      if (!prevFailed && currFailed) {
        triggeredAlerts.push({
          kind: 'availability',
          title: `${asset.name} is down (HTTP ${httpStatus ?? 'Failed to connect'})`,
          failed_checks: [],
        });
      }
    } else {
      // For the first capture (baseline), we don't alert on changes or vulns. 
      // But we CAN alert on availability failure if the baseline itself fails to connect or returns >= 500.
      const currFailed = httpStatus === null || httpStatus >= 500;
      if (currFailed) {
        triggeredAlerts.push({
          kind: 'availability',
          title: `${asset.name} baseline capture failed (HTTP ${httpStatus ?? 'Connection failed'})`,
          failed_checks: [],
        });
      }
    }

    // 6. Handle AI risk scoring if alerts triggered
    for (const alert of triggeredAlerts) {
      console.log(`Triggering Alert: ${alert.title} (${alert.kind})`);

      // Invoke Gemini API (src/llm.ts). Pass the real HTTP status so the model
      // can weigh a 5xx/availability signal instead of always seeing "null".
      const aiScore = await scoreAssetRisk({
        assetName: asset.name,
        assetUrl: asset.url,
        httpStatus,
        fetchError: httpStatus !== null && httpStatus >= 500 ? `HTTP ${httpStatus}` : null,
        diffSummary: textDiffSummary,
        failedChecks: alert.failed_checks,
      });

      const alertInsert = db.prepare(`
        INSERT INTO alert_events (asset_id, snapshot_id, kind, title, severity, ai_explanation, ai_remediation, ai_model, ai_error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        asset.id,
        nextSnapshotId,
        alert.kind,
        alert.title,
        aiScore.severity,
        aiScore.explanation,
        aiScore.remediation,
        aiScore.model,
        aiScore.error || null
      );

      appendAudit('system', 'alert.create', 'alert_events', Number(alertInsert.lastInsertRowid), {
        asset_id: asset.id,
        kind: alert.kind,
        title: alert.title,
        severity: aiScore.severity,
      });
    }

  } catch (err: any) {
    console.error(`Pipeline failure for asset ${asset.id}:`, err.message || err);
    fetchError = err.message || String(err);

    // Save failed snapshot inside DB
    const failedSnapshotId = nextSnapshotId;
    const saveFailedTx = db.transaction(() => {
      db.prepare(`
        INSERT INTO snapshots (id, asset_id, captured_at, http_status, fetch_error, response_headers, screenshot_path, html_path, phash, html_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(failedSnapshotId, asset.id, capturedAt, null, fetchError, '{}', null, null, null, null);

      // Diff results for failed check is dummy
      db.prepare(`
        INSERT INTO diff_results (snapshot_id, prev_snapshot_id, visual_distance, visual_changed, text_changed, text_diff_summary)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(failedSnapshotId, null, null, 0, 0, null);
    });
    saveFailedTx();

    // Check transition for availability alert (was online, now crashed)
    const prevSnapshot = db.prepare(`
      SELECT id, http_status, fetch_error FROM snapshots
      WHERE asset_id = ? AND id < ?
      ORDER BY captured_at DESC
      LIMIT 1
    `).get(asset.id, failedSnapshotId) as any;

    const prevFailed = prevSnapshot ? (prevSnapshot.http_status === null || prevSnapshot.http_status >= 500 || prevSnapshot.fetch_error !== null) : false;

    if (!prevFailed) {
      // Trigger availability alert
      const title = `${asset.name} connection failed: ${fetchError}`;
      const aiScore = await scoreAssetRisk({
        assetName: asset.name,
        assetUrl: asset.url,
        httpStatus: null,
        fetchError,
        diffSummary: null,
        failedChecks: [],
      });

      const alertInsert = db.prepare(`
        INSERT INTO alert_events (asset_id, snapshot_id, kind, title, severity, ai_explanation, ai_remediation, ai_model, ai_error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        asset.id,
        failedSnapshotId,
        'availability',
        title,
        aiScore.severity,
        aiScore.explanation,
        aiScore.remediation,
        aiScore.model,
        aiScore.error || null
      );

      appendAudit('system', 'alert.create', 'alert_events', Number(alertInsert.lastInsertRowid), {
        asset_id: asset.id,
        kind: 'availability',
        title,
        severity: aiScore.severity,
      });
    }

  } finally {
    if (pageContext) {
      try {
        await pageContext.close();
      } catch {}
    }
  }
}

// Background scheduler tick
async function schedulerTick() {
  try {
    const nowStr = new Date().toISOString();
    // Query active and not deleted assets whose scheduled capture time has passed
    const dueAssets = db.prepare(`
      SELECT * FROM assets
      WHERE is_active = 1 AND is_deleted = 0 AND next_capture_at <= ?
    `).all(nowStr) as any[];

    for (const asset of dueAssets) {
      // Run capture
      await captureAsset(asset);

      // Re-schedule asset with jitter (±20s)
      const jitterSeconds = Math.floor(Math.random() * 41) - 20; // -20 to +20 seconds
      const interval = asset.interval_seconds;
      const delaySeconds = Math.max(60, interval + jitterSeconds); // Ensure at least 60 seconds interval
      const nextCapture = new Date(Date.now() + delaySeconds * 1000).toISOString();

      db.prepare(`
        UPDATE assets
        SET next_capture_at = ?
        WHERE id = ?
      `).run(nextCapture, asset.id);
    }
  } catch (err) {
    console.error('Error during scheduler tick:', err);
  }
}

// Retention sweep (spec §6.5): delete screenshot + HTML *files* older than 24h
// to bound disk use. DB rows and audit rows are never touched; the paths are
// nulled so the API/UI degrade gracefully to "file no longer retained".
const RETENTION_MS = 24 * 60 * 60 * 1000;

function retentionSweep() {
  try {
    const cutoff = new Date(Date.now() - RETENTION_MS).toISOString();
    const stale = db.prepare(`
      SELECT id, screenshot_path, html_path
      FROM snapshots
      WHERE captured_at < ? AND (screenshot_path IS NOT NULL OR html_path IS NOT NULL)
    `).all(cutoff) as any[];

    const screensDir = path.resolve(path.join(DATA_DIR_PATH, 'screens'));
    const htmlDir = path.resolve(path.join(DATA_DIR_PATH, 'html'));

    for (const row of stale) {
      for (const [p, dir] of [[row.screenshot_path, screensDir], [row.html_path, htmlDir]] as const) {
        if (!p) continue;
        const abs = path.resolve(p);
        // Never delete outside the managed data dirs.
        if (abs !== dir && !abs.startsWith(dir + path.sep)) continue;
        try {
          if (fs.existsSync(abs)) fs.unlinkSync(abs);
        } catch (e) {
          console.warn(`Retention: failed to delete ${abs}:`, (e as any)?.message || e);
        }
      }
      db.prepare('UPDATE snapshots SET screenshot_path = NULL, html_path = NULL WHERE id = ?').run(row.id);
    }
    if (stale.length > 0) {
      console.log(`Retention sweep cleared files for ${stale.length} snapshot(s) older than 24h.`);
    }
  } catch (err) {
    console.error('Retention sweep error:', err);
  }
}

// Start Worker Scheduler (sequential loop utilizing setTimeout to prevent overlapping ticks)
export function startWorker() {
  console.log('Starting background snapshot worker loop (sequential setTimeout)...');

  async function runLoop() {
    await schedulerTick();
    setTimeout(runLoop, 30000);
  }

  runLoop();

  // Run retention once at startup, then hourly.
  retentionSweep();
  setInterval(retentionSweep, 60 * 60 * 1000);
}

// Relaunch browser on process exit or crash cleanup
process.on('exit', async () => {
  if (globalBrowser) {
    await globalBrowser.close();
  }
});
