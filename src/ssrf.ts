import dns from 'dns';
import net from 'net';
import { URL } from 'url';

/**
 * Normalize an IPv4-mapped / IPv4-compatible IPv6 address down to its embedded
 * IPv4 form so range checks apply. e.g. "::ffff:169.254.169.254" -> "169.254.169.254",
 * "::ffff:a9fe:a9fe" -> "169.254.169.254".
 */
function unwrapMappedIPv4(ip: string): string {
  const lower = ip.toLowerCase();
  const m = lower.match(/^::ffff:(.+)$/);
  if (!m) return ip;
  const rest = m[1];
  if (net.isIPv4(rest)) return rest;
  // Hex form: ::ffff:a9fe:a9fe
  const hex = rest.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return ip;
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) {
    return true; // malformed → treat as unsafe
  }
  const [a, b] = parts;

  if (a === 0) return true;                              // 0.0.0.0/8 "this host"
  if (a === 10) return true;                             // 10.0.0.0/8 private
  if (a === 127) return true;                            // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;              // 169.254.0.0/16 link-local (incl. cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true;     // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true;              // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true;    // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && parts[2] === 0) return true;   // 192.0.0.0/24 IETF protocol
  if (a === 192 && b === 0 && parts[2] === 2) return true;   // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true;     // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && parts[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return true;  // 203.0.113.0/24 TEST-NET-3
  if (a >= 224 && a <= 239) return true;                // 224.0.0.0/4 multicast
  if (a >= 240) return true;                            // 240.0.0.0/4 reserved + 255.255.255.255

  return false;
}

function isPrivateIPv6(ipRaw: string): boolean {
  const ip = ipRaw.toLowerCase();

  if (ip === '::1') return true;                        // loopback
  if (ip === '::' ) return true;                        // unspecified
  if (ip.startsWith('fe80:') || ip.startsWith('fe80::')) return true; // link-local fe80::/10
  if (/^fe[89ab]/.test(ip)) return true;               // fe80::/10 broader match
  if (/^f[cd]/.test(ip)) return true;                  // fc00::/7 unique local
  if (ip.startsWith('ff')) return true;                // ff00::/8 multicast
  if (ip.startsWith('64:ff9b:')) return true;          // 64:ff9b::/96 NAT64 (maps to IPv4)
  if (ip.startsWith('2001:db8:')) return true;         // documentation
  if (ip.startsWith('::ffff:')) return true;           // any mapped addr not already unwrapped

  return false;
}

export function isPrivateIP(ip: string): boolean {
  // Strip IPv6 brackets / zone index and whitespace.
  const cleanIp = ip.replace(/^\[|\]$/g, '').replace(/%.*$/, '').trim();

  const unwrapped = unwrapMappedIPv4(cleanIp);

  if (net.isIPv4(unwrapped)) {
    return isPrivateIPv4(unwrapped);
  }
  if (net.isIPv6(cleanIp)) {
    return isPrivateIPv6(cleanIp);
  }
  // Not a recognizable IP literal → fail closed.
  return true;
}

/**
 * Reject hostnames that are numeric IP literals in non-dotted-decimal form
 * (decimal 2130706433, octal 0177.0.0.1, hex 0x7f000001) which bypass naive
 * string range checks but still resolve to private space.
 */
function isSuspiciousNumericHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (/^0x[0-9a-f]+$/.test(h)) return true;          // hex literal
  if (/^0[0-7]+$/.test(h)) return true;              // octal literal
  if (/^\d+$/.test(h)) return true;                  // plain decimal (dword) literal
  // Dotted forms with octal/hex octets, e.g. 0177.0.0.1 or 0x7f.0.0.1
  if (h.includes('.')) {
    const octets = h.split('.');
    if (octets.every((o) => /^(0x[0-9a-f]+|0[0-7]*|\d+)$/.test(o))) {
      if (octets.some((o) => /^0x/.test(o) || /^0[0-7]+$/.test(o))) return true;
    }
  }
  return false;
}

export async function validateUrl(
  urlStr: string
): Promise<{ valid: boolean; ip: string | null; error?: string }> {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, ip: null, error: 'Protocol must be http or https' };
    }

    // Reject embedded credentials (http://user:pass@host) — a common SSRF/phishing vector.
    if (parsed.username || parsed.password) {
      return { valid: false, ip: null, error: 'Credentials in URL are not allowed' };
    }

    const hostname = parsed.hostname;
    if (!hostname) {
      return { valid: false, ip: null, error: 'Invalid hostname' };
    }

    if (isSuspiciousNumericHost(hostname)) {
      return { valid: false, ip: null, error: `Blocked: numeric/encoded host "${hostname}"` };
    }

    // If the host is already an IP literal, validate it directly.
    if (net.isIP(hostname.replace(/^\[|\]$/g, ''))) {
      const lit = hostname.replace(/^\[|\]$/g, '');
      if (isPrivateIP(lit)) {
        return { valid: false, ip: lit, error: `SSRF Blocked: IP ${lit} is private/reserved` };
      }
      return { valid: true, ip: lit };
    }

    // Resolve ALL addresses (A + AAAA). Reject if ANY resolved address is
    // private/reserved — a hostname with one public and one private record
    // must not slip through.
    const results = await dns.promises.lookup(hostname, { all: true });
    if (!results || results.length === 0) {
      return { valid: false, ip: null, error: 'Hostname did not resolve to any address' };
    }
    for (const r of results) {
      if (isPrivateIP(r.address)) {
        return { valid: false, ip: r.address, error: `SSRF Blocked: ${hostname} resolves to private/reserved IP ${r.address}` };
      }
    }

    return { valid: true, ip: results[0].address };
  } catch (err: any) {
    return { valid: false, ip: null, error: err.message || 'Failed to resolve URL' };
  }
}
