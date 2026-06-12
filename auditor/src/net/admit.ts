// SSRF admission control for remote MCP targets — centralized, DEFAULT-DENY.
//
// PLAN-UI.md §6: the audited MCP endpoint is attacker-influenced input. Before
// the auditor ever opens a socket to it we run admitTarget(), which:
//   - requires https
//   - allows only explicit safe ports (443 + env-config list)
//   - rejects userinfo (user:pass@host) and non-http(s) schemes
//   - resolves A + AAAA and rejects if ANY resolved address is
//     private / loopback / link-local / CGNAT / ULA / metadata / multicast / unspecified
//   - returns the PINNED resolved IP so the caller can connect to that exact IP
//     while still sending the original Host header / TLS SNI (defeats DNS
//     rebinding: the name resolves once, here, and the connection uses the
//     vetted address — not a second, attacker-controlled re-resolution).
//
// Allowlist model (default-deny):
//   - SEEDED_TARGET_ALLOWLIST   host[:port],...  -> always admitted (deterministic demo target).
//   - EXTERNAL_TARGET_ALLOWLIST host[:port],...  -> opt-in for real external endpoints.
//   - TARGET_STRICT (default "1"/on): a host in NEITHER allowlist is DENIED.
//     Set TARGET_STRICT=0 to allow non-allowlisted hosts (still IP-vetted) — NOT for the demo.
//
// CALLER CONTRACT (the caller MUST honor these — admit cannot enforce them):
//   1. Connect to result.pinnedIp, sending Host/SNI = the original hostname.
//   2. Do NOT follow redirects (or re-run admitTarget on every hop's URL).
//   3. Do NOT honor outbound proxy env (HTTP(S)_PROXY) — go direct so the pin holds.
//   4. Apply CONNECT_TIMEOUT_MS / READ_TIMEOUT_MS / MAX_RESPONSE_BYTES caps.

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

// ---- Caps (caller responsibility to enforce; exported as the single source) ----
export const CONNECT_TIMEOUT_MS = 5_000;
export const READ_TIMEOUT_MS = 15_000;
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MiB

// Ports we will ever dial. 443 always; extra via TARGET_ALLOWED_PORTS (comma list).
const DEFAULT_ALLOWED_PORTS = new Set<number>([443]);

export type AdmitOk = { ok: true; url: string; host: string; port: number; pinnedIp: string };
export type AdmitDeny = { ok: false; reason: string };
export type AdmitResult = AdmitOk | AdmitDeny;

// Resolver is injectable so tests can run without real DNS (avoids flakiness and
// lets us assert the IP-classification logic deterministically).
export type LookupAddress = { address: string; family: number };
export type ResolveFn = (hostname: string) => Promise<LookupAddress[]>;

// Default resolver: A + AAAA via node:dns/promises with {all:true}.
export const defaultResolver: ResolveFn = async (hostname) => {
  const addrs = await dnsLookup(hostname, { all: true, verbatim: true });
  return addrs.map((a) => ({ address: a.address, family: a.family }));
};

export interface AdmitOptions {
  resolve?: ResolveFn;
}

// ---------------------------------------------------------------------------
// IP classification — robust IPv4 + IPv6 range checks, no external dependency.
// ---------------------------------------------------------------------------

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

function inV4Cidr(ipInt: number, baseIp: string, bits: number): boolean {
  const base = ipv4ToInt(baseIp);
  if (base === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (base & mask);
}

// Returns a reason string if the IPv4 address is NOT publicly routable, else null.
function classifyIPv4(ip: string): string | null {
  const n = ipv4ToInt(ip);
  if (n === null) return `unparseable IPv4 ${ip}`;
  // Ranges that must never be dialed.
  const denied: Array<[string, number, string]> = [
    ["0.0.0.0", 8, "unspecified/this-network 0.0.0.0/8"],
    ["10.0.0.0", 8, "private 10/8"],
    ["100.64.0.0", 10, "CGNAT 100.64/10"],
    ["127.0.0.0", 8, "loopback 127/8"],
    ["169.254.0.0", 16, "link-local 169.254/16 (incl. metadata 169.254.169.254)"],
    ["172.16.0.0", 12, "private 172.16/12"],
    ["192.0.0.0", 24, "IETF protocol 192.0.0/24"],
    ["192.0.2.0", 24, "TEST-NET-1"],
    ["192.168.0.0", 16, "private 192.168/16"],
    ["198.18.0.0", 15, "benchmark 198.18/15"],
    ["198.51.100.0", 24, "TEST-NET-2"],
    ["203.0.113.0", 24, "TEST-NET-3"],
    ["224.0.0.0", 4, "multicast 224/4"],
    ["240.0.0.0", 4, "reserved 240/4 (incl. 255.255.255.255 broadcast)"],
  ];
  for (const [base, bits, label] of denied) {
    if (inV4Cidr(n, base, bits)) return `IPv4 ${ip} in ${label}`;
  }
  return null;
}

// Expand IPv6 to 8 16-bit groups; supports "::" compression and IPv4-mapped tails.
function expandIPv6(ip: string): number[] | null {
  let s = ip.trim();
  // Strip zone id (e.g. fe80::1%eth0).
  const pct = s.indexOf("%");
  if (pct !== -1) s = s.slice(0, pct);

  // Handle embedded IPv4 tail (e.g. ::ffff:192.168.0.1).
  let v4tail: number[] | null = null;
  const lastColon = s.lastIndexOf(":");
  const tail = lastColon === -1 ? "" : s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const n = ipv4ToInt(tail);
    if (n === null) return null;
    v4tail = [(n >>> 16) & 0xffff, n & 0xffff];
    s = s.slice(0, lastColon + 1) + "0:0"; // placeholder groups, replaced below
  }

  const dbl = s.split("::");
  if (dbl.length > 2) return null;
  const dbl0 = dbl[0] ?? "";
  const dbl1 = dbl[1] ?? "";

  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const groups: number[] = [];
    for (const g of part.split(":")) {
      if (g === "") return null;
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      groups.push(parseInt(g, 16));
    }
    return groups;
  };

  let head: number[];
  let rest: number[];
  if (dbl.length === 2) {
    const h = parseGroups(dbl0);
    const r = parseGroups(dbl1);
    if (h === null || r === null) return null;
    const fill = 8 - (h.length + r.length);
    if (fill < 0) return null;
    head = h;
    rest = [...new Array(fill).fill(0), ...r];
  } else {
    const all = parseGroups(s);
    if (all === null) return null;
    head = all;
    rest = [];
  }

  let groups = [...head, ...rest];
  if (v4tail) {
    // Replace the placeholder last two groups with the real v4 tail.
    groups = [...groups.slice(0, 6), ...v4tail];
  }
  if (groups.length !== 8) return null;
  return groups;
}

// Returns a reason string if the IPv6 address is NOT publicly routable, else null.
function classifyIPv6(ip: string): string | null {
  const g = expandIPv6(ip);
  if (g === null) return `unparseable IPv6 ${ip}`;
  // expandIPv6 guarantees exactly 8 groups; destructure to a fixed tuple so the
  // type checker (noUncheckedIndexedAccess) sees defined values.
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [
    number, number, number, number, number, number, number, number,
  ];

  const isAll = (v: number) => g.every((x) => x === v);
  // ::  unspecified
  if (isAll(0)) return "IPv6 unspecified ::";
  // ::1 loopback
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) {
    return "IPv6 loopback ::1";
  }

  // fe80::/10 link-local
  if ((g0 & 0xffc0) === 0xfe80) return "IPv6 link-local fe80::/10";
  // fc00::/7 unique-local (ULA) — covers fd00::/8
  if ((g0 & 0xfe00) === 0xfc00) return "IPv6 unique-local fc00::/7 (ULA)";
  // ff00::/8 multicast
  if ((g0 & 0xff00) === 0xff00) return "IPv6 multicast ff00::/8";

  const embeddedV4 = `${(g6 >>> 8) & 0xff}.${g6 & 0xff}.${(g7 >>> 8) & 0xff}.${g7 & 0xff}`;

  // IPv4-mapped ::ffff:0:0/96 and IPv4-compatible ::/96 — vet the embedded v4.
  const isV4Mapped = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff;
  const isV4Compat =
    g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 &&
    !(g6 === 0 && g7 === 0) && !(g6 === 0 && g7 === 1);
  if (isV4Mapped || isV4Compat) {
    const r = classifyIPv4(embeddedV4);
    return r ? `embedded ${r}` : null;
  }

  // AWS IMDSv6-style metadata endpoint fd00:ec2::254 is already covered by ULA
  // (fc00::/7) above. 64:ff9b::/96 NAT64 maps to public v4 in practice; we vet
  // the embedded v4 conservatively.
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    const r = classifyIPv4(embeddedV4);
    return r ? `embedded NAT64 ${r}` : null;
  }

  return null;
}

/**
 * Classify a literal IP address. Returns a deny reason string if the address is
 * private / loopback / link-local / CGNAT / ULA / metadata / multicast /
 * unspecified, or null if it appears publicly routable. Exported for tests.
 */
export function classifyIp(ip: string): string | null {
  const fam = isIP(ip);
  if (fam === 4) return classifyIPv4(ip);
  if (fam === 6) return classifyIPv6(ip);
  return `not an IP literal: ${ip}`;
}

// ---------------------------------------------------------------------------
// Allowlist parsing
// ---------------------------------------------------------------------------

// Parse "host:port, host2, [::1]:443" -> Set of lowercased "host" and "host:port".
function parseAllowlist(raw: string | undefined): Set<string> {
  const set = new Set<string>();
  if (!raw) return set;
  for (const entry of raw.split(",")) {
    const e = entry.trim().toLowerCase();
    if (e) set.add(e);
  }
  return set;
}

function allowlistHas(set: Set<string>, host: string, port: number): boolean {
  const h = host.toLowerCase();
  return set.has(h) || set.has(`${h}:${port}`);
}

function allowedPorts(): Set<number> {
  const extra = process.env.TARGET_ALLOWED_PORTS;
  if (!extra) return DEFAULT_ALLOWED_PORTS;
  const set = new Set<number>(DEFAULT_ALLOWED_PORTS);
  for (const p of extra.split(",")) {
    const n = Number(p.trim());
    if (Number.isInteger(n) && n > 0 && n <= 65535) set.add(n);
  }
  return set;
}

// ---------------------------------------------------------------------------
// admitTarget — the single entry point.
// ---------------------------------------------------------------------------

/**
 * Decide whether the auditor may connect to `rawUrl`. Default-DENY.
 *
 * On success returns the pinned resolved IP; the caller MUST dial that exact IP
 * while presenting the original hostname as Host header + TLS SNI, must not
 * follow redirects, and must apply the exported timeout/byte caps.
 */
export async function admitTarget(rawUrl: string, opts: AdmitOptions = {}): Promise<AdmitResult> {
  const resolve = opts.resolve ?? defaultResolver;

  // 1. Parse.
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: `unparseable URL: ${String(rawUrl)}` };
  }

  // 2. Scheme: https only.
  if (url.protocol !== "https:") {
    return { ok: false, reason: `scheme must be https (got ${url.protocol || "none"})` };
  }

  // 3. No userinfo (user:pass@host is a classic SSRF/parsing-confusion vector).
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "userinfo (user:pass@) not allowed in target URL" };
  }

  const host = url.hostname;
  if (!host) return { ok: false, reason: "empty host" };

  // 4. Port: explicit allowlist only.
  const port = url.port ? Number(url.port) : 443;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return { ok: false, reason: `invalid port ${url.port}` };
  }
  if (!allowedPorts().has(port)) {
    return { ok: false, reason: `port ${port} not in allowed set [${[...allowedPorts()].join(",")}]` };
  }

  // 5. Allowlist gate (default-deny in STRICT mode).
  const seeded = parseAllowlist(process.env.SEEDED_TARGET_ALLOWLIST);
  const external = parseAllowlist(process.env.EXTERNAL_TARGET_ALLOWLIST);
  const inSeeded = allowlistHas(seeded, host, port);
  const inExternal = allowlistHas(external, host, port);
  const strict = (process.env.TARGET_STRICT ?? "1") !== "0";
  if (!inSeeded && !inExternal && strict) {
    return {
      ok: false,
      reason: `host ${host}:${port} not in SEEDED_TARGET_ALLOWLIST or EXTERNAL_TARGET_ALLOWLIST (strict mode)`,
    };
  }

  // 6. Resolve + vet every address. If the host is itself an IP literal, vet it
  //    directly (still pin it). Otherwise resolve A/AAAA and reject if ANY
  //    address is non-routable (defeats split-horizon / multi-A tricks).
  const literalFam = isIP(host);
  let candidates: LookupAddress[];
  if (literalFam) {
    candidates = [{ address: host, family: literalFam }];
  } else {
    try {
      candidates = await resolve(host);
    } catch (e) {
      return { ok: false, reason: `DNS resolution failed for ${host}: ${(e as Error).message}` };
    }
    if (candidates.length === 0) {
      return { ok: false, reason: `no A/AAAA records for ${host}` };
    }
  }

  for (const c of candidates) {
    const bad = classifyIp(c.address);
    if (bad) {
      return { ok: false, reason: `resolved address rejected: ${bad}` };
    }
  }

  // 7. Pin the first vetted address. Caller dials this IP, sends original Host/SNI.
  const firstAddr = candidates[0];
  if (!firstAddr) return { ok: false, reason: `no usable address for ${host}` };
  return { ok: true, url: url.toString(), host, port, pinnedIp: firstAddr.address };
}
