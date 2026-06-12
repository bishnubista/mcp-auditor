// Unit tests for the SSRF admission gate. Resolver is stubbed so we assert the
// classification + allowlist logic deterministically with no real DNS.
//
// Run: bun test src/net/admit.test.ts   (from mcp-auditor/auditor)

import { test, expect, beforeEach } from "bun:test";
import { admitTarget, classifyIp, type ResolveFn } from "./admit.js";

// Map hostnames -> resolved addresses for the stub resolver.
const DNS: Record<string, Array<{ address: string; family: number }>> = {
  "public.example.com": [{ address: "93.184.216.34", family: 4 }],
  "rebind.evil.com": [{ address: "10.0.0.5", family: 4 }],
  "internal.corp": [{ address: "192.168.1.10", family: 4 }],
  "v6loop.evil.com": [{ address: "::1", family: 6 }],
  "ula.evil.com": [{ address: "fd00::1234", family: 6 }],
  // A host whose A is public but AAAA is private -> must be rejected (any-bad rule).
  "mixed.evil.com": [
    { address: "93.184.216.34", family: 4 },
    { address: "fd00::dead", family: 6 },
  ],
};

const stubResolve: ResolveFn = async (host) => {
  const r = DNS[host];
  if (!r) throw new Error(`NXDOMAIN ${host}`);
  return r;
};

beforeEach(() => {
  // Allowlist all the hosts we exercise so the test isolates the IP-vetting
  // logic from the allowlist gate. The accept case lives in EXTERNAL list.
  process.env.SEEDED_TARGET_ALLOWLIST = "";
  process.env.EXTERNAL_TARGET_ALLOWLIST =
    "public.example.com,rebind.evil.com,internal.corp,v6loop.evil.com,ula.evil.com,mixed.evil.com,169.254.169.254,127.0.0.1,localhost,[::1]";
  process.env.TARGET_STRICT = "1";
});

// ---- classifyIp unit coverage ----
test("classifyIp flags private/loopback/link-local/metadata/CGNAT/ULA/v6loop", () => {
  expect(classifyIp("10.0.0.1")).toBeTruthy();
  expect(classifyIp("192.168.1.1")).toBeTruthy();
  expect(classifyIp("172.16.5.5")).toBeTruthy();
  expect(classifyIp("127.0.0.1")).toBeTruthy();
  expect(classifyIp("169.254.169.254")).toBeTruthy(); // cloud metadata
  expect(classifyIp("100.64.0.1")).toBeTruthy(); // CGNAT
  expect(classifyIp("0.0.0.0")).toBeTruthy();
  expect(classifyIp("224.0.0.1")).toBeTruthy(); // multicast
  expect(classifyIp("::1")).toBeTruthy(); // v6 loopback
  expect(classifyIp("fd00::1")).toBeTruthy(); // ULA
  expect(classifyIp("fe80::1")).toBeTruthy(); // link-local
  expect(classifyIp("::ffff:10.0.0.1")).toBeTruthy(); // v4-mapped private
  // Public addresses pass.
  expect(classifyIp("93.184.216.34")).toBeNull();
  expect(classifyIp("2606:2800:220:1:248:1893:25c8:1946")).toBeNull();
});

// ---- REJECT cases ----
test("rejects http:// (not https)", async () => {
  const r = await admitTarget("http://public.example.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects http(s)://localhost", async () => {
  const r = await admitTarget("https://localhost/mcp", { resolve: stubResolve });
  // localhost resolves to loopback; even though allowlisted, IP vetting denies.
  // Our stub has no "localhost" entry -> resolution fails -> denied either way.
  expect(r.ok).toBe(false);
});

test("rejects https://127.0.0.1 (loopback literal)", async () => {
  const r = await admitTarget("https://127.0.0.1/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects https://169.254.169.254 (metadata literal)", async () => {
  const r = await admitTarget("https://169.254.169.254/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects host resolving to 10.x", async () => {
  const r = await admitTarget("https://rebind.evil.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects host resolving to 192.168.x", async () => {
  const r = await admitTarget("https://internal.corp/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects host resolving to ::1", async () => {
  const r = await admitTarget("https://v6loop.evil.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects host resolving to fd00:: (ULA)", async () => {
  const r = await admitTarget("https://ula.evil.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects host with a mixed public-A + private-AAAA (any-bad rule)", async () => {
  const r = await admitTarget("https://mixed.evil.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects userinfo in URL", async () => {
  const r = await admitTarget("https://user:pass@public.example.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects non-allowlisted host in strict mode", async () => {
  process.env.EXTERNAL_TARGET_ALLOWLIST = ""; // empty
  process.env.SEEDED_TARGET_ALLOWLIST = "";
  const r = await admitTarget("https://public.example.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

test("rejects disallowed port", async () => {
  const r = await admitTarget("https://public.example.com:8443/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(false);
});

// ---- ACCEPT case ----
test("accepts allowlisted public https host and pins the resolved IP", async () => {
  const r = await admitTarget("https://public.example.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.pinnedIp).toBe("93.184.216.34");
    expect(r.host).toBe("public.example.com");
    expect(r.port).toBe(443);
  }
});

test("accepts via SEEDED allowlist too", async () => {
  process.env.EXTERNAL_TARGET_ALLOWLIST = "";
  process.env.SEEDED_TARGET_ALLOWLIST = "public.example.com";
  const r = await admitTarget("https://public.example.com/mcp", { resolve: stubResolve });
  expect(r.ok).toBe(true);
});
