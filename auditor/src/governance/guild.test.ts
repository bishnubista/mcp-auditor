// T10 verification for GuildGovernance.
//
// Run: cd mcp-auditor/auditor && bun run src/governance/guild.test.ts
//
// Proves, with a FAKE key + placeholder/unreachable URL, that audit():
//   1. mirrors the event to a local audit.jsonl (so the demo trail always exists),
//   2. attempts the Guild POST and fails/times out GRACEFULLY (no throw),
//   3. never rejects/throws into the demo path.
// Also proves WITHOUT a key it is local-only and does not throw.

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEntry } from "./index.ts";
import { LocalGovernance } from "./local.ts";
import { GuildGovernance } from "./guild.ts";

const entry: AuditEntry = {
  ts: new Date().toISOString(),
  agent: "prober-credential-leak",
  serverId: "target-local",
  tool: "get_config",
  safeT: "SAFE-T1502",
  payloadHash: "deadbeef0012",
  verdict: "allowed",
  reason: "ok",
};

let failures = 0;
const ok = (cond: boolean, label: string) => {
  console.log(`${cond ? "PASS" : "FAIL"} — ${label}`);
  if (!cond) failures++;
};

const tmp = mkdtempSync(join(tmpdir(), "guild-test-"));

// --- Case A: fake key + unreachable URL → mirrors locally, POST fails gracefully.
{
  const auditPath = join(tmp, "audit-withkey.jsonl");
  const local = new LocalGovernance(auditPath);
  const guild = new GuildGovernance(
    {
      apiKey: "fake-key-do-not-use",
      // RFC 5737 TEST-NET-1 — guaranteed-unroutable so the POST times out/fails.
      apiUrl: "http://192.0.2.1:9/v1",
      projectId: "hackathon-demo",
    },
    local,
  );

  let threw = false;
  try {
    guild.audit(entry); // synchronous; the POST is fire-and-forget
  } catch {
    threw = true;
  }
  ok(!threw, "audit() with fake key does NOT throw synchronously");
  ok(existsSync(auditPath), "local mirror file created");
  const line = readFileSync(auditPath, "utf8").trim();
  const parsed = JSON.parse(line) as AuditEntry;
  ok(parsed.payloadHash === entry.payloadHash, "mirrored entry matches input");
  ok(parsed.verdict === "allowed", "mirrored verdict preserved");
}

// --- Case B: no key → local-only, no throw.
{
  const auditPath = join(tmp, "audit-nokey.jsonl");
  const local = new LocalGovernance(auditPath);
  const guild = new GuildGovernance({ apiKey: undefined }, local);
  let threw = false;
  try {
    guild.audit(entry);
  } catch {
    threw = true;
  }
  ok(!threw, "audit() without key does NOT throw");
  ok(existsSync(auditPath), "no-key path still mirrors locally");
}

// Give the fire-and-forget POST time to fail/timeout, proving it never
// produces an unhandled rejection that would crash the process.
await new Promise((r) => setTimeout(r, 4000));

rmSync(tmp, { recursive: true, force: true });

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
