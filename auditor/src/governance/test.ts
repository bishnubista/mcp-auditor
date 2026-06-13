// Acceptance test for the governance probeExecutor. Run: `bun run src/governance/test.ts`
// from mcp-auditor/auditor/. Proves:
//   (a) allowlisted probe executes and audits with verdict "allowed"
//   (b) non-allowlisted server is denied, callTool NOT called, denial audited
//   (c) probe #(cap+1) on the same tool is denied with reason "rate-cap"
//   (d) audit.jsonl lines parse as JSON with all required fields

import { readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { executeProbe } from "./index.ts";
import type { ProbePolicy, AuditEntry } from "./index.ts";
import { LocalGovernance } from "./local.ts";

const AUDIT_PATH = resolve(import.meta.dir, "../../../out/audit.test.jsonl");
rmSync(AUDIT_PATH, { force: true });

const backend = new LocalGovernance(AUDIT_PATH);

let callToolInvocations = 0;
const fakeCallTool = async (tool: string, _args: unknown): Promise<unknown> => {
  callToolInvocations++;
  return { ok: true, tool };
};

const policy: ProbePolicy = {
  allowedServers: ["seeded-target"],
  allowedTools: ["read_file", "exec"],
  maxProbesPerTool: 3,
  // Counters live on the policy (per-run scoping); a fresh Map here IS the
  // reset that the old module-level __resetProbeCounts() used to provide.
  counters: new Map(),
};

const results: { name: string; pass: boolean; detail: string }[] = [];
const check = (name: string, pass: boolean, detail: string) =>
  results.push({ name, pass, detail });

// (a) allowlisted probe executes and audits allowed
{
  const before = callToolInvocations;
  const r = await executeProbe(
    { agent: "prober-cred-leak", serverId: "seeded-target", tool: "read_file", safeT: "SAFE-T1001", payload: { path: "/etc/passwd" } },
    fakeCallTool,
    policy,
    backend,
  );
  check("(a) allowlisted -> allowed", r.verdict === "allowed", `verdict=${r.verdict}`);
  check("(a) callTool invoked", callToolInvocations === before + 1, `invocations delta=${callToolInvocations - before}`);
}

// (b) non-allowlisted server denied, callTool NOT called
{
  const before = callToolInvocations;
  const r = await executeProbe(
    { agent: "prober-scope", serverId: "evil-server", tool: "read_file", safeT: "SAFE-T1100", payload: { x: 1 } },
    fakeCallTool,
    policy,
    backend,
  );
  check("(b) bad server -> denied", r.verdict === "denied", `verdict=${r.verdict} reason=${(r as { reason?: string }).reason}`);
  check("(b) callTool NOT invoked", callToolInvocations === before, `invocations delta=${callToolInvocations - before}`);
}

// (c) probe #(cap+1) on same tool -> rate-cap. cap=3; (a) already used 1, so 2 more allowed then deny.
{
  // exec used 0 so far; fire cap probes (all allowed) then one more (denied).
  let lastVerdict = "";
  let lastReason = "";
  for (let i = 0; i < policy.maxProbesPerTool + 1; i++) {
    const r = await executeProbe(
      { agent: "prober-inject", serverId: "seeded-target", tool: "exec", safeT: "SAFE-T1200", payload: { i } },
      fakeCallTool,
      policy,
      backend,
    );
    lastVerdict = r.verdict;
    lastReason = (r as { reason?: string }).reason ?? "";
  }
  check("(c) cap+1 -> denied", lastVerdict === "denied", `verdict=${lastVerdict}`);
  check("(c) reason rate-cap", lastReason === "rate-cap", `reason=${lastReason}`);
}

// (d) audit.jsonl lines parse with all required fields
{
  const required = ["ts", "agent", "serverId", "tool", "safeT", "payloadHash", "verdict", "reason"];
  const lines = readFileSync(AUDIT_PATH, "utf8").trim().split("\n").filter(Boolean);
  let allValid = lines.length > 0;
  let badLine = "";
  for (const line of lines) {
    let obj: AuditEntry;
    try {
      obj = JSON.parse(line) as AuditEntry;
    } catch {
      allValid = false;
      badLine = `unparseable: ${line}`;
      break;
    }
    const missing = required.filter((f) => !(f in obj));
    const hashOk = typeof obj.payloadHash === "string" && /^[0-9a-f]{12}$/.test(obj.payloadHash);
    if (missing.length || !hashOk) {
      allValid = false;
      badLine = `missing=[${missing.join(",")}] hashOk=${hashOk} line=${line}`;
      break;
    }
  }
  check("(d) audit lines valid JSON + fields", allValid, badLine || `${lines.length} lines all valid`);
  // expected entries: 1 (a) + 1 (b denied) + 4 (c: 3 allowed + 1 denied) = 6
  check("(d) expected entry count", lines.length === 6, `lines=${lines.length} (expected 6)`);
}

console.log("\n=== Governance probeExecutor acceptance ===");
let allPass = true;
for (const r of results) {
  const mark = r.pass ? "PASS" : "FAIL";
  if (!r.pass) allPass = false;
  console.log(`  [${mark}] ${r.name} — ${r.detail}`);
}
console.log(`\nAudit log: ${AUDIT_PATH}`);
console.log(allPass ? "\nALL CHECKS PASSED" : "\nSOME CHECKS FAILED");
rmSync(AUDIT_PATH, { force: true }); // clean up test artifact
process.exit(allPass ? 0 : 1);
