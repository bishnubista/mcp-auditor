#!/usr/bin/env bun
// demo:local — the top-level anti-fake-done gate AND on-stage demo entrypoint.
//
// Runs the WHOLE auditor loop deterministically against the seeded target:
//   1. Clean prior artifacts (findings/audit/report all APPEND, so stale data
//      would otherwise inflate counts and mask a broken pipeline).
//   2. Audit: orchestrator -> stdio MCP target -> 6 parallel governed probers.
//   3. Synthesize: findings.jsonl + audit.jsonl -> audit-report.md.
//   4. ASSERT every required artifact exists, is non-empty, and is well-formed.
//   5. Print a stage-friendly summary.
//   6. Exit NONZERO naming the first failed assertion; exit 0 only when clean.
//
// Nothing in this project is "done" until `bun run demo:local` exits 0.

import { spawn } from "node:child_process";
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const AUDITOR = resolve(ROOT, "auditor");
const OUT = resolve(ROOT, "out");
const FINDINGS = resolve(OUT, "findings.jsonl");
const AUDIT = resolve(OUT, "audit.jsonl");
const REPORT = resolve(OUT, "audit-report.md");
const PROBERS_DIR = resolve(AUDITOR, "src/probers");

// Expected governance coverage: the full (prober, tool, safeT) tuple set — all
// six probes, INCLUDING the get_weather / SAFE-T-CONTROL negative control.
const EXPECTED_AUDIT_TUPLES: { agent: string; tool: string; safeT: string }[] = [
  { agent: "prober-path-traversal", tool: "read_file", safeT: "SAFE-T1106" },
  { agent: "prober-credential-leakage", tool: "get_config", safeT: "SAFE-T1502" },
  { agent: "prober-description-poisoning", tool: "search_docs", safeT: "SAFE-T1102" },
  { agent: "prober-excessive-scope", tool: "run_query", safeT: "SAFE-T1104" },
  { agent: "prober-unvalidated-outbound", tool: "send_notification", safeT: "SAFE-T1402" },
  { agent: "prober-schema-control", tool: "get_weather", safeT: "SAFE-T-CONTROL" },
];

// Exact set of SAFE-T techniques that MUST appear in findings (the five seeded
// flaws). The control class (SAFE-T-CONTROL) must produce ZERO findings.
const EXPECTED_FINDING_SAFE_TS = new Set([
  "SAFE-T1102",
  "SAFE-T1104",
  "SAFE-T1106",
  "SAFE-T1402",
  "SAFE-T1502",
]);

// Target-server command can be overridden for the negative/failure test.
const TARGET_CMD =
  process.env.DEMO_TARGET_CMD ??
  `bun run ${resolve(ROOT, "target-server/src/index.ts")}`;

function fail(msg: string): never {
  console.error(`\n❌ demo:local FAILED — ${msg}`);
  process.exit(1);
}

function step(msg: string): void {
  console.error(`\n▶ ${msg}`);
}

// Run a command in auditor/, streaming stderr to the stage; reject on nonzero.
function run(cmd: string, args: string[], label: string): Promise<void> {
  return new Promise((res, rej) => {
    const child = spawn(cmd, args, {
      cwd: AUDITOR,
      stdio: ["ignore", "inherit", "inherit"],
      env: process.env,
    });
    child.on("error", (e) => rej(new Error(`${label}: ${e.message}`)));
    child.on("exit", (code) =>
      code === 0
        ? res()
        : rej(new Error(`${label}: exited with code ${code ?? "null"}`)),
    );
  });
}

// Run a command in auditor/, CAPTURING stdout (stderr still streams to stage).
// Used to exercise the Composio sponsor action and inspect its emitted payload.
function runCapture(
  cmd: string,
  args: string[],
  label: string,
): Promise<{ code: number; stdout: string }> {
  return new Promise((res, rej) => {
    const child = spawn(cmd, args, {
      cwd: AUDITOR,
      stdio: ["ignore", "pipe", "inherit"],
      env: process.env,
    });
    let stdout = "";
    child.stdout?.on("data", (d) => {
      stdout += d.toString();
    });
    child.on("error", (e) => rej(new Error(`${label}: ${e.message}`)));
    child.on("exit", (code) => res({ code: code ?? -1, stdout }));
  });
}

// #1 FUNNEL STATIC GUARD — governance integrity made enforceable, not just
// conventional. Every prober's tool invocation MUST go through executeProbe();
// no file under src/probers/** may INVOKE callTool directly — neither the dotted
// `client.callTool(...)` form NOR the bare `callTool(...)` form (the raw injected
// primitive). The ONLY legitimate appearance of `callTool` is as a bare ARGUMENT
// identifier handed INTO `executeProbe(req, callTool, policy)` — there it is
// passed, never invoked. So we flag any `callTool(` that is an invocation:
//
//   - dotted invocation:        x.callTool( ... )            -> BREACH
//   - bare invocation:          callTool(x, y)               -> BREACH
//   - legitimate handoff:       executeProbe(req, callTool, policy)  -> OK
//
// We detect the breach by removing every legitimate `callTool` ARGUMENT
// occurrence (a `callTool` token immediately preceded by `,` or `(` and followed
// by `,` or `)` — i.e. used as an argument, not called) from the line, then
// asserting NO `callTool(` invocation token survives. Comments are ignored.
function assertFunnelIntegrity(): void {
  step("Funnel static guard (probers may only reach tools via executeProbe)");
  const offenders: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (!/\.(ts|tsx|js|mjs)$/.test(entry)) continue;
      const src = readFileSync(full, "utf8");
      src.split("\n").forEach((line, i) => {
        // Strip line comments so commented examples never trip the guard.
        const code = line.replace(/\/\/.*$/, "");
        // Neutralize every LEGITIMATE bare-argument use of `callTool`: a
        // `callTool` token bounded by an argument separator/paren on BOTH sides
        // (`,` or `(` before, `,` or `)` after, whitespace tolerated) is being
        // PASSED, not called. Replace those with a placeholder so they cannot be
        // mistaken for an invocation below.
        const stripped = code.replace(
          /(^|[(,]\s*)callTool(\s*[),])/g,
          "$1__CALLTOOL_ARG__$2",
        );
        // Anything LEFT that still invokes callTool — `callTool(` dotted or bare —
        // is a funnel breach. `\bcallTool\s*\(` catches the bare invocation that
        // the old (dotted-only) guard missed.
        if (/\bcallTool\s*\(/.test(stripped)) {
          offenders.push(`${full}:${i + 1}: ${line.trim()}`);
        }
      });
    }
  };
  walk(PROBERS_DIR);
  if (offenders.length > 0) {
    fail(
      "FUNNEL BREACH — probers invoke a tool directly instead of via executeProbe():\n  " +
        offenders.join("\n  "),
    );
  }
  console.error(
    "  OK — no direct callTool( invocation in src/probers/**; callTool only appears as the executeProbe() argument.",
  );
}

function readNonEmpty(path: string, label: string): string {
  if (!existsSync(path)) fail(`${label} missing — expected ${path}`);
  const body = readFileSync(path, "utf8").trim();
  if (body.length === 0) fail(`${label} is empty — ${path}`);
  return body;
}

async function main(): Promise<void> {
  console.error("=== MCP Server Auditor — demo:local ===");

  // 0. Funnel static guard — fail BEFORE running anything if a prober bypasses
  //    the governance funnel (governance integrity is enforced, not assumed).
  assertFunnelIntegrity();

  // 1. Clean prior artifacts (these files are append-only at the source).
  step("Cleaning prior artifacts");
  const PAYLOAD = resolve(OUT, "composio-payload.json");
  for (const p of [FINDINGS, AUDIT, REPORT, PAYLOAD]) {
    if (existsSync(p)) rmSync(p);
  }

  // 2. Full governed audit run (probers fan out — stderr streams to stage).
  step("Running governed audit (orchestrator -> 6 parallel probers)");
  const [tcmd, ...targs] = TARGET_CMD.split(/\s+/);
  if (!tcmd) fail("DEMO_TARGET_CMD is empty");
  await run(
    "bun",
    ["run", "src/orchestrator.ts", "--", tcmd, ...targs],
    "orchestrator",
  ).catch((e) => fail((e as Error).message));

  // 3. Synthesize the cited report.
  step("Synthesizing cited SAFE-T audit report");
  await run("bun", ["run", "src/synthesizer.ts"], "synthesizer").catch((e) =>
    fail((e as Error).message),
  );

  // 4. Assert artifacts exist, are non-empty, and well-formed.
  step("Asserting artifacts");
  const findingsBody = readNonEmpty(FINDINGS, "findings.jsonl");
  const auditBody = readNonEmpty(AUDIT, "audit.jsonl");
  const reportBody = readNonEmpty(REPORT, "audit-report.md");

  if (!reportBody.includes("SAFE-T"))
    fail('audit-report.md missing "SAFE-T" classification keys');
  if (!reportBody.includes("Overall Risk"))
    fail('audit-report.md missing an "Overall Risk" line');

  // Parse findings (frozen shape: ts, safeT, tool, severity, probe, evidence, prober).
  interface FindingRow {
    safeT?: string;
    tool?: string;
    severity?: string;
    prober?: string;
  }
  const findings = findingsBody
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as FindingRow);

  // Parse audit entries (verdict trail).
  interface AuditRow {
    agent?: string;
    tool?: string;
    safeT?: string;
    verdict?: string;
  }
  const auditEntries = auditBody
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as AuditRow);

  // ── #5 EXACT SAFE-T ASSERTION ──────────────────────────────────────────────
  // Findings' SAFE-T set must EXACTLY equal the five seeded techniques, and there
  // must be ZERO SAFE-T-CONTROL findings (the clean tool's negative control).
  const findingSafeTs = new Set(findings.map((f) => f.safeT));
  const controlFindings = findings.filter(
    (f) => f.safeT === "SAFE-T-CONTROL" || f.tool === "get_weather",
  ).length;
  if (controlFindings !== 0)
    fail(
      `negative control breached — ${controlFindings} SAFE-T-CONTROL/get_weather finding(s), expected 0`,
    );
  const missingSafeTs = [...EXPECTED_FINDING_SAFE_TS].filter((s) => !findingSafeTs.has(s));
  const extraSafeTs = [...findingSafeTs].filter((s) => s && !EXPECTED_FINDING_SAFE_TS.has(s));
  if (missingSafeTs.length > 0)
    fail(`findings missing expected SAFE-T technique(s): ${missingSafeTs.join(", ")}`);
  if (extraSafeTs.length > 0)
    fail(`findings contain unexpected SAFE-T technique(s): ${extraSafeTs.join(", ")}`);

  // ── #6 EXACT AUDIT-TUPLE PROOF (governance coverage) ───────────────────────
  // EXACTLY 6 audit entries, ALL verdict=allowed, matching the expected
  // (prober, tool, safeT) tuple set INCLUDING get_weather/SAFE-T-CONTROL.
  if (auditEntries.length !== EXPECTED_AUDIT_TUPLES.length)
    fail(
      `audit.jsonl has ${auditEntries.length} entr(ies), expected EXACTLY ${EXPECTED_AUDIT_TUPLES.length}`,
    );
  const notAllowed = auditEntries.filter((a) => a.verdict !== "allowed");
  if (notAllowed.length > 0)
    fail(
      `audit.jsonl has ${notAllowed.length} non-allowed verdict(s); expected every probe allowed. ` +
        `First: ${JSON.stringify(notAllowed[0])}`,
    );
  const tupleKey = (a: { agent?: string; tool?: string; safeT?: string }) =>
    `${a.agent}::${a.tool}::${a.safeT}`;
  const auditTupleSet = new Set(auditEntries.map(tupleKey));
  for (const exp of EXPECTED_AUDIT_TUPLES) {
    if (!auditTupleSet.has(tupleKey(exp)))
      fail(`audit.jsonl missing expected governance tuple: ${tupleKey(exp)}`);
  }
  // No unexpected tuples (set sizes already match counts, but be explicit).
  const expectedTupleSet = new Set(EXPECTED_AUDIT_TUPLES.map(tupleKey));
  for (const a of auditEntries) {
    if (!expectedTupleSet.has(tupleKey(a)))
      fail(`audit.jsonl has an unexpected governance tuple: ${tupleKey(a)}`);
  }

  // Every finding row MUST have a matching ALLOWED audit entry (tool + safeT).
  // This is the coverage proof: no finding was produced without a governed probe.
  const allowedToolSafeT = new Set(
    auditEntries.filter((a) => a.verdict === "allowed").map((a) => `${a.tool}::${a.safeT}`),
  );
  for (const f of findings) {
    const k = `${f.tool}::${f.safeT}`;
    if (!allowedToolSafeT.has(k))
      fail(`finding has NO matching allowed audit entry (governance bypass?): ${k}`);
  }

  // ── #7 EXERCISE COMPOSIO IN GATE (mandatory sponsor action) ────────────────
  // Run the Composio action in --dry-run so the gate validates the tool-call path
  // WITHOUT filing a live GitHub issue (repeated gate runs must not spam real
  // issues even when a real COMPOSIO_API_KEY is present). Live filing is the
  // separate explicit `bun run file-report`. Assert stdout is the 'COMPOSIO
  // TOOL-CALL' payload block (or, if someone runs it live, a GitHub issue URL).
  step("Exercising Composio sponsor action (file-report, --dry-run)");
  const composio = await runCapture(
    "bun",
    ["run", "src/actions/composio.ts", "--dry-run"],
    "composio",
  ).catch((e) => fail((e as Error).message));
  const out = composio.stdout;
  const isIssueUrl = /https?:\/\/github\.com\/[^\s/]+\/[^\s/]+\/issues(\/\d+)?/.test(out);
  const isDegradedBlock = out.includes("COMPOSIO TOOL-CALL");
  if (!isIssueUrl && !isDegradedBlock)
    fail(
      `Composio action produced neither a GitHub issue URL nor a degraded 'COMPOSIO TOOL-CALL' block ` +
        `(exit=${composio.code}). stdout head: ${out.slice(0, 200)}`,
    );
  const composioMode = isIssueUrl ? `LIVE (issue URL)` : `DRY-RUN (tool-call payload validated)`;
  // In degraded mode, the full payload artifact should also exist (#8).
  const PAYLOAD_ARTIFACT = resolve(OUT, "composio-payload.json");
  if (isDegradedBlock && !existsSync(PAYLOAD_ARTIFACT))
    fail(`degraded Composio path did not write the full payload artifact at ${PAYLOAD_ARTIFACT}`);

  // 5. Stage-friendly summary.
  const bySeverity = new Map<string, number>();
  const safeTClasses = new Set<string>();
  for (const f of findings) {
    bySeverity.set(f.severity ?? "unknown", (bySeverity.get(f.severity ?? "unknown") ?? 0) + 1);
    if (f.safeT) safeTClasses.add(f.safeT);
  }
  const sevOrder = ["critical", "high", "medium", "low"];
  const sevStr = sevOrder
    .filter((s) => bySeverity.has(s))
    .map((s) => `${s}=${bySeverity.get(s)}`)
    .join(", ");

  console.error("\n=== AUDIT SUMMARY ===");
  console.error(`Findings:        ${findings.length} (${sevStr})`);
  console.error(
    `SAFE-T set:      EXACT match [${[...safeTClasses].sort().join(", ")}] (control: 0 findings)`,
  );
  console.error(
    `Governed probes: ${auditEntries.length} audit entries — EXACTLY ${EXPECTED_AUDIT_TUPLES.length}, all allowed, tuples verified`,
  );
  console.error(`Funnel guard:    PASS — probers reach tools only via executeProbe()`);
  console.error(`Composio:        ${composioMode}`);
  console.error("Clean control:   get_weather findings=0 (negative control holds)");
  console.error(`Report:          ${REPORT}`);
  console.error("\n✅ demo:local PASSED — full governed audit loop is green.");
  process.exit(0);
}

main().catch((e) => fail((e as Error).message ?? String(e)));
