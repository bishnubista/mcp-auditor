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
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const AUDITOR = resolve(ROOT, "auditor");
const OUT = resolve(ROOT, "out");
const FINDINGS = resolve(OUT, "findings.jsonl");
const AUDIT = resolve(OUT, "audit.jsonl");
const REPORT = resolve(OUT, "audit-report.md");

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

function readNonEmpty(path: string, label: string): string {
  if (!existsSync(path)) fail(`${label} missing — expected ${path}`);
  const body = readFileSync(path, "utf8").trim();
  if (body.length === 0) fail(`${label} is empty — ${path}`);
  return body;
}

function lineCount(body: string): number {
  return body.split("\n").filter((l) => l.trim().length > 0).length;
}

async function main(): Promise<void> {
  console.error("=== MCP Server Auditor — demo:local ===");

  // 1. Clean prior artifacts (these files are append-only at the source).
  step("Cleaning prior artifacts");
  for (const p of [FINDINGS, AUDIT, REPORT]) {
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

  const findingLines = lineCount(findingsBody);
  if (findingLines < 4)
    fail(`findings.jsonl has ${findingLines} line(s), expected >= 4`);

  const auditLines = lineCount(auditBody);
  if (auditLines < 5)
    fail(`audit.jsonl has ${auditLines} line(s), expected >= 5`);

  if (!reportBody.includes("SAFE-T"))
    fail('audit-report.md missing "SAFE-T" classification keys');
  if (!reportBody.includes("Overall Risk"))
    fail('audit-report.md missing an "Overall Risk" line');

  // Negative control: the clean tool must produce ZERO findings.
  const weatherFindings = findingsBody
    .split("\n")
    .filter((l) => l.includes('"tool":"get_weather"')).length;
  if (weatherFindings !== 0)
    fail(
      `get_weather (clean control) produced ${weatherFindings} finding(s), expected 0`,
    );

  // 5. Stage-friendly summary.
  const findings = findingsBody
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as { severity?: string; safeT?: string });

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
  console.error(`SAFE-T classes:  ${safeTClasses.size} [${[...safeTClasses].sort().join(", ")}]`);
  console.error(`Governed probes: ${auditLines} (audit.jsonl lines — every probe gated)`);
  console.error("Clean control:   get_weather findings=0 (negative control holds)");
  console.error(`Report:          ${REPORT}`);
  console.error("\n✅ demo:local PASSED — full governed audit loop is green.");
  process.exit(0);
}

main().catch((e) => fail((e as Error).message ?? String(e)));
