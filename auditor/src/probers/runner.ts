// runner.ts — the multi-agent prober fan-out.
//
// Six specialist SAFE-T probers run CONCURRENTLY (Promise.all). Each builds a
// probe job from the static catalog (payloads.ts) and invokes its target tool
// EXCLUSIVELY through the governance funnel (executeProbe) — there is no other
// tool-call path, so the audit trail shows one entry per probe (graded).
//
// Findings are appended to ../out/findings.jsonl in the FROZEN shape:
//   { ts, safeT, tool, severity, probe, evidence, prober }
//
// Per-prober start/result is logged to stderr for the live demo.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { resultText, type ToolInfo, type ToolCallResult } from "../mcp-client.ts";
import {
  executeProbe,
  type CallToolFn,
  type ProbePolicy,
  type ProbeRequest,
  type Verdict,
} from "../governance/index.ts";
import { PROBE_CLASSES, type ProbeClass, type ProbeContext } from "./payloads.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
// findings.jsonl lives at mcp-auditor/out/ (sibling of auditor/), matching the
// orchestrator/governance convention.
const OUT_DIR = resolve(__dirname, "../../../out");
const FINDINGS_PATH = resolve(OUT_DIR, "findings.jsonl");

// The frozen finding record (shared contract with the synthesizer T5).
export interface Finding {
  ts: string;
  safeT: string;
  tool: string;
  severity: string;
  probe: string;
  evidence: string;
  prober: string;
}

export interface ProberResult {
  prober: string;
  safeT: string;
  tool: string;
  isFinding: boolean;
  verdict: Verdict["verdict"];
  finding?: Finding;
}

function descriptionFor(tools: ToolInfo[], name: string): string {
  return tools.find((t) => t.name === name)?.description ?? "";
}

// Write ALL findings to findings.jsonl in ONE deterministic pass (OVERWRITE, not
// append). The caller sorts findings by PROBE_CLASSES declaration order first, so
// the on-disk order is stable across runs regardless of prober finish order.
async function writeFindings(findings: Finding[]): Promise<void> {
  await mkdir(OUT_DIR, { recursive: true });
  const body = findings.map((f) => JSON.stringify(f)).join("\n");
  await writeFile(FINDINGS_PATH, findings.length ? `${body}\n` : "", "utf8");
}

/**
 * Run ONE specialist prober: governed tool call → detector → optional finding.
 *
 * FUNNEL INVARIANT: every tool invocation in this prober goes through
 * executeProbe (the single governance funnel); this function NEVER touches
 * `client.callTool` / the raw transport directly. It only ever hands the
 * injected `callTool` primitive INTO executeProbe. (Enforced statically by the
 * funnel guard in scripts/demo-local.ts.)
 *
 * Returns a structured result carrying the finding (if any). It does NOT write
 * to disk — the caller collects, sorts, and writes findings.jsonl ONCE so the
 * output order is deterministic.
 */
async function runOneProber(
  cls: ProbeClass,
  tools: ToolInfo[],
  callTool: CallToolFn,
  policy: ProbePolicy,
): Promise<ProberResult> {
  console.error(`[${cls.prober}] START — ${cls.safeT} → ${cls.tool}`);

  const req: ProbeRequest = {
    agent: cls.prober,
    serverId: policy.allowedServers[0] as string,
    tool: cls.tool,
    safeT: cls.safeT,
    payload: cls.payload,
  };

  // THE ONLY permitted tool-call path — governance gate + audit on every probe.
  const verdict = await executeProbe(req, callTool, policy);

  if (verdict.verdict === "denied") {
    console.error(`[${cls.prober}] DENIED by governance: ${verdict.reason}`);
    return {
      prober: cls.prober,
      safeT: cls.safeT,
      tool: cls.tool,
      isFinding: false,
      verdict: "denied",
    };
  }

  const responseText = resultText(verdict.result as ToolCallResult);
  const ctx: ProbeContext = {
    responseText,
    toolDescription: descriptionFor(tools, cls.tool),
  };
  const hit = cls.detect(ctx);

  if (!hit) {
    console.error(`[${cls.prober}] no finding (clean) — ${cls.tool}`);
    return {
      prober: cls.prober,
      safeT: cls.safeT,
      tool: cls.tool,
      isFinding: false,
      verdict: "allowed",
    };
  }

  const finding: Finding = {
    ts: new Date().toISOString(),
    safeT: cls.safeT,
    tool: cls.tool,
    severity: hit.severity,
    probe: cls.probe,
    evidence: hit.evidence,
    prober: cls.prober,
  };
  console.error(
    `[${cls.prober}] FINDING (${hit.severity}) ${cls.safeT} ${cls.tool} :: ${cls.probe}`,
  );
  return {
    prober: cls.prober,
    safeT: cls.safeT,
    tool: cls.tool,
    isFinding: true,
    verdict: "allowed",
    finding,
  };
}

/**
 * Fan out ALL six SAFE-T probers in parallel against the enumerated tools.
 *
 * Only probes classes whose target tool actually exists on the surface. The
 * governance `policy` is scoped to exactly the probed tools on the target
 * server; anything outside it is denied AND audited by executeProbe.
 *
 * @param tools    enumerated tool surface (carries descriptions for metadata probes)
 * @param callTool the single transport primitive governance is allowed to invoke
 * @param policy   governance allowlist + rate cap (serverId + probed tools)
 */
// #2 NON-TAUTOLOGICAL CATALOG GUARD — the expected SAFE-T probe catalog is six
// classes (five seeded flaws + the get_weather negative control). Asserting
// `results.length === PROBE_CLASSES.length` is a tautology (we map over exactly
// that array), so it can NEVER catch a silently reduced catalog. Instead pin the
// catalog to its expected SHAPE: exactly EXPECTED_PROBE_COUNT classes, with
// unique prober ids AND unique target tools. If someone trims payloads.ts, this
// fails loudly BEFORE any probing rather than producing a green partial audit.
const EXPECTED_PROBE_COUNT = 6;

function assertCatalogIntegrity(): void {
  if (PROBE_CLASSES.length !== EXPECTED_PROBE_COUNT) {
    throw new Error(
      `[runner] SAFE-T probe catalog was reduced: expected EXACTLY ${EXPECTED_PROBE_COUNT} ` +
        `probe classes (5 seeded flaws + 1 negative control), found ${PROBE_CLASSES.length}. ` +
        `Refusing to run a partial audit that would look green.`,
    );
  }
  const proberIds = PROBE_CLASSES.map((c) => c.prober);
  const uniqueProbers = new Set(proberIds);
  if (uniqueProbers.size !== EXPECTED_PROBE_COUNT) {
    throw new Error(
      `[runner] prober ids are not unique: ${proberIds.join(", ")} ` +
        `(${uniqueProbers.size} distinct of ${EXPECTED_PROBE_COUNT}).`,
    );
  }
  const probedTools = PROBE_CLASSES.map((c) => c.tool);
  const uniqueTools = new Set(probedTools);
  if (uniqueTools.size !== EXPECTED_PROBE_COUNT) {
    throw new Error(
      `[runner] probed tool set is not the expected size: ${probedTools.join(", ")} ` +
        `(${uniqueTools.size} distinct of ${EXPECTED_PROBE_COUNT}).`,
    );
  }
}

export async function runProbers(
  tools: ToolInfo[],
  callTool: CallToolFn,
  policy: ProbePolicy,
): Promise<ProberResult[]> {
  // #2 Assert the catalog is intact BEFORE running (non-tautological).
  assertCatalogIntegrity();

  const toolNames = new Set(tools.map((t) => t.name));

  // #4 NO SILENT TOOL SKIP — every PROBE_CLASSES tool (all 6, incl. get_weather)
  // MUST be present on the target surface. A missing tool would silently drop a
  // prober: the negative control could "pass" without ever probing get_weather,
  // and a partial surface would look green. Fail LOUDLY instead.
  const missing = PROBE_CLASSES.filter((c) => !toolNames.has(c.tool));
  if (missing.length > 0) {
    throw new Error(
      `[runner] target surface is missing ${missing.length} expected tool(s): ` +
        missing.map((c) => `${c.tool} (${c.prober}/${c.safeT})`).join(", ") +
        `. Every SAFE-T probe class must have its tool present — refusing to run a ` +
        `partial audit that would look green.`,
    );
  }

  console.error(
    `[runner] fanning out ${PROBE_CLASSES.length} probers in parallel: ` +
      PROBE_CLASSES.map((c) => c.prober).join(", "),
  );

  // The "multi-agent" moment: all specialists probe concurrently. Each probe goes
  // EXCLUSIVELY through the governance funnel (executeProbe inside runOneProber).
  const results = await Promise.all(
    PROBE_CLASSES.map((c) => runOneProber(c, tools, callTool, policy)),
  );

  // #2 Post-run catalog proof (non-tautological): EXACTLY EXPECTED_PROBE_COUNT
  // results, each carrying a DISTINCT prober id and a DISTINCT probed tool — i.e.
  // every declared class actually ran exactly once. (`results.length ===
  // PROBE_CLASSES.length` alone is a tautology; pinning to the fixed expected
  // count + uniqueness is not.)
  if (results.length !== EXPECTED_PROBE_COUNT) {
    throw new Error(
      `[runner] expected EXACTLY ${EXPECTED_PROBE_COUNT} probers to run, got ${results.length}`,
    );
  }
  const ranProbers = new Set(results.map((r) => r.prober));
  const ranTools = new Set(results.map((r) => r.tool));
  if (ranProbers.size !== EXPECTED_PROBE_COUNT || ranTools.size !== EXPECTED_PROBE_COUNT) {
    throw new Error(
      `[runner] prober/tool coverage incomplete after run: ` +
        `${ranProbers.size} distinct probers, ${ranTools.size} distinct tools ` +
        `(expected ${EXPECTED_PROBE_COUNT} each).`,
    );
  }

  // #3 DETERMINISTIC FINDINGS ORDER — collect findings, SORT by the PROBE_CLASSES
  // declaration order, then write findings.jsonl ONCE (overwrite). Prober finish
  // order is concurrency-dependent; this makes the on-disk artifact stable.
  const classOrder = new Map(PROBE_CLASSES.map((c, i) => [c.prober, i]));
  const findingsOut = results
    .filter((r) => r.isFinding && r.finding)
    .map((r) => r.finding as Finding)
    .sort(
      (a, b) =>
        (classOrder.get(a.prober) ?? Number.MAX_SAFE_INTEGER) -
        (classOrder.get(b.prober) ?? Number.MAX_SAFE_INTEGER),
    );
  await writeFindings(findingsOut);

  const safeTs = new Set(findingsOut.map((f) => f.safeT));
  const weatherFindings = findingsOut.filter((f) => f.tool === "get_weather").length;
  console.error(
    `[runner] DONE — ${findingsOut.length} finding(s) across ${safeTs.size} SAFE-T class(es); ` +
      `get_weather findings=${weatherFindings} (expected 0); findings.jsonl written deterministically.`,
  );

  return results;
}

// Build a governance policy scoped to exactly the tools the probers will touch
// on the given server. Helper so the orchestrator stays a one-liner.
export function buildPolicy(serverId: string, tools: ToolInfo[]): ProbePolicy {
  const toolNames = new Set(tools.map((t) => t.name));
  const probedTools = [
    ...new Set(
      PROBE_CLASSES.filter((c) => toolNames.has(c.tool)).map((c) => c.tool),
    ),
  ];
  return {
    allowedServers: [serverId],
    allowedTools: probedTools,
    maxProbesPerTool: 10,
  };
}

export { FINDINGS_PATH };
