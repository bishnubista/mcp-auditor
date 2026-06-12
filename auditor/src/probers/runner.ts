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

// ── UI1 streaming hook (ADDITIVE) ──────────────────────────────────────────
// runProbers can OPTIONALLY emit per-agent lifecycle events for the live SSE
// stream (PLAN-UI.md §5). The runner emits RAW typed events; the SSE server
// (audit-stream-server.ts) stamps auditId/runId/seq/id/ts and wraps them into
// the wire envelope. Keeping the runner ignorant of seq/id keeps the demo:local
// path byte-identical when onEvent is absent (the gate must stay green).
//
// Emitted types (terminal per-agent state is agent.done OR agent.error):
//   agent.start   { agentId, safeT, tool }
//   agent.gate    { agentId, verdict:"allowed" }   (only emitted when allowed)
//   agent.finding { agentId, safeT, tool, severity, evidenceExcerpt }
//   agent.clean   { agentId, tool }                (negative control / no finding)
//   agent.done    { agentId, ms }                  (terminal)
//   agent.error   { agentId, message }             (terminal)
export type RunnerAgentEvent =
  | { type: "agent.start"; agentId: string; safeT: string; tool: string }
  | { type: "agent.gate"; agentId: string; verdict: "allowed" | "denied" }
  | {
      type: "agent.finding";
      agentId: string;
      safeT: string;
      tool: string;
      severity: string;
      evidenceExcerpt: string;
    }
  | { type: "agent.clean"; agentId: string; tool: string }
  | { type: "agent.done"; agentId: string; ms: number }
  | { type: "agent.error"; agentId: string; message: string };

export type RunnerOnEvent = (e: RunnerAgentEvent) => void;

// No-op emitter so the hot path never branches on undefined and behavior is
// IDENTICAL to the pre-streaming runner when no consumer is attached.
const noopEmit: RunnerOnEvent = () => {};

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
  emit: RunnerOnEvent,
): Promise<ProberResult> {
  console.error(`[${cls.prober}] START — ${cls.safeT} → ${cls.tool}`);
  // Logical per-agent duration. Date.now() is fine in the Bun runtime; if it is
  // ever restricted this still degrades to ms:0 without throwing.
  const startedAt = (() => {
    try {
      return Date.now();
    } catch {
      return 0;
    }
  })();
  const elapsed = (): number => {
    try {
      return Math.max(0, Date.now() - startedAt);
    } catch {
      return 0;
    }
  };

  emit({ type: "agent.start", agentId: cls.prober, safeT: cls.safeT, tool: cls.tool });

  const req: ProbeRequest = {
    agent: cls.prober,
    serverId: policy.allowedServers[0] as string,
    tool: cls.tool,
    safeT: cls.safeT,
    payload: cls.payload,
  };

  try {
    // THE ONLY permitted tool-call path — governance gate + audit on every probe.
    const verdict = await executeProbe(req, callTool, policy);

    if (verdict.verdict === "denied") {
      console.error(`[${cls.prober}] DENIED by governance: ${verdict.reason}`);
      emit({ type: "agent.gate", agentId: cls.prober, verdict: "denied" });
      // A denied probe is a terminal per-agent state too (no finding possible).
      emit({ type: "agent.error", agentId: cls.prober, message: `denied: ${verdict.reason}` });
      return {
        prober: cls.prober,
        safeT: cls.safeT,
        tool: cls.tool,
        isFinding: false,
        verdict: "denied",
      };
    }

    // Governance allowed the probe.
    emit({ type: "agent.gate", agentId: cls.prober, verdict: "allowed" });

    const responseText = resultText(verdict.result as ToolCallResult);
    const ctx: ProbeContext = {
      responseText,
      toolDescription: descriptionFor(tools, cls.tool),
    };
    const hit = cls.detect(ctx);

    if (!hit) {
      console.error(`[${cls.prober}] no finding (clean) — ${cls.tool}`);
      emit({ type: "agent.clean", agentId: cls.prober, tool: cls.tool });
      emit({ type: "agent.done", agentId: cls.prober, ms: elapsed() });
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
    emit({
      type: "agent.finding",
      agentId: cls.prober,
      safeT: cls.safeT,
      tool: cls.tool,
      severity: hit.severity,
      // Evidence is UNTRUSTED target output — the server escapes+truncates it
      // again before it reaches any client; we pass the runner's short excerpt.
      evidenceExcerpt: hit.evidence,
    });
    emit({ type: "agent.done", agentId: cls.prober, ms: elapsed() });
    return {
      prober: cls.prober,
      safeT: cls.safeT,
      tool: cls.tool,
      isFinding: true,
      verdict: "allowed",
      finding,
    };
  } catch (err) {
    // Any unexpected throw is a TERMINAL agent.error so the stream never hangs.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[${cls.prober}] ERROR — ${message}`);
    emit({ type: "agent.error", agentId: cls.prober, message });
    throw err;
  }
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
  onEvent?: RunnerOnEvent,
): Promise<ProberResult[]> {
  // ADDITIVE: optional live-event emitter (UI1 SSE). Absent -> no-op -> the
  // demo:local / orchestrator path is byte-identical to before.
  const emit = onEvent ?? noopEmit;

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
    PROBE_CLASSES.map((c) => runOneProber(c, tools, callTool, policy, emit)),
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
