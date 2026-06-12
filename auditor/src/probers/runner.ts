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

import { mkdir, appendFile } from "node:fs/promises";
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

async function appendFinding(f: Finding): Promise<void> {
  await mkdir(OUT_DIR, { recursive: true });
  await appendFile(FINDINGS_PATH, `${JSON.stringify(f)}\n`, "utf8");
}

/**
 * Run ONE specialist prober: governed tool call → detector → optional finding.
 * Every invocation goes through executeProbe; nothing here touches callTool
 * directly. Returns a structured result (also appends the finding if any).
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
  await appendFinding(finding);
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
export async function runProbers(
  tools: ToolInfo[],
  callTool: CallToolFn,
  policy: ProbePolicy,
): Promise<ProberResult[]> {
  const toolNames = new Set(tools.map((t) => t.name));
  const applicable = PROBE_CLASSES.filter((c) => toolNames.has(c.tool));
  const skipped = PROBE_CLASSES.filter((c) => !toolNames.has(c.tool));
  for (const c of skipped) {
    console.error(`[${c.prober}] SKIP — target tool '${c.tool}' not on surface`);
  }

  console.error(
    `[runner] fanning out ${applicable.length} probers in parallel: ` +
      applicable.map((c) => c.prober).join(", "),
  );

  // The "multi-agent" moment: all specialists probe concurrently.
  const results = await Promise.all(
    applicable.map((c) => runOneProber(c, tools, callTool, policy)),
  );

  const findings = results.filter((r) => r.isFinding);
  const safeTs = new Set(findings.map((r) => r.safeT));
  const weatherFindings = findings.filter((r) => r.tool === "get_weather").length;
  console.error(
    `[runner] DONE — ${findings.length} finding(s) across ${safeTs.size} SAFE-T class(es); ` +
      `get_weather findings=${weatherFindings} (expected 0)`,
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
