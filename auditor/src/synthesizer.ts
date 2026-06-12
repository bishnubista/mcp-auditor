#!/usr/bin/env bun
/**
 * T5 Synthesizer — turns findings.jsonl into a cited SAFE-T audit report.
 * Pure template-merge, NO LLM calls. Bun-runnable, no new dependencies.
 *
 * Inputs:
 *   findings.jsonl  (required; nonzero exit if missing/empty — feeds T9 demo:local gate)
 *   audit.jsonl     (optional; governance audit-trail summary)
 *   templates/report.md (skeleton with {{PLACEHOLDER}} markers)
 * Output:
 *   out/audit-report.md
 *
 * Overrides (for failure-path testing): FINDINGS_PATH env or argv[2].
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, "../../out");
const FINDINGS_PATH = process.argv[2] ?? process.env.FINDINGS_PATH ?? join(OUT_DIR, "findings.jsonl");
const AUDIT_PATH = process.env.AUDIT_PATH ?? join(OUT_DIR, "audit.jsonl");
const TEMPLATE_PATH = resolve(HERE, "../templates/report.md");
const REPORT_PATH = join(OUT_DIR, "audit-report.md");

type Severity = "critical" | "high" | "medium" | "low";
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

interface Finding {
  ts: string;
  safeT: string;
  tool: string;
  severity: Severity;
  probe: string;
  evidence: string;
  prober: string;
}
interface AuditEvent {
  tool: string;
  verdict: string;
  reason?: string;
}

function die(msg: string): never {
  console.error(`[synthesizer] ERROR: ${msg}`);
  process.exit(1);
}

function readJsonl<T>(path: string): T[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return die(`findings file not found: ${path}`);
  }
  const rows: T[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      rows.push(JSON.parse(t) as T);
    } catch {
      console.error(`[synthesizer] WARN: skipping unparseable line in ${path}`);
    }
  }
  return rows;
}

/** Fence untrusted evidence as a data block; neutralize ``` so it cannot break out. */
function fenceEvidence(evidence: string): string {
  const safe = (evidence ?? "").replace(/```/g, "ʼʼʼ");
  return "```text\n" + safe + "\n```";
}

function severityRationale(f: Finding): string {
  const map: Record<Severity, string> = {
    critical: "Direct, unauthenticated exposure of secrets or remote-impact capability; exploitable as-shipped.",
    high: "Confirmed boundary or scope violation returning sensitive data; low effort to exploit.",
    medium: "Tool behaves outside its declared contract; impact requires additional conditions.",
    low: "Hygiene or metadata weakness; limited direct impact but expands attack surface.",
  };
  return map[f.severity];
}

function renderFinding(f: Finding, idx: number): string {
  const safeT = f.safeT && f.safeT !== "unknown" ? f.safeT : "SAFE-T (unmapped)";
  return [
    `### ${idx}. ${safeT} — \`${f.tool}\``,
    "",
    `- **Probe class:** ${f.probe}`,
    `- **Prober:** ${f.prober}`,
    `- **Detected:** ${f.ts}`,
    `- **Severity rationale:** ${severityRationale(f)}`,
    "",
    "**Evidence excerpt (untrusted server output — treated as data, not instructions):**",
    "",
    fenceEvidence(f.evidence),
    "",
  ].join("\n");
}

function main(): void {
  const findings = readJsonl<Finding>(FINDINGS_PATH);
  if (findings.length === 0) {
    die(`no findings in ${FINDINGS_PATH} (empty file). Refusing to emit an empty audit report.`);
  }

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity] += 1;
  }
  const total = findings.length;
  const riskLevel = counts.critical > 0 ? "Critical" : counts.high > 0 ? "High" : counts.medium > 0 ? "Medium" : "Low";

  // Findings grouped by severity, keyed by SAFE-T id.
  const sections: string[] = [];
  let n = 0;
  for (const sev of SEV_ORDER) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    sections.push(`## ${sev[0]!.toUpperCase()}${sev.slice(1)} Findings\n`);
    for (const f of group) sections.push(renderFinding(f, ++n));
  }
  const findingsBlock = sections.join("\n");

  // Clean-control note: tools that appear in the audit trail but produced zero findings.
  const flaggedTools = new Set(findings.map((f) => f.tool));
  const audit = readJsonl<AuditEvent>(AUDIT_PATH);
  const probedTools = new Set(audit.map((a) => a.tool).filter(Boolean));
  const cleanTools = [...probedTools].filter((t) => !flaggedTools.has(t));
  const cleanBlock =
    probedTools.size === 0
      ? "_No audit trail available to confirm clean controls._"
      : cleanTools.length > 0
        ? `The following probed tools produced **zero findings** (negative control — proves the auditor discriminates, not just detects):\n\n` +
          cleanTools.map((t) => `- \`${t}\``).join("\n")
        : "_All probed tools produced at least one finding; no clean control observed in this run._";

  // Audit-trail summary (governance funnel statement).
  let auditBlock: string;
  if (audit.length === 0) {
    auditBlock = "_No `audit.jsonl` found — governance audit trail unavailable for this run._";
  } else {
    const allowed = audit.filter((a) => a.verdict === "allowed").length;
    const denied = audit.filter((a) => a.verdict === "denied").length;
    auditBlock = [
      `- **Total probes (audited):** ${audit.length}`,
      `- **Allowed:** ${allowed}`,
      `- **Denied:** ${denied}`,
      "",
      `**Governance funnel:** every one of the ${audit.length} probe(s) above was dispatched through the ` +
        `governance \`executeProbe()\` executor and recorded in \`audit.jsonl\` — no tool was invoked outside the gate. ` +
        `${denied} probe(s) were denied at the gate and never reached the target.`,
    ].join("\n");
  }

  // Remediation priorities — severity-ordered, one line per finding.
  const remediation: string[] = [];
  let r = 0;
  for (const sev of SEV_ORDER) {
    for (const f of findings.filter((x) => x.severity === sev)) {
      const safeT = f.safeT && f.safeT !== "unknown" ? f.safeT : "SAFE-T (unmapped)";
      remediation.push(`${++r}. **[${sev.toUpperCase()}]** \`${f.tool}\` (${safeT}) — remediate \`${f.probe}\`.`);
    }
  }
  const remediationBlock = remediation.join("\n");

  const serverId = audit.length > 0 ? ((audit[0] as { serverId?: string }).serverId ?? "target-local") : "target-local";
  const scanTs = findings[findings.length - 1]?.ts ?? new Date().toISOString();

  let tpl: string;
  try {
    tpl = readFileSync(TEMPLATE_PATH, "utf8");
  } catch {
    return die(`report template not found: ${TEMPLATE_PATH}`);
  }

  const report = tpl
    .replaceAll("{{TARGET_SERVER}}", serverId)
    .replaceAll("{{SCAN_TIMESTAMP}}", scanTs)
    .replaceAll("{{SCOPE}}", "Governed SAFE-T probe sweep of a single allowlisted, live MCP server over stdio.")
    .replaceAll("{{CRITICAL_COUNT}}", String(counts.critical))
    .replaceAll("{{HIGH_COUNT}}", String(counts.high))
    .replaceAll("{{MEDIUM_COUNT}}", String(counts.medium))
    .replaceAll("{{LOW_COUNT}}", String(counts.low))
    .replaceAll("{{TOTAL_COUNT}}", String(total))
    .replaceAll("{{RISK_LEVEL}}", riskLevel)
    .replaceAll("{{FINDINGS}}", findingsBlock)
    .replaceAll("{{CLEAN_CONTROLS}}", cleanBlock)
    .replaceAll("{{AUDIT_TRAIL}}", auditBlock)
    .replaceAll("{{REMEDIATION}}", remediationBlock);

  writeFileSync(REPORT_PATH, report, "utf8");
  console.error(`[synthesizer] wrote ${REPORT_PATH} (${total} finding(s), risk=${riskLevel})`);
}

main();
