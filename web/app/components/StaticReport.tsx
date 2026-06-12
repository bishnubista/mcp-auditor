"use client";

// Static structured report renderer — the REQUIRED path (PLAN-UI §3, §7).
// Thesys C1 generative rendering (UI5) slots in BEHIND this seam: when a
// validated C1 spec is available it can replace <StaticReport/>, falling back
// here on missing key / invalid schema. This component renders ONLY bounded,
// already-escaped fields as plain text — no HTML, no markdown-HTML, no links
// sourced from evidence (PLAN-UI §6 trust boundary).

import {
  type AuditCompleteFinding,
  type ReportModel,
  type Severity,
  severityRank,
} from "@/lib/protocol";
import { clampEvidence } from "@/lib/safe";
import { SeverityBadge } from "./SeverityBadge";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Normalize a bounded ReportModel (the report.ready static path) into the
// AuditCompleteFinding shape this renderer already knows. ReportModel findings
// carry `probeClass` instead of `agentId`; we stash it in agentId for the title.
function modelToFindings(model: ReportModel): AuditCompleteFinding[] {
  return model.findings.map((f) => ({
    agentId: f.probeClass,
    safeT: f.safeT,
    severity: f.severity,
    tool: f.tool,
    evidenceExcerpt: f.evidenceExcerpt,
  }));
}

export function StaticReport({
  findings,
  model,
  target,
}: {
  findings?: AuditCompleteFinding[];
  model?: ReportModel | null;
  target: string | null;
}) {
  // Prefer the bounded ReportModel when present (richer, backend-sanitized);
  // otherwise render the audit.complete findings.
  const resolvedFindings: AuditCompleteFinding[] = model
    ? modelToFindings(model)
    : (findings ?? []);
  const resolvedTarget = model?.target ?? target;
  return renderReport(resolvedFindings, resolvedTarget);
}

function renderReport(
  findings: AuditCompleteFinding[],
  target: string | null,
) {
  const counts = SEV_ORDER.map((sev) => ({
    sev,
    n: findings.filter((f) => f.severity === sev).length,
  }));
  const total = findings.length;

  const sorted = [...findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );

  const worst: Severity | null = sorted.length ? sorted[0].severity : null;

  return (
    <section
      className="rounded-lg border border-[var(--color-line-bright)] bg-[var(--color-panel)]"
      data-report="static"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-line)] px-5 py-4">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-[0.2em] text-[var(--color-ink)]">
            Audit Report
          </h2>
          {target && (
            <p className="mt-1 break-all font-mono text-[11px] text-[var(--color-ink-faint)]">
              target: {target}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-[var(--color-ink-faint)]">
            verdict
          </span>
          {worst ? (
            <SeverityBadge severity={worst} />
          ) : (
            <span className="text-[11px] font-bold tracking-widest text-[var(--color-phosphor)]">
              CLEAN
            </span>
          )}
        </div>
      </header>

      {/* severity summary */}
      <div className="grid grid-cols-3 gap-px border-b border-[var(--color-line)] bg-[var(--color-line)] sm:grid-cols-6">
        <SummaryCell label="findings" value={total} highlight />
        {counts.map((c) => (
          <SummaryCell key={c.sev} label={c.sev} value={c.n} sev={c.sev} />
        ))}
      </div>

      {/* per-finding cards */}
      <div className="space-y-3 p-5">
        {sorted.length === 0 ? (
          <p className="text-[12px] text-[var(--color-ink-dim)]">
            No vulnerabilities found. All probed tools behaved within their
            declared scope.
          </p>
        ) : (
          sorted.map((f, i) => <FindingRow key={`${f.agentId}-${i}`} f={f} />)
        )}
      </div>
    </section>
  );
}

function SummaryCell({
  label,
  value,
  sev,
  highlight,
}: {
  label: string;
  value: number;
  sev?: Severity;
  highlight?: boolean;
}) {
  const color = sev
    ? `var(--color-sev-${sev})`
    : highlight
      ? "var(--color-ink)"
      : "var(--color-ink-dim)";
  return (
    <div className="bg-[var(--color-panel)] px-3 py-3 text-center">
      <div
        className="text-2xl font-bold tabular-nums"
        style={{ color: value > 0 || highlight ? color : "var(--color-ink-faint)" }}
      >
        {value}
      </div>
      <div className="mt-0.5 text-[10px] uppercase tracking-widest text-[var(--color-ink-faint)]">
        {label}
      </div>
    </div>
  );
}

function FindingRow({ f }: { f: AuditCompleteFinding }) {
  return (
    <article className="rounded border border-[var(--color-line)] bg-[var(--color-canvas)] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--color-ink-faint)]">
          {f.safeT}
        </span>
        <span className="text-sm font-semibold text-[var(--color-ink)]">
          {prettyAgent(f.agentId)}
        </span>
        <span className="ml-auto rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--color-cyan)]">
          {f.tool}
        </span>
      </div>

      <div className="mt-3">
        <div className="mb-1 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
          evidence · untrusted data
        </div>
        {/* plain-text children — React escapes; no dangerouslySetInnerHTML */}
        <p className="whitespace-pre-wrap break-words rounded bg-[var(--color-panel-2)] p-2 font-mono text-[11px] text-[var(--color-ink-dim)]">
          {clampEvidence(f.evidenceExcerpt)}
        </p>
      </div>

      <div className="mt-3">
        <div className="mb-1 text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
          remediation
        </div>
        <p className="text-[12px] leading-relaxed text-[var(--color-ink-dim)]">
          {remediationFor(f)}
        </p>
      </div>
    </article>
  );
}

function prettyAgent(agentId: string): string {
  return agentId
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

// Static remediation guidance keyed by SAFE-T id (our own copy — not target
// derived, so it is safe to render).
function remediationFor(f: AuditCompleteFinding): string {
  switch (f.safeT) {
    case "SAFE-T1106":
      return "Canonicalize and confine all file paths to an allowlisted root; reject '..' traversal and absolute paths before any filesystem access.";
    case "SAFE-T1502":
      return "Never expose secret material through tool responses; redact credentials and exclude dotenv/keystore paths from any readable surface.";
    case "SAFE-T1102":
      return "Treat tool names and descriptions as untrusted data; strip/neutralize embedded instructions and never feed them back to the model as directives.";
    case "SAFE-T1104":
      return "Scope each tool to the minimum data and capability it needs; enforce least-privilege at the gate rather than trusting the tool's stated purpose.";
    case "SAFE-T1402":
      return "Validate and allowlist outbound destinations; block private/loopback/metadata addresses and require explicit approval for external egress.";
    default:
      return "Review the tool's behavior against its declared schema and confirm it operates within least-privilege scope.";
  }
}
