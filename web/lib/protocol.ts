// PLAN-UI.md §5 — SSE event protocol (FROZEN contract).
// Every event has an SSE `id: <seq>` and a JSON body sharing this meta shape.
// `seq` is a monotonic per-audit counter. Terminal per-agent state is
// `agent.done` OR `agent.error`. `audit.complete` is emitted only after all
// 6 probers are terminal.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type EventType =
  | "audit.start"
  | "agent.start"
  | "agent.gate"
  | "agent.finding"
  | "agent.clean"
  | "agent.done"
  | "agent.error"
  | "audit.complete"
  | "audit.error"
  | "report.ready";

export interface BaseEvent {
  auditId: string;
  runId: string;
  seq: number;
  ts: string;
  type: EventType;
}

export interface AuditStartEvent extends BaseEvent {
  type: "audit.start";
  target: string;
  probers: string[]; // 6 agentIds
}

export interface AgentStartEvent extends BaseEvent {
  type: "agent.start";
  agentId: string;
  safeT: string;
  tool: string;
}

export interface AgentGateEvent extends BaseEvent {
  type: "agent.gate";
  agentId: string;
  verdict: "allowed" | "blocked";
}

export interface AgentFindingEvent extends BaseEvent {
  type: "agent.finding";
  agentId: string;
  safeT: string;
  severity: Severity;
  tool: string;
  // UNTRUSTED, escaped + truncated upstream. Rendered as plain text ONLY.
  evidenceExcerpt: string;
}

export interface AgentCleanEvent extends BaseEvent {
  type: "agent.clean";
  agentId: string;
}

export interface AgentDoneEvent extends BaseEvent {
  type: "agent.done";
  agentId: string;
  ms: number;
}

export interface AgentErrorEvent extends BaseEvent {
  type: "agent.error";
  agentId: string;
  message: string;
}

export interface AuditCompleteFinding {
  agentId: string;
  safeT: string;
  severity: Severity;
  tool: string;
  evidenceExcerpt: string;
}

export interface AuditCompleteEvent extends BaseEvent {
  type: "audit.complete";
  findings: AuditCompleteFinding[];
  reportReady: true;
}

// TERMINAL audit-level failure (e.g. admission denied / remote targets
// disabled). The run is over; no further events follow. `message` is
// UNTRUSTED backend text — rendered as plain text ONLY, never HTML.
export interface AuditErrorEvent extends BaseEvent {
  type: "audit.error";
  message: string;
  code?: string; // e.g. "remote_disabled" | "admission_denied"
}

// ---- Bounded ReportModel (PLAN-UI §6 trust boundary) ----
// Mirror of the backend's report-model.ts. The ONLY structured object that
// crosses into C1 / the renderer. Evidence is already escaped + truncated +
// labeled untrusted by the backend; we still render it as plain text only.
export interface ReportModelFinding {
  safeT: string;
  probeClass: string;
  severity: "critical" | "high" | "medium" | "low";
  tool: string;
  evidenceExcerpt: string;
}

export interface ReportModel {
  target: string;
  scanTs: string;
  auditId: string | null;
  severityCounts: Record<"critical" | "high" | "medium" | "low", number>;
  totalFindings: number;
  overallRisk: "critical" | "high" | "medium" | "low" | "none";
  findings: ReportModelFinding[];
  untrustedDataNote: string;
}

// `report.ready` (PLAN-UI §7). mode='c1' carries a validated C1 component tree
// in `spec`; mode='static' (or any C1 failure) carries only the bounded `model`.
export interface ReportReadyEvent extends BaseEvent {
  type: "report.ready";
  mode: "c1" | "static";
  // C1 component tree (already schema-validated by the backend). UNKNOWN shape —
  // treated as opaque data handed to <C1Component>, never executed as HTML.
  spec?: unknown;
  // Bounded ReportModel — always present; the static fallback renders from this.
  model?: ReportModel;
}

export type AuditEvent =
  | AuditStartEvent
  | AgentStartEvent
  | AgentGateEvent
  | AgentFindingEvent
  | AgentCleanEvent
  | AgentDoneEvent
  | AgentErrorEvent
  | AuditCompleteEvent
  | AuditErrorEvent
  | ReportReadyEvent;

// ---- The 6 SAFE-T probers (deterministic catalog) ----
// agentId is the stable key the UI cards bind to (PLAN-UI §5).
export interface ProberSpec {
  agentId: string;
  safeT: string;
  tool: string;
  label: string;
  blurb: string;
}

// agentId / safeT / tool are EXACT mirrors of the backend prober catalog
// (auditor/src/probers/payloads.ts) so each card binds to the agent.* events the
// backend actually emits. Do NOT drift these strings from the backend.
export const PROBERS: ProberSpec[] = [
  {
    agentId: "prober-path-traversal",
    safeT: "SAFE-T1106",
    tool: "read_file",
    label: "Path Traversal",
    blurb: "Escapes the sandbox via ../ to read files outside the allowed root.",
  },
  {
    agentId: "prober-credential-leakage",
    safeT: "SAFE-T1502",
    tool: "get_config",
    label: "Credential Leakage",
    blurb: "Harvests plaintext secrets and tokens from the config surface.",
  },
  {
    agentId: "prober-description-poisoning",
    safeT: "SAFE-T1102",
    tool: "search_docs",
    label: "Tool-Description Poisoning",
    blurb: "Hides prompt-injection instructions inside tool descriptions.",
  },
  {
    agentId: "prober-excessive-scope",
    safeT: "SAFE-T1104",
    tool: "run_query",
    label: "Excessive Scope",
    blurb: "Over-privileged tool reaches data beyond its stated purpose.",
  },
  {
    agentId: "prober-unvalidated-outbound",
    safeT: "SAFE-T1402",
    tool: "send_notification",
    label: "Unvalidated Outbound",
    blurb: "Fires outbound requests to attacker-controlled destinations.",
  },
  {
    agentId: "prober-schema-control",
    safeT: "SAFE-T-CONTROL",
    tool: "get_weather",
    label: "Schema Control",
    blurb: "Negative control — a well-scoped tool that should come back clean.",
  },
];

export const PROBER_IDS = PROBERS.map((p) => p.agentId);

export function severityRank(s: Severity): number {
  switch (s) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default:
      return 0;
  }
}
