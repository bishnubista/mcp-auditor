// Pure reducer that folds the §5 SSE event stream into renderable UI state.
// Rules (PLAN-UI §5): cards key off agentId; ignore out-of-order / duplicate seq.

import {
  type AuditEvent,
  type AuditCompleteFinding,
  type ReportModel,
  type Severity,
  PROBERS,
} from "./protocol";

export interface ReportState {
  mode: "c1" | "static";
  spec: unknown | null;
  model: ReportModel | null;
}

export type AgentPhase = "idle" | "probing" | "found" | "clean" | "error";

export interface AgentCardState {
  agentId: string;
  safeT: string;
  tool: string;
  label: string;
  blurb: string;
  phase: AgentPhase;
  gated: boolean; // governance gate verdict "allowed" seen
  gateVerdict: "allowed" | "blocked" | null;
  severity: Severity | null;
  evidenceExcerpt: string | null;
  errorMessage: string | null;
  ms: number | null;
  // highest seq applied to THIS agent (out-of-order guard, per-agent).
  lastSeq: number;
}

export interface LogEntry {
  seq: number;
  ts: string;
  type: string;
  agentId?: string;
  text: string;
}

export interface AuditState {
  status: "connecting" | "live" | "complete" | "error";
  auditId: string | null;
  runId: string | null;
  target: string | null;
  agents: Record<string, AgentCardState>;
  order: string[]; // stable agent render order
  log: LogEntry[];
  findings: AuditCompleteFinding[];
  reportReady: boolean;
  // Generative report (PLAN-UI §7). Set by the report.ready event. Null until
  // it arrives; the static report still renders from `findings` meanwhile.
  report: ReportState | null;
  // de-dup guard across the whole audit: highest global seq seen.
  maxSeq: number;
  seenSeq: Set<number>;
}

function blankAgent(agentId: string): AgentCardState {
  const spec = PROBERS.find((p) => p.agentId === agentId);
  return {
    agentId,
    safeT: spec?.safeT ?? "",
    tool: spec?.tool ?? "",
    label: spec?.label ?? agentId,
    blurb: spec?.blurb ?? "",
    phase: "idle",
    gated: false,
    gateVerdict: null,
    severity: null,
    evidenceExcerpt: null,
    errorMessage: null,
    ms: null,
    lastSeq: -1,
  };
}

export function initialState(): AuditState {
  const agents: Record<string, AgentCardState> = {};
  const order: string[] = [];
  for (const p of PROBERS) {
    agents[p.agentId] = blankAgent(p.agentId);
    order.push(p.agentId);
  }
  return {
    status: "connecting",
    auditId: null,
    runId: null,
    target: null,
    agents,
    order,
    log: [],
    findings: [],
    reportReady: false,
    report: null,
    maxSeq: -1,
    seenSeq: new Set<number>(),
  };
}

function logLine(ev: AuditEvent): string {
  switch (ev.type) {
    case "audit.start":
      return `audit started against ${ev.target}`;
    case "agent.start":
      return `${ev.agentId} probing ${ev.tool} (${ev.safeT})`;
    case "agent.gate":
      return `${ev.agentId} governance gate: ${ev.verdict}`;
    case "agent.finding":
      return `${ev.agentId} FINDING ${ev.severity.toUpperCase()} on ${ev.tool}`;
    case "agent.clean":
      return `${ev.agentId} clean`;
    case "agent.done":
      return `${ev.agentId} done (${ev.ms}ms)`;
    case "agent.error":
      return `${ev.agentId} error: ${ev.message}`;
    case "audit.complete":
      return `audit complete — ${ev.findings.length} finding(s)`;
    case "report.ready":
      return `report ready — ${ev.mode === "c1" ? "generative (C1)" : "static"} renderer`;
    default:
      return "event";
  }
}

// Apply one event. Returns a new state object (immutable-ish for React).
export function applyEvent(state: AuditState, ev: AuditEvent): AuditState {
  // Global de-dup / out-of-order guard. A seq we've already applied is dropped.
  if (state.seenSeq.has(ev.seq)) {
    return state;
  }

  const seenSeq = new Set(state.seenSeq);
  seenSeq.add(ev.seq);
  const maxSeq = Math.max(state.maxSeq, ev.seq);

  const next: AuditState = {
    ...state,
    seenSeq,
    maxSeq,
    log: [
      ...state.log,
      {
        seq: ev.seq,
        ts: ev.ts,
        type: ev.type,
        agentId: "agentId" in ev ? ev.agentId : undefined,
        text: logLine(ev),
      },
    ],
  };

  const updateAgent = (
    agentId: string,
    seq: number,
    patch: Partial<AgentCardState>,
  ): AuditState => {
    const cur = next.agents[agentId] ?? blankAgent(agentId);
    // Per-agent ordering guard: a stale per-agent seq must not regress phase.
    if (seq <= cur.lastSeq) {
      return next;
    }
    return {
      ...next,
      agents: {
        ...next.agents,
        [agentId]: { ...cur, ...patch, lastSeq: seq },
      },
    };
  };

  switch (ev.type) {
    case "audit.start":
      return {
        ...next,
        status: "live",
        auditId: ev.auditId,
        runId: ev.runId,
        target: ev.target,
      };

    case "agent.start":
      return updateAgent(ev.agentId, ev.seq, { phase: "probing" });

    case "agent.gate":
      return updateAgent(ev.agentId, ev.seq, {
        gated: ev.verdict === "allowed",
        gateVerdict: ev.verdict,
      });

    case "agent.finding":
      return updateAgent(ev.agentId, ev.seq, {
        phase: "found",
        severity: ev.severity,
        evidenceExcerpt: ev.evidenceExcerpt,
      });

    case "agent.clean":
      return updateAgent(ev.agentId, ev.seq, { phase: "clean" });

    case "agent.done": {
      const cur = next.agents[ev.agentId];
      // Only settle to a terminal phase if no finding/clean already set it.
      const phase: AgentPhase =
        cur && (cur.phase === "found" || cur.phase === "clean")
          ? cur.phase
          : cur && cur.phase === "error"
            ? "error"
            : "clean";
      return updateAgent(ev.agentId, ev.seq, { phase, ms: ev.ms });
    }

    case "agent.error":
      return updateAgent(ev.agentId, ev.seq, {
        phase: "error",
        errorMessage: ev.message,
      });

    case "audit.complete":
      return {
        ...next,
        status: "complete",
        findings: ev.findings,
        reportReady: ev.reportReady,
      };

    case "report.ready":
      return {
        ...next,
        report: {
          // Trust gate: only honor mode='c1' when a spec is actually present.
          mode: ev.mode === "c1" && ev.spec != null ? "c1" : "static",
          spec: ev.mode === "c1" ? (ev.spec ?? null) : null,
          model: ev.model ?? null,
        },
      };

    default:
      return next;
  }
}
