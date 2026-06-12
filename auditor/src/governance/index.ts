// Governance probeExecutor — the ONLY permitted path for any prober to invoke a
// target tool. This module is the funnel: permission gate + audit trail.
//
// HARD RULE: executeProbe() is the only exported function that touches CallToolFn.
// There is no other export here that can invoke a target tool. No escape hatches.
//
// Pure TypeScript. No external dependencies (node:crypto + node:fs only, via local.ts).

import { LocalGovernance } from "./local.ts";

export interface ProbeRequest {
  agent: string; // prober id, e.g. "prober-credential-leak"
  serverId: string; // target server identifier
  tool: string; // tool being probed
  safeT: string; // SAFE-T technique id driving the probe
  payload: unknown; // probe arguments
}

export interface ProbePolicy {
  allowedServers: string[]; // explicit allowlist — deny anything else
  allowedTools: string[] | "*";
  maxProbesPerTool: number; // rate cap, e.g. 10
}

export type CallToolFn = (tool: string, args: unknown) => Promise<unknown>;

export interface AuditEntry {
  ts: string;
  agent: string;
  serverId: string;
  tool: string;
  safeT: string;
  payloadHash: string; // sha256(JSON.stringify(payload)), first 12 hex chars
  verdict: "allowed" | "denied";
  reason: string;
}

export type Verdict =
  | { verdict: "allowed"; result?: unknown; reason?: string }
  | { verdict: "denied"; reason: string };

// A governance backend records audit events. local.ts is the default;
// guild.ts is a drop-in stub implementing the same interface.
export interface GovernanceBackend {
  audit(entry: AuditEntry): void;
}

const defaultBackend: GovernanceBackend = new LocalGovernance();

// Per-tool probe counters. Keyed by `${serverId}::${tool}` so rate caps are
// scoped to a concrete target tool, not a tool name reused across servers.
const probeCounts = new Map<string, number>();

// Test-only: reset the in-memory rate-cap counters. Does NOT touch CallToolFn.
export function __resetProbeCounts(): void {
  probeCounts.clear();
}

async function sha256First12(payload: unknown): Promise<string> {
  const { createHash } = await import("node:crypto");
  const json = JSON.stringify(payload) ?? "undefined";
  return createHash("sha256").update(json).digest("hex").slice(0, 12);
}

/**
 * The funnel. Checks policy → denies or executes → ALWAYS audits (allowed AND
 * denied). callTool is NEVER invoked for a denied probe.
 */
export async function executeProbe(
  req: ProbeRequest,
  callTool: CallToolFn,
  policy: ProbePolicy,
  backend: GovernanceBackend = defaultBackend,
): Promise<Verdict> {
  const payloadHash = await sha256First12(req.payload);
  const base = {
    ts: new Date().toISOString(),
    agent: req.agent,
    serverId: req.serverId,
    tool: req.tool,
    safeT: req.safeT,
    payloadHash,
  };

  const deny = (reason: string): Verdict => {
    backend.audit({ ...base, verdict: "denied", reason });
    return { verdict: "denied", reason };
  };

  // 1. Server allowlist — deny anything not explicitly listed.
  if (!policy.allowedServers.includes(req.serverId)) {
    return deny("server-not-allowlisted");
  }

  // 2. Tool allowlist — "*" permits any tool on an allowlisted server.
  if (policy.allowedTools !== "*" && !policy.allowedTools.includes(req.tool)) {
    return deny("tool-not-allowlisted");
  }

  // 3. Per-tool rate cap.
  const key = `${req.serverId}::${req.tool}`;
  const used = probeCounts.get(key) ?? 0;
  if (used >= policy.maxProbesPerTool) {
    return deny("rate-cap");
  }
  probeCounts.set(key, used + 1);

  // 4. Allowed — invoke the target tool through the single permitted path.
  try {
    const result = await callTool(req.tool, req.payload);
    backend.audit({ ...base, verdict: "allowed", reason: "ok" });
    return { verdict: "allowed", result, reason: "ok" };
  } catch (err) {
    const reason = `tool-error:${err instanceof Error ? err.message : String(err)}`;
    // The probe WAS permitted; the target tool threw. Audit as allowed so the
    // governance trail reflects that the gate let it through; surface the error.
    backend.audit({ ...base, verdict: "allowed", reason });
    return { verdict: "allowed", reason };
  }
}
