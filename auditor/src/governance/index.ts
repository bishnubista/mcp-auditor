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
  // Per-tool probe counters, keyed by `${serverId}::${tool}` so rate caps are
  // scoped to a concrete target tool, not a tool name reused across servers.
  // The Map LIVES ON THE POLICY (not at module level) so the rate-cap budget is
  // scoped to one audit run: buildPolicy() mints a fresh Map per audit, which is
  // what the long-lived stream server needs — concurrent and sequential audits
  // in one process each get their own budget instead of starving on a global
  // counter that never resets. Required (not optional) so the compiler forces
  // every policy — including hand-built test policies — to carry its own budget.
  counters: Map<string, number>;
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

  // 3. Per-tool rate cap. Counters live on the policy (see ProbePolicy), so the
  //    budget is per audit run — never shared across runs in one process.
  const key = `${req.serverId}::${req.tool}`;
  const used = policy.counters.get(key) ?? 0;
  if (used >= policy.maxProbesPerTool) {
    return deny("rate-cap");
  }
  policy.counters.set(key, used + 1);

  // 4. Allowed — AUDIT BEFORE DISPATCH (integrity invariant).
  //
  // The single audit entry is written BEFORE callTool is invoked. The verdict is
  // already decided (allowed) at this point, so the trail is complete the moment
  // the gate opens: a crash AFTER invoke but BEFORE we returned can never leave an
  // un-audited probe. There is EXACTLY ONE audit entry per probe — we do NOT write
  // a second "completion" entry (demo:local asserts exactly 6 audit lines), so a
  // subsequent tool-call error is surfaced in the RETURNED result only, never as a
  // second audit line.
  backend.audit({ ...base, verdict: "allowed", reason: "ok" });

  try {
    const result = await callTool(req.tool, req.payload);
    return { verdict: "allowed", result, reason: "ok" };
  } catch (err) {
    const reason = `tool-error:${err instanceof Error ? err.message : String(err)}`;
    // The probe WAS already permitted AND audited above. The target tool threw;
    // surface the error in the returned result WITHOUT writing a second audit line.
    return { verdict: "allowed", reason };
  }
}
