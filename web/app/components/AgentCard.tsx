"use client";

import type { AgentCardState } from "@/lib/audit-state";
import { clampEvidence } from "@/lib/safe";
import { SeverityBadge } from "./SeverityBadge";

const PHASE_META: Record<
  AgentCardState["phase"],
  { label: string; color: string; ring: string }
> = {
  idle: { label: "IDLE", color: "var(--color-ink-faint)", ring: "var(--color-line)" },
  probing: { label: "PROBING", color: "var(--color-cyan)", ring: "var(--color-cyan)" },
  found: { label: "FOUND", color: "var(--color-rose)", ring: "var(--color-rose)" },
  clean: { label: "CLEAN", color: "var(--color-phosphor)", ring: "var(--color-phosphor)" },
  error: { label: "ERROR", color: "var(--color-amber)", ring: "var(--color-amber)" },
};

export function AgentCard({ agent }: { agent: AgentCardState }) {
  const meta = PHASE_META[agent.phase];
  const active = agent.phase === "probing";

  return (
    <div
      className="relative overflow-hidden rounded-lg border bg-[var(--color-panel)] p-4 transition-colors duration-300"
      style={{ borderColor: meta.ring }}
    >
      {active && <div className="scanline" />}

      {/* header: tool + safeT */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[11px] uppercase tracking-widest text-[var(--color-ink-faint)]">
            {agent.safeT}
          </div>
          <div className="truncate text-sm font-semibold text-[var(--color-ink)]">
            {agent.label}
          </div>
        </div>
        <PhaseIndicator phase={agent.phase} color={meta.color} />
      </div>

      {/* target tool */}
      <div className="mt-2 flex items-center gap-2 text-[11px] text-[var(--color-ink-dim)]">
        <span className="text-[var(--color-ink-faint)]">tool</span>
        <span className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 font-mono text-[var(--color-cyan)]">
          {agent.tool}
        </span>
      </div>

      {/* blurb / evidence area */}
      <div className="mt-3 min-h-[58px] text-[12px] leading-relaxed">
        {agent.phase === "found" && agent.evidenceExcerpt ? (
          <div className="rounded border border-[var(--color-line)] bg-[var(--color-canvas)] p-2">
            <div className="mb-1 flex items-center gap-2">
              {agent.severity && <SeverityBadge severity={agent.severity} />}
              <span className="text-[10px] uppercase tracking-wider text-[var(--color-ink-faint)]">
                evidence · untrusted
              </span>
            </div>
            {/* Rendered as plain-text children — React escapes. No HTML, no links. */}
            <p className="whitespace-pre-wrap break-words font-mono text-[11px] text-[var(--color-ink-dim)]">
              {clampEvidence(agent.evidenceExcerpt, 260)}
            </p>
          </div>
        ) : agent.phase === "error" ? (
          <p className="font-mono text-[11px] text-[var(--color-amber)]">
            {agent.errorMessage ?? "prober error"}
          </p>
        ) : (
          <p className="text-[var(--color-ink-faint)]">{agent.blurb}</p>
        )}
      </div>

      {/* footer: governance gate + status + timing */}
      <div className="mt-3 flex items-center justify-between border-t border-[var(--color-line)] pt-2">
        <GateBadge gated={agent.gated} verdict={agent.gateVerdict} />
        <div className="flex items-center gap-2 text-[10px]">
          {agent.ms != null && (
            <span className="text-[var(--color-ink-faint)]">{agent.ms}ms</span>
          )}
          <span
            className="font-bold tracking-widest"
            style={{ color: meta.color }}
          >
            {meta.label}
          </span>
        </div>
      </div>
    </div>
  );
}

function PhaseIndicator({
  phase,
  color,
}: {
  phase: AgentCardState["phase"];
  color: string;
}) {
  if (phase === "probing") {
    return <div className="spinner" aria-label="probing" />;
  }
  if (phase === "found") {
    return (
      <span className="text-base leading-none" style={{ color }} aria-label="found">
        ✕
      </span>
    );
  }
  if (phase === "clean") {
    return (
      <span className="text-base leading-none" style={{ color }} aria-label="clean">
        ✓
      </span>
    );
  }
  if (phase === "error") {
    return (
      <span className="text-base leading-none" style={{ color }} aria-label="error">
        ⚠
      </span>
    );
  }
  return (
    <span
      className="inline-block h-2.5 w-2.5 rounded-full"
      style={{ backgroundColor: "var(--color-line-bright)" }}
      aria-label="idle"
    />
  );
}

function GateBadge({
  gated,
  verdict,
}: {
  gated: boolean;
  verdict: "allowed" | "blocked" | null;
}) {
  if (verdict === "blocked") {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-[var(--color-rose)]">
        <span>⛔</span> gate blocked
      </span>
    );
  }
  if (gated) {
    return (
      <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-[var(--color-phosphor)]">
        <span>🛡</span> gated ✓
      </span>
    );
  }
  return (
    <span className="text-[10px] text-[var(--color-ink-faint)]">
      gate pending
    </span>
  );
}
