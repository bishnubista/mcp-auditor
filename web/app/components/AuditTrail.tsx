"use client";

import { useEffect, useRef } from "react";
import type { LogEntry } from "@/lib/audit-state";

const TYPE_COLOR: Record<string, string> = {
  "audit.start": "var(--color-cyan)",
  "agent.start": "var(--color-ink-dim)",
  "agent.gate": "var(--color-phosphor)",
  "agent.finding": "var(--color-rose)",
  "agent.clean": "var(--color-phosphor)",
  "agent.done": "var(--color-ink-faint)",
  "agent.error": "var(--color-amber)",
  "audit.complete": "var(--color-cyan)",
  "audit.error": "var(--color-amber)",
};

export function AuditTrail({ log }: { log: LogEntry[] }) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [log.length]);

  return (
    <div className="flex h-full flex-col rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)]">
      <div className="flex items-center justify-between border-b border-[var(--color-line)] px-3 py-2">
        <span className="text-[11px] uppercase tracking-widest text-[var(--color-ink-dim)]">
          audit trail
        </span>
        <span className="text-[10px] text-[var(--color-ink-faint)]">
          {log.length} events
        </span>
      </div>
      <div className="thin-scroll max-h-[320px] flex-1 overflow-y-auto px-3 py-2 font-mono text-[11px] leading-relaxed">
        {log.length === 0 ? (
          <p className="text-[var(--color-ink-faint)]">
            <span className="cursor-blink">▮</span> awaiting stream…
          </p>
        ) : (
          log.map((e, i) => (
            <div key={`${e.seq}-${i}`} className="flex gap-2">
              <span className="shrink-0 text-[var(--color-ink-faint)]">
                {String(e.seq).padStart(3, "0")}
              </span>
              <span
                className="shrink-0 font-semibold"
                style={{ color: TYPE_COLOR[e.type] ?? "var(--color-ink-dim)" }}
              >
                {e.type}
              </span>
              {/* plain-text children — escaped by React */}
              <span className="text-[var(--color-ink-dim)]">{e.text}</span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
