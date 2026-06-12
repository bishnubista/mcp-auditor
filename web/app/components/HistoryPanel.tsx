"use client";

// History panel (PLAN-UI §4 GET /history). Recent audits with target, ts and
// severity counts. Backend-only enrichment — renders nothing in mock mode and
// degrades to an empty state on any fetch failure. All fields are rendered as
// plain text (target is backend-sanitized; we never echo it as markup/links).

import { useEffect, useState } from "react";
import { type HistoryEntry, fetchHistory } from "@/lib/connect";

const SEVS: Array<{ key: string; abbr: string }> = [
  { key: "critical", abbr: "C" },
  { key: "high", abbr: "H" },
  { key: "medium", abbr: "M" },
  { key: "low", abbr: "L" },
];

export function HistoryPanel() {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);

  useEffect(() => {
    let alive = true;
    fetchHistory().then((rows) => {
      if (alive) setEntries(rows);
    });
    return () => {
      alive = false;
    };
  }, []);

  // Still loading — render nothing (avoid layout flash).
  if (entries === null) return null;
  // No history yet — quiet empty state.
  if (entries.length === 0) {
    return (
      <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] px-4 py-3">
        <h3 className="text-[11px] font-bold uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">
          Recent audits
        </h3>
        <p className="mt-1 text-[11px] text-[var(--color-ink-faint)]">
          No prior audits recorded.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)]">
      <h3 className="border-b border-[var(--color-line)] px-4 py-2.5 text-[11px] font-bold uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">
        Recent audits
      </h3>
      <ul className="divide-y divide-[var(--color-line)]">
        {entries.slice(0, 8).map((e, i) => (
          <li
            key={`${e.auditId}-${i}`}
            className="flex flex-wrap items-center gap-3 px-4 py-2.5"
          >
            <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-[var(--color-ink)]">
              {e.target || "(unknown target)"}
            </span>
            <span className="font-mono text-[10px] text-[var(--color-ink-faint)]">
              {formatTs(e.ts)}
            </span>
            <span className="flex items-center gap-1.5">
              {SEVS.map((s) => {
                const n = Number(e.severityCounts?.[s.key] ?? 0);
                return (
                  <span
                    key={s.key}
                    title={`${s.key}: ${n}`}
                    className="rounded px-1.5 py-0.5 font-mono text-[10px] tabular-nums"
                    style={{
                      color:
                        n > 0
                          ? `var(--color-sev-${s.key})`
                          : "var(--color-ink-faint)",
                      backgroundColor: "var(--color-panel-2)",
                    }}
                  >
                    {s.abbr}
                    {n}
                  </span>
                );
              })}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
