import { LiveAuditPanel } from "./components/LiveAuditPanel";
import { PROBERS } from "@/lib/protocol";

// Server component. No Bun/Node-only APIs — pure render. The streaming + state
// all lives in the client <LiveAuditPanel/> (SSE consumed client-side per §4).
export default function Home() {
  return (
    <main className="mx-auto max-w-6xl px-5 py-10 md:py-14">
      <header className="mb-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded border border-[var(--color-phosphor)] bg-[var(--color-panel)] text-[var(--color-phosphor)]">
            <span className="text-lg">⌖</span>
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-[var(--color-ink)]">
              MCP&nbsp;Auditor
              <span className="cursor-blink ml-1 text-[var(--color-phosphor)]">
                ▮
              </span>
            </h1>
            <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--color-ink-faint)]">
              governed multi-agent security audit
            </p>
          </div>
          <div className="ml-auto hidden items-center gap-2 sm:flex">
            <Pill>SAFE-T</Pill>
            <Pill>governed</Pill>
            <Pill>SSE live</Pill>
          </div>
        </div>

        <p className="mt-5 max-w-2xl text-[13px] leading-relaxed text-[var(--color-ink-dim)]">
          Point six SAFE-T security agents at a live MCP endpoint and watch them
          hunt vulnerabilities in real time. Every probe runs behind a
          governance gate — each tool call is admitted, audited, and streamed.
          The target&apos;s output is treated as untrusted data, never as
          instructions.
        </p>

        {/* prober legend */}
        <div className="mt-5 flex flex-wrap gap-2">
          {PROBERS.map((p) => (
            <span
              key={p.agentId}
              className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] px-2 py-1 text-[10px] text-[var(--color-ink-faint)]"
              title={p.blurb}
            >
              <span className="text-[var(--color-ink-dim)]">{p.safeT}</span>{" "}
              {p.label}
            </span>
          ))}
        </div>
      </header>

      <LiveAuditPanel />

      <footer className="mt-12 border-t border-[var(--color-line)] pt-4 text-[10px] text-[var(--color-ink-faint)]">
        Static report renderer is the required path. Thesys C1 generative
        rendering (UI5) slots in behind a schema-validated seam — unknown
        components fall back here. No raw HTML, no untrusted links.
      </footer>
    </main>
  );
}

function Pill({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full border border-[var(--color-line-bright)] px-2.5 py-1 text-[10px] uppercase tracking-widest text-[var(--color-ink-dim)]">
      {children}
    </span>
  );
}
