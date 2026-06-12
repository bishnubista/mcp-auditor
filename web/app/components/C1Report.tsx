"use client";

// Thesys C1 generative report renderer (PLAN-UI §7).
//
// Renders a backend-validated C1 component tree via the Thesys Crayon React SDK
// (`@thesysai/genui-sdk` -> <C1Component>). The spec arriving on the report.ready
// event is `choices[0].message.content` from the C1 chat-completions response,
// ALREADY schema-validated by the backend (auditor/src/thesys/c1.ts) against the
// allowlisted component set + https/#-only hrefs + banned-markup guard.
//
// Trust boundary (PLAN-UI §6): we NEVER use dangerouslySetInnerHTML. <C1Component>
// builds React elements from the structured spec — it does not inject raw HTML.
// Any render-time failure is caught by the error boundary and the caller drops to
// the static renderer, so a malformed/hostile spec can never break the page.

import { Component, type ReactNode } from "react";
import { C1Component, ThemeProvider } from "@thesysai/genui-sdk";
import "@crayonai/react-ui/styles/index.css";

// C1Component expects the response as a string (the C1 DSL / message content).
// Our backend may hand us a string OR a parsed object; normalize to a string.
function toC1Response(spec: unknown): string {
  if (typeof spec === "string") return spec;
  try {
    return JSON.stringify(spec);
  } catch {
    return "";
  }
}

class C1ErrorBoundary extends Component<
  { onFail: () => void; children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    // Notify the parent so it can switch to the static renderer.
    this.props.onFail();
  }

  render() {
    if (this.state.failed) return null;
    return this.props.children;
  }
}

export function C1Report({
  spec,
  onFail,
}: {
  spec: unknown;
  onFail: () => void;
}) {
  const c1Response = toC1Response(spec);
  if (!c1Response) {
    // Empty/unstringifiable spec — fall straight back.
    onFail();
    return null;
  }

  return (
    <section
      className="rounded-lg border border-[var(--color-line-bright)] bg-[var(--color-panel)] p-1"
      data-report="c1"
    >
      <div className="flex items-center gap-2 border-b border-[var(--color-line)] px-4 py-2.5">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-[var(--color-ink)]">
          Audit Report
        </span>
        <span className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-[var(--color-cyan)]">
          generative · Thesys C1
        </span>
      </div>
      <div className="c1-report-body p-3">
        <C1ErrorBoundary onFail={onFail}>
          <ThemeProvider>
            <C1Component c1Response={c1Response} isStreaming={false} />
          </ThemeProvider>
        </C1ErrorBoundary>
      </div>
    </section>
  );
}
