"use client";

// Composio "File GitHub issue" action (PLAN-UI §4 POST /audits/:id/file-issue).
// On success shows the returned issueUrl as an https-only link, or the degraded
// preview payload (when Composio auth stalls). The payload preview is rendered
// as plain JSON text — never as HTML, never executed.

import { useState } from "react";
import { type FileIssueResult, fileIssue } from "@/lib/connect";
import { isSafeHttpsUrl } from "@/lib/safe";

type State =
  | { kind: "idle" }
  | { kind: "filing" }
  | { kind: "done"; result: FileIssueResult };

export function FileIssueButton({
  auditId,
  streamToken,
}: {
  auditId: string;
  streamToken: string;
}) {
  const [state, setState] = useState<State>({ kind: "idle" });

  const file = async () => {
    setState({ kind: "filing" });
    const result = await fileIssue(auditId, streamToken);
    setState({ kind: "done", result });
  };

  if (state.kind === "done") {
    const r = state.result;
    if (r.ok && "issueUrl" in r && isSafeHttpsUrl(r.issueUrl)) {
      return (
        <div className="rounded border border-[var(--color-phosphor)] bg-[var(--color-panel)] px-4 py-3 text-[12px]">
          <span className="text-[var(--color-ink-dim)]">
            Filed via Composio:{" "}
          </span>
          <a
            href={r.issueUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="break-all font-mono text-[var(--color-cyan)] underline"
          >
            {r.issueUrl}
          </a>
        </div>
      );
    }
    if (r.ok && "degraded" in r) {
      return (
        <div className="rounded border border-[var(--color-amber)] bg-[var(--color-panel)] px-4 py-3">
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-amber)]">
            Composio unavailable — issue payload preview
          </div>
          {/* plain-text JSON; React escapes, no HTML injection */}
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-[var(--color-panel-2)] p-2 font-mono text-[11px] text-[var(--color-ink-dim)]">
            {safeStringify(r.payload)}
          </pre>
        </div>
      );
    }
    // Error or unexpected shape.
    return (
      <div className="flex items-center gap-3 rounded border border-[var(--color-amber)] bg-[var(--color-panel)] px-4 py-2 text-[12px] text-[var(--color-amber)]">
        <span>
          file-issue failed
          {!r.ok && "error" in r ? `: ${r.error}` : ""}
        </span>
        <button
          type="button"
          onClick={() => setState({ kind: "idle" })}
          className="ml-auto text-[11px] underline"
        >
          retry
        </button>
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={file}
      disabled={state.kind === "filing"}
      className="inline-flex items-center gap-2 rounded border border-[var(--color-line-bright)] bg-transparent px-3 py-2 text-[12px] text-[var(--color-ink-dim)] transition-colors hover:border-[var(--color-phosphor)] hover:text-[var(--color-ink)] disabled:opacity-50"
    >
      {state.kind === "filing" ? "filing…" : "⌥ File GitHub issue (Composio)"}
    </button>
  );
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "(unserializable payload)";
  }
}
