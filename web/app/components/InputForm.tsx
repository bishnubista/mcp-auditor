"use client";

import { useState } from "react";
import type { AuditInput } from "@/lib/connect";

// Seeded/demo run sends NO endpoint so the backend uses its seeded stdio default
// target (audit-stream-server: no endpoint -> deterministic demo target). A
// non-empty endpoint opts into the remote SSRF-admitted path, which the
// `seeded://demo-target` pseudo-URL would (correctly) fail. Keep endpoint empty.
const SEEDED_DEMO: AuditInput = {
  githubUrl: "https://github.com/bishnubista/mcp-auditor",
  endpoint: "",
};

export function InputForm({
  onRun,
  disabled,
  mockMode,
  onToggleMock,
  canToggleMock,
}: {
  onRun: (input: AuditInput, forceMock: boolean) => void;
  disabled: boolean;
  mockMode: boolean;
  onToggleMock: (v: boolean) => void;
  canToggleMock: boolean;
}) {
  const [githubUrl, setGithubUrl] = useState("");
  const [endpoint, setEndpoint] = useState("");

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onRun({ githubUrl, endpoint }, mockMode);
  };

  const runSeeded = () => {
    setGithubUrl(SEEDED_DEMO.githubUrl);
    setEndpoint(SEEDED_DEMO.endpoint);
    onRun(SEEDED_DEMO, mockMode);
  };

  return (
    <form
      onSubmit={submit}
      className="rounded-lg border border-[var(--color-line-bright)] bg-[var(--color-panel)] p-5"
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Field
          label="GitHub repo (provenance)"
          hint="owner/repo — shown for context, never cloned"
        >
          <input
            type="text"
            inputMode="url"
            placeholder="https://github.com/org/mcp-server"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            disabled={disabled}
            className="w-full rounded border border-[var(--color-line)] bg-[var(--color-canvas)] px-3 py-2 font-mono text-[13px] text-[var(--color-ink)] outline-none transition-colors placeholder:text-[var(--color-ink-faint)] focus:border-[var(--color-phosphor)] disabled:opacity-50"
          />
        </Field>

        <Field
          label="MCP endpoint (audited target)"
          hint="StreamableHTTP URL — admitted via SSRF default-deny"
        >
          <input
            type="text"
            inputMode="url"
            placeholder="https://target.example/mcp"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            disabled={disabled}
            className="w-full rounded border border-[var(--color-line)] bg-[var(--color-canvas)] px-3 py-2 font-mono text-[13px] text-[var(--color-ink)] outline-none transition-colors placeholder:text-[var(--color-ink-faint)] focus:border-[var(--color-phosphor)] disabled:opacity-50"
          />
        </Field>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={disabled}
          className="group relative inline-flex items-center gap-2 rounded bg-[var(--color-phosphor)] px-4 py-2 text-[13px] font-bold tracking-wide text-[#04130c] transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <span>▶</span> Run governed audit
        </button>

        <button
          type="button"
          onClick={runSeeded}
          disabled={disabled}
          className="inline-flex items-center gap-2 rounded border border-[var(--color-line-bright)] bg-transparent px-3 py-2 text-[12px] text-[var(--color-ink-dim)] transition-colors hover:border-[var(--color-phosphor)] hover:text-[var(--color-ink)] disabled:opacity-40"
        >
          ⚡ Try the seeded demo target
        </button>

        <label
          className={`ml-auto flex items-center gap-2 text-[11px] ${
            canToggleMock
              ? "text-[var(--color-ink-dim)]"
              : "text-[var(--color-ink-faint)]"
          }`}
          title={
            canToggleMock
              ? "Toggle between the built-in mock stream and the real backend"
              : "No backend configured — running the built-in mock stream"
          }
        >
          <input
            type="checkbox"
            checked={mockMode}
            disabled={!canToggleMock || disabled}
            onChange={(e) => onToggleMock(e.target.checked)}
            className="accent-[var(--color-phosphor)]"
          />
          mock stream
        </label>
      </div>
    </form>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="mb-1.5 flex items-baseline justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-widest text-[var(--color-ink-dim)]">
          {label}
        </span>
      </div>
      {children}
      <p className="mt-1 text-[10px] text-[var(--color-ink-faint)]">{hint}</p>
    </label>
  );
}
