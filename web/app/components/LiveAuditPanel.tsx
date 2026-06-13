"use client";

// THE CENTERPIECE — live 6-agent panel (PLAN-UI §5).
// Opens a subscription (mock or real backend EventSource), folds §5 events into
// per-agent card state keyed by agentId (ignoring out-of-order/duplicate seq),
// and renders 6 animated cards + a live audit trail. On audit.complete it
// renders the static structured report.

import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import {
  type AuditInput,
  type PaymentMode,
  type PaymentRequired402,
  subscribeAudit,
  type Subscription,
  isMockMode,
  backendUrl,
} from "@/lib/connect";
import {
  type AuditState,
  applyEvent,
  initialState,
} from "@/lib/audit-state";
import type { AuditEvent } from "@/lib/protocol";
import { InputForm } from "./InputForm";
import { AgentCard } from "./AgentCard";
import { AuditTrail } from "./AuditTrail";
import { StaticReport } from "./StaticReport";
import { C1Report } from "./C1Report";
import { GithubProvenance } from "./GithubProvenance";
import { HistoryPanel } from "./HistoryPanel";
import { FileIssueButton } from "./FileIssueButton";

type Action =
  | { kind: "event"; ev: AuditEvent }
  | { kind: "reset" }
  | { kind: "error"; message: string };

function reducer(state: AuditState, action: Action): AuditState {
  switch (action.kind) {
    case "event":
      return applyEvent(state, action.ev);
    case "reset":
      return initialState();
    case "error":
      return { ...state, status: "error" };
    default:
      return state;
  }
}

export function LiveAuditPanel() {
  const [state, dispatch] = useReducer(reducer, undefined, initialState);
  const [running, setRunning] = useState(false);
  const [started, setStarted] = useState(false);
  const [connError, setConnError] = useState<string | null>(null);
  // x402: set when POST /audits returns 402; the UI shows a pay affordance.
  const [paymentRequired, setPaymentRequired] = useState(false);
  // Parsed 402 body (carries the Cash App accepts entry + one-shot note).
  // Refreshed on every 402, so a stale-note retry auto-shows the new note.
  const [payment402, setPayment402] = useState<PaymentRequired402 | undefined>(
    undefined,
  );
  const [paid, setPaid] = useState(false);
  // C1 render fell back to the static report (invalid spec / render error).
  const [c1Fallback, setC1Fallback] = useState(false);
  // streamToken from POST /audits — needed to auth the file-issue call.
  const [streamToken, setStreamToken] = useState<string | null>(null);
  const [lastInput, setLastInput] = useState<AuditInput>({
    githubUrl: "",
    endpoint: "",
  });

  // mock toggle: defaults to env-driven mock mode; only meaningful when a
  // backend URL exists (otherwise we are always mock).
  const hasBackend = backendUrl() !== null;
  const [mockMode, setMockMode] = useState(true);
  useEffect(() => {
    setMockMode(isMockMode());
  }, []);

  const subRef = useRef<Subscription | null>(null);

  const stop = useCallback(() => {
    subRef.current?.close();
    subRef.current = null;
  }, []);

  useEffect(() => () => stop(), [stop]);

  // when the stream reaches a terminal state, mark not-running. On a terminal
  // error (e.g. audit.error) also close the subscription so the EventSource
  // doesn't keep auto-reconnecting to a dead stream. (Not on "complete" —
  // report.ready still arrives after audit.complete.)
  useEffect(() => {
    if (state.status === "complete" || state.status === "error") {
      setRunning(false);
      if (state.status === "error") stop();
    }
  }, [state.status, stop]);

  const startSubscription = useCallback(
    (input: AuditInput, forceMock: boolean, payment: PaymentMode) => {
      stop();
      dispatch({ kind: "reset" });
      setConnError(null);
      setPaymentRequired(false);
      setC1Fallback(false);
      setStreamToken(null);
      setStarted(true);
      setRunning(true);

      subRef.current = subscribeAudit(
        input,
        {
          onEvent: (ev) => dispatch({ kind: "event", ev }),
          onError: (message) => {
            setConnError(message);
            dispatch({ kind: "error", message });
          },
          onStarted: ({ streamToken: tok }) => setStreamToken(tok),
          onPaymentRequired: (body) => {
            // x402 gate hit — surface the pay affordance, not a hard error.
            // Always store the fresh body: notes are one-shot, so a stale-note
            // retry 402s again with a NEW note we must show.
            setRunning(false);
            setPaid(false);
            setPayment402(body);
            setPaymentRequired(true);
          },
        },
        forceMock,
        payment,
      );
    },
    [stop],
  );

  const run = useCallback(
    (input: AuditInput, forceMock: boolean) => {
      setLastInput(input);
      setPaid(false);
      startSubscription(input, forceMock, undefined);
    },
    [startSubscription],
  );

  // Pay the x402 demo gate and re-run with X-PAYMENT: demo.
  const payAndRun = useCallback(() => {
    setPaid(true);
    startSubscription(lastInput, false, "demo");
  }, [lastInput, startSubscription]);

  // Cash App accepts entry from the 402 body (defensive — may be absent).
  const cashAccept = payment402?.accepts?.find((a) => a?.scheme === "cashapp");
  const cashNote =
    typeof cashAccept?.extra?.paymentNote === "string"
      ? cashAccept.extra.paymentNote
      : null;
  const cashPayUrl =
    typeof cashAccept?.extra?.payUrl === "string"
      ? cashAccept.extra.payUrl
      : null;
  const cashTag = cashAccept?.payTo ?? "$mcpauditor";

  // "I've sent it" — retry the audit with the cashapp note. If the note is
  // stale, the backend 402s again and onPaymentRequired refreshes the panel.
  const payCashAppAndRun = useCallback(() => {
    if (!cashNote) return;
    startSubscription(lastInput, false, { kind: "cashapp", note: cashNote });
  }, [cashNote, lastInput, startSubscription]);

  const sourceLabel = mockMode || !hasBackend ? "MOCK STREAM" : "RENDER BACKEND";

  const showReport = state.status === "complete" && state.reportReady;
  const report = state.report;
  // Use the C1 generative renderer only when the backend marked the report
  // mode='c1' AND a spec is present AND the Crayon render hasn't fallen back.
  const useC1 = !!report && report.mode === "c1" && report.spec != null && !c1Fallback;

  return (
    <div className="space-y-6">
      <InputForm
        onRun={run}
        disabled={running}
        mockMode={mockMode}
        onToggleMock={setMockMode}
        canToggleMock={hasBackend}
      />

      {/* History is a backend-only enrichment (PLAN-UI §3). */}
      {hasBackend && !mockMode && <HistoryPanel />}

      {/* x402 pay affordance — shown when POST /audits returned 402. */}
      {paymentRequired && !paid && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-[var(--color-amber)] bg-[var(--color-panel)] px-4 py-3">
            <span className="text-[12px] text-[var(--color-amber)]">
              x402 · payment required to run this audit
            </span>
            <button
              type="button"
              onClick={payAndRun}
              className="ml-auto inline-flex items-center gap-2 rounded bg-[var(--color-amber)] px-3 py-1.5 text-[12px] font-bold text-[#1a1206] transition-all hover:brightness-110"
            >
              Pay $0.10 to audit (demo)
            </button>
          </div>

          {/* Cash App pay panel — rendered when the 402 offers a cashapp scheme */}
          {cashAccept && cashNote && (
            <div className="rounded-lg border border-[#00D632] bg-[var(--color-panel)] px-4 py-4">
              <h3 className="text-[13px] font-bold tracking-wide text-[#00D632]">
                Pay with Cash App
              </h3>
              <div className="mt-3 flex flex-wrap items-start gap-5">
                {cashPayUrl && (
                  /* eslint-disable-next-line @next/next/no-img-element -- external zero-dep QR for demo */
                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(cashPayUrl)}`}
                    alt={`Cash App QR code for ${cashTag}`}
                    width={180}
                    height={180}
                    className="rounded border border-[var(--color-line)] bg-white"
                  />
                )}
                <div className="min-w-[240px] flex-1 space-y-2 text-[12px]">
                  <p className="text-[var(--color-ink-dim)]">
                    Send{" "}
                    <span className="font-bold text-[#00D632]">$0.10</span> to{" "}
                    <span className="font-mono font-bold text-[#00D632]">
                      {cashTag}
                    </span>
                  </p>
                  {cashPayUrl && (
                    <p>
                      <a
                        href={cashPayUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-[11px] text-[#00D632] underline underline-offset-2 hover:brightness-110"
                      >
                        {cashPayUrl}
                      </a>
                    </p>
                  )}
                  <p className="text-[11px] text-[var(--color-ink-faint)]">
                    Include this note with your Cash App payment:
                  </p>
                  <code className="block w-fit select-all rounded border border-[#00D632] bg-[#00D632]/10 px-3 py-2 font-mono text-[14px] font-bold tracking-wider text-[#00D632]">
                    {cashNote}
                  </code>
                  <button
                    type="button"
                    onClick={payCashAppAndRun}
                    className="mt-2 inline-flex items-center gap-2 rounded bg-[#00D632] px-3 py-1.5 text-[12px] font-bold text-[#062e12] transition-all hover:brightness-110"
                  >
                    I&apos;ve sent it — unlock audit
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {paid && (
        <div className="rounded border border-[var(--color-phosphor)] bg-[var(--color-panel)] px-3 py-1.5 text-[11px] text-[var(--color-phosphor)]">
          x402 · payment accepted (demo mode) — X-PAYMENT: demo
        </div>
      )}

      {started && (
        <>
          {/* status bar */}
          <div className="flex flex-wrap items-center gap-3">
            <StatusPill status={state.status} />
            <span className="rounded border border-[var(--color-line)] px-2 py-1 text-[10px] uppercase tracking-widest text-[var(--color-ink-faint)]">
              source · {sourceLabel}
            </span>
            {state.auditId && (
              <span className="font-mono text-[10px] text-[var(--color-ink-faint)]">
                audit {state.auditId}
              </span>
            )}
            <div className="ml-auto">
              <GithubProvenance githubUrl={lastInput.githubUrl} />
            </div>
          </div>

          {/* terminal audit failure (audit.error) — the run is over. */}
          {state.auditError && (
            <div className="rounded-lg border border-[var(--color-amber)] bg-[var(--color-panel)] px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-widest text-[var(--color-amber)]">
                  audit failed
                </span>
                {state.auditError.code && (
                  <span className="rounded border border-[var(--color-amber)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-amber)]">
                    {state.auditError.code}
                  </span>
                )}
              </div>
              {/* UNTRUSTED backend text — plain-text children only (React escapes). */}
              <p className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[12px] text-[var(--color-ink-dim)]">
                {state.auditError.message}
              </p>
              <p className="mt-1.5 text-[11px] text-[var(--color-ink-faint)]">
                this run is over — adjust the target above and start a new audit
              </p>
            </div>
          )}

          {connError && !state.auditError && (
            <div className="rounded border border-[var(--color-amber)] bg-[var(--color-panel)] px-3 py-2 text-[12px] text-[var(--color-amber)]">
              connection: {connError}
            </div>
          )}

          {/* 6 agent cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {state.order.map((id) => (
              <AgentCard key={id} agent={state.agents[id]} />
            ))}
          </div>

          {/* audit trail */}
          <AuditTrail log={state.log} />

          {/* report on completion — C1 generative when available, else static */}
          {showReport && (
            <>
              {useC1 ? (
                <C1Report
                  spec={report!.spec}
                  onFail={() => setC1Fallback(true)}
                />
              ) : (
                <StaticReport
                  findings={state.findings}
                  model={report?.model ?? null}
                  target={state.target}
                />
              )}

              {c1Fallback && (
                <p className="text-[10px] text-[var(--color-ink-faint)]">
                  generative renderer unavailable — showing the static report
                </p>
              )}

              {/* Composio: file this audit as a GitHub issue (backend only) */}
              {hasBackend && !mockMode && state.auditId && streamToken && (
                <FileIssueButton
                  auditId={state.auditId}
                  streamToken={streamToken}
                />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: AuditState["status"] }) {
  const map: Record<
    AuditState["status"],
    { label: string; color: string; dot: boolean }
  > = {
    connecting: { label: "CONNECTING", color: "var(--color-cyan)", dot: true },
    live: { label: "LIVE", color: "var(--color-phosphor)", dot: true },
    complete: { label: "COMPLETE", color: "var(--color-ink-dim)", dot: false },
    error: { label: "ERROR", color: "var(--color-amber)", dot: false },
  };
  const m = map[status];
  return (
    <span
      className="inline-flex items-center gap-2 rounded border px-2.5 py-1 text-[10px] font-bold tracking-widest"
      style={{ borderColor: m.color, color: m.color }}
    >
      {m.dot && (
        <span
          className="inline-block h-2 w-2 rounded-full pulse-ring"
          style={{ backgroundColor: m.color }}
        />
      )}
      {m.label}
    </span>
  );
}
