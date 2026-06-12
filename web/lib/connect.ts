// Connection layer (CLIENT only). Unifies the two demo paths from PLAN-UI §4:
//
//   MOCK   : built-in timer-driven §5 stream (no backend needed).
//   BACKEND: POST {backend}/audits -> { auditId, streamToken }
//            then EventSource GET {backend}/audits/:id/events?token=...
//
// SSE is consumed by the client DIRECTLY from the Render origin — never proxied
// through a Next route handler (PLAN-UI §4 hard rule). No Bun/Node APIs here.

import type { AuditEvent, EventType } from "./protocol";
import { startMockStream, type MockHandle } from "./mock-stream";

export interface AuditInput {
  githubUrl: string;
  endpoint: string;
}

export interface SubscribeCallbacks {
  onEvent: (ev: AuditEvent) => void;
  onError: (message: string) => void;
  // Called when POST /audits returns 402 (x402 gate). The UI shows a pay
  // affordance; retrying with `payment: "demo"` sends X-PAYMENT: demo.
  onPaymentRequired?: () => void;
  // Called once the backend audit is minted (real path only). Lets the UI keep
  // the streamToken for token-authed follow-up calls (e.g. file-issue).
  onStarted?: (info: { auditId: string; streamToken: string }) => void;
}

export interface Subscription {
  close: () => void;
}

// Payment mode for a backend audit. `demo` sends the X-PAYMENT: demo header
// (demo-mode acceptance per PLAN-UI §3). `undefined` = unpaid (may 402).
export type PaymentMode = "demo" | undefined;

const EVENT_TYPES: EventType[] = [
  "audit.start",
  "agent.start",
  "agent.gate",
  "agent.finding",
  "agent.clean",
  "agent.done",
  "agent.error",
  "audit.complete",
  "report.ready",
];

export function backendUrl(): string | null {
  const raw = process.env.NEXT_PUBLIC_AUDIT_BACKEND_URL;
  if (!raw || raw.trim() === "") return null;
  return raw.replace(/\/+$/, "");
}

export function isMockMode(): boolean {
  // Explicit opt-in to mock, OR no backend configured (dev default).
  if (process.env.NEXT_PUBLIC_MOCK === "1") return true;
  return backendUrl() === null;
}

// Subscribe with the built-in mock stream.
export function subscribeMock(
  input: AuditInput,
  cb: SubscribeCallbacks,
): Subscription {
  const target = input.endpoint || input.githubUrl || "seeded://demo-target";
  let handle: MockHandle | null = null;
  try {
    handle = startMockStream(target, cb.onEvent);
  } catch (e) {
    cb.onError(e instanceof Error ? e.message : "mock stream failed");
  }
  return {
    close: () => handle?.cancel(),
  };
}

// Subscribe to the real Render backend per §4. Async because it must POST first.
// `payment` controls the x402 gate: undefined = unpaid (may 402), "demo" = send
// X-PAYMENT: demo (demo-mode acceptance).
export function subscribeBackend(
  input: AuditInput,
  cb: SubscribeCallbacks,
  payment?: PaymentMode,
): Subscription {
  const base = backendUrl();
  let es: EventSource | null = null;
  let closed = false;

  if (!base) {
    cb.onError("NEXT_PUBLIC_AUDIT_BACKEND_URL is not set");
    return { close: () => {} };
  }

  const handlers: Array<[EventType, (e: MessageEvent) => void]> = [];

  (async () => {
    let auditId: string;
    let streamToken: string;
    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
      };
      // x402: demo-mode payment is negotiated ONLY here, in POST /audits
      // (never on the SSE GET) — PLAN-UI §4.
      if (payment === "demo") headers["X-PAYMENT"] = "demo";

      const res = await fetch(`${base}/audits`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          githubUrl: input.githubUrl || undefined,
          endpoint: input.endpoint || undefined,
        }),
      });
      if (res.status === 402) {
        // Surface a pay affordance instead of a hard error.
        if (cb.onPaymentRequired) cb.onPaymentRequired();
        else cb.onError("payment required (x402) — backend returned 402");
        return;
      }
      if (!res.ok) {
        cb.onError(`backend POST /audits failed (${res.status})`);
        return;
      }
      const json = (await res.json()) as {
        auditId?: string;
        streamToken?: string;
      };
      if (!json.auditId || !json.streamToken) {
        cb.onError("backend did not return auditId/streamToken");
        return;
      }
      auditId = json.auditId;
      streamToken = json.streamToken;
      cb.onStarted?.({ auditId, streamToken });
    } catch (e) {
      cb.onError(
        e instanceof Error ? `connect failed: ${e.message}` : "connect failed",
      );
      return;
    }

    if (closed) return;

    const url = `${base}/audits/${encodeURIComponent(
      auditId,
    )}/events?token=${encodeURIComponent(streamToken)}`;

    es = new EventSource(url);

    const parse = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as AuditEvent;
        cb.onEvent(data);
      } catch {
        // ignore malformed frame; the reducer is the trust boundary anyway.
      }
    };

    for (const t of EVENT_TYPES) {
      const h = (e: MessageEvent) => parse(e);
      es.addEventListener(t, h as EventListener);
      handlers.push([t, h]);
    }
    // Also handle unnamed "message" frames as a fallback.
    es.onmessage = parse;

    es.onerror = () => {
      // EventSource auto-reconnects with Last-Event-ID; surface transient note
      // only if the connection is fully closed.
      if (es && es.readyState === EventSource.CLOSED && !closed) {
        cb.onError("stream connection closed");
      }
    };
  })();

  return {
    close: () => {
      closed = true;
      if (es) {
        for (const [t, h] of handlers) {
          es.removeEventListener(t, h as EventListener);
        }
        es.close();
      }
    },
  };
}

// Single entry point the UI calls. Picks mock vs backend per env/toggle.
export function subscribeAudit(
  input: AuditInput,
  cb: SubscribeCallbacks,
  forceMock?: boolean,
  payment?: PaymentMode,
): Subscription {
  if (forceMock || isMockMode()) {
    return subscribeMock(input, cb);
  }
  return subscribeBackend(input, cb, payment);
}

// ---- Backend read endpoints (used only when a backend is configured) ----

export interface HistoryEntry {
  auditId: string;
  target: string;
  ts: string;
  severityCounts: Record<string, number>;
}

// GET /history — recent audits. Returns [] on any failure (degrade silently;
// history is an enrichment, not the required path).
export async function fetchHistory(): Promise<HistoryEntry[]> {
  const base = backendUrl();
  if (!base) return [];
  try {
    const res = await fetch(`${base}/history`, { method: "GET" });
    if (!res.ok) return [];
    const json = (await res.json()) as unknown;
    // Accept either a bare array (frozen contract) or { audits: [...] }
    // (the in-memory/ClickHouse backend wraps it). Be tolerant of both.
    const rows: unknown[] = Array.isArray(json)
      ? json
      : json && typeof json === "object" && Array.isArray((json as { audits?: unknown }).audits)
        ? ((json as { audits: unknown[] }).audits)
        : [];
    return rows
      .filter((e): e is HistoryEntry => !!e && typeof e === "object")
      .map((e) => ({
        auditId: String((e as HistoryEntry).auditId ?? ""),
        target: String((e as HistoryEntry).target ?? ""),
        ts: String((e as HistoryEntry).ts ?? ""),
        severityCounts:
          (e as HistoryEntry).severityCounts &&
          typeof (e as HistoryEntry).severityCounts === "object"
            ? (e as HistoryEntry).severityCounts
            : {},
      }));
  } catch {
    return [];
  }
}

export type FileIssueResult =
  | { ok: true; issueUrl: string }
  | { ok: true; degraded: true; payload: unknown }
  | { ok: false; error: string };

// POST /audits/:id/file-issue — Composio GitHub-issue action. Returns either a
// live issue URL (https only) or a degraded preview payload. Auth by the
// streamToken minted at POST /audits (same gate as the SSE stream).
export async function fileIssue(
  auditId: string,
  streamToken: string,
): Promise<FileIssueResult> {
  const base = backendUrl();
  if (!base) return { ok: false, error: "no backend configured" };
  try {
    const res = await fetch(
      `${base}/audits/${encodeURIComponent(auditId)}/file-issue?token=${encodeURIComponent(
        streamToken,
      )}`,
      { method: "POST", headers: { "content-type": "application/json" } },
    );
    if (!res.ok) {
      return { ok: false, error: `file-issue failed (${res.status})` };
    }
    const json = (await res.json()) as {
      issueUrl?: string;
      degraded?: boolean;
      payload?: unknown;
    };
    if (json.degraded) {
      return { ok: true, degraded: true, payload: json.payload ?? null };
    }
    if (typeof json.issueUrl === "string") {
      return { ok: true, issueUrl: json.issueUrl };
    }
    return { ok: false, error: "file-issue returned no issueUrl" };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "file-issue request failed",
    };
  }
}
