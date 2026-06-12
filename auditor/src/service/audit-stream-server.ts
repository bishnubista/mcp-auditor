#!/usr/bin/env bun
// audit-stream-server.ts — the LIVE multi-agent streaming backend (UI1, P1).
//
// WHAT THIS IS
// ------------
// A Bun.serve HTTP service that lets a browser watch our six SAFE-T probers hunt
// a target MCP server in real time over Server-Sent Events (PLAN-UI.md §4/§5).
// It is a SIBLING of x402-audit-server.ts: same x402 payment gate semantics, but
// instead of a single blocking POST that returns a finished report, it splits the
// lifecycle into:
//
//   POST /audits             -> x402 gate -> mint {auditId, streamToken}; kick off
//                               the governed audit ASYNC against the SEEDED target.
//   GET  /audits/:id/events  -> SSE; auth by streamToken; emits §5 events live;
//                               supports Last-Event-ID replay from a ring buffer.
//   GET  /audits/:id         -> final JSON snapshot {status, findings, events}.
//   GET  /health             -> 200.
//
// WHY IN-PROCESS (not a subprocess like x402-audit-server)
// --------------------------------------------------------
// To stream per-agent lifecycle events as they happen, we run the governed
// prober fan-out IN THIS PROCESS via runProbers(..., onEvent) — the new additive
// hook in src/probers/runner.ts. Each raw runner event is WRAPPED here into the
// §5 wire envelope (auditId, runId, seq, ts, type, ...). The runner stays
// ignorant of seq/id so the demo:local gate (subprocess path) is unaffected.
//
// SEEDED TARGET ONLY (P1)
// -----------------------
// For P1 we ALWAYS audit the seeded stdio target (the deterministic demo target
// server), regardless of any `endpoint` in the request body. Remote MCP targets
// + SSRF admission are UI2's later wiring — see the TODO(UI2) marker in
// startAudit() where admitTarget() + the HTTP MCP client plug in.
//
// SECURITY / TRUST BOUNDARY (PLAN-UI.md §6)
// -----------------------------------------
// The target's tool output (evidence) is UNTRUSTED. Every evidenceExcerpt and
// message that reaches a client is HTML/JSON-escaped and TRUNCATED here before it
// is placed in an SSE frame, so a poisoned target cannot inject markup/control
// data into the stream. We never echo raw target text verbatim.
//
// DETERMINISM: seq is a per-audit MONOTONIC counter assigned at emit (never
// Date.now/Math.random). auditId is a monotonic counter + sha hash. `ts` uses
// new Date().toISOString() which is allowed in the Bun runtime.

import { createHash, randomBytes } from "node:crypto";

import { McpClient, type ToolInfo, type ToolCallResult } from "../mcp-client.ts";
import { McpHttpClient } from "../mcp-http-client.ts";
import { admitTarget } from "../net/admit.ts";
import {
  runProbers,
  buildPolicy,
  type RunnerAgentEvent,
} from "../probers/runner.ts";
import type { ProbePolicy } from "../governance/index.ts";
import {
  buildReportModel,
  type ReportModel,
  type RawFinding,
} from "../thesys/report-model.ts";
import { renderWithC1 } from "../thesys/c1.ts";

// ---------------------------------------------------------------------------
// Config (env-driven; safe local defaults). No secrets.
// ---------------------------------------------------------------------------
const PORT = Number(process.env.AUDIT_STREAM_PORT ?? process.env.PORT ?? 8910);

// CORS allowlist. Default '*' for local dev; in deploy set ALLOWED_ORIGIN to the
// Vercel origin (PLAN-UI.md §4: CORS allowlist the Vercel origin only).
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN ?? "*";

// The seeded stdio target — same command demo-local.ts / x402-server use.
const SERVER_ID = "target-local";
const ROOT_FROM_HERE = new URL("../../../", import.meta.url); // -> mcp-auditor/
const SEEDED_TARGET_PATH = new URL("target-server/src/index.ts", ROOT_FROM_HERE)
  .pathname;
const TARGET_CMD =
  process.env.DEMO_TARGET_CMD ?? `bun run ${SEEDED_TARGET_PATH}`;

// Ring buffer cap per audit (events are tiny; 1024 is generous for 6 agents).
const RING_CAP = 1024;

// ---------------------------------------------------------------------------
// §5 SSE wire envelope. Every event carries auditId, runId, seq, ts, type, ...
// ---------------------------------------------------------------------------
type WireEvent = {
  auditId: string;
  runId: string;
  seq: number;
  ts: string;
  type: string;
  [k: string]: unknown;
};

type AuditStatus = "running" | "complete" | "error";

interface AuditFinding {
  agentId: string;
  safeT: string;
  tool: string;
  severity: string;
  evidenceExcerpt: string;
}

// The minimal MCP client surface used by startAudit(). Both McpClient (stdio,
// seeded default) and McpHttpClient (admitted remote) satisfy it, so the run
// loop is identical regardless of which transport the request selected.
interface AuditMcpClient {
  connect(): Promise<void>;
  listTools(): Promise<ToolInfo[]>;
  callTool(name: string, args: unknown): Promise<ToolCallResult>;
  close(): Promise<void>;
}

// UI3 — the completed report attached to an audit (always carries the bounded
// model so the UI can render the static report even in c1 mode).
type AuditReport = {
  mode: "c1" | "static";
  model: ReportModel;
  spec?: unknown; // present only when mode === "c1" (validated C1 spec)
  reason?: string; // why we fell back to static (no key / schema / etc.)
};

interface AuditState {
  auditId: string;
  runId: string;
  streamToken: string;
  status: AuditStatus;
  seq: number; // monotonic per-audit event counter
  ring: WireEvent[]; // bounded replay buffer
  findings: AuditFinding[];
  // Live subscribers: each gets wire events pushed as they are emitted.
  subscribers: Set<(e: WireEvent) => void>;
  createdSeq: number; // for auditId minting context
  // UI5a additive fields.
  target: string; // human label for the audited target (seeded id or remote host)
  endpoint?: string; // raw remote endpoint, if one was admitted
  createdTs: string; // ISO start time, for history
  report?: AuditReport; // populated on completion (UI3)
  // True once the audit has emitted its FINAL event (report.ready after a
  // successful run, or audit.error). The SSE stream stays open until this so
  // live consumers receive report.ready. "complete" status alone is not final:
  // report.ready is emitted shortly after audit.complete.
  finalized: boolean;
}

// In-memory audit registry.
const audits = new Map<string, AuditState>();

// In-memory history (the GET /history fallback when ClickHouse is unreachable).
// Newest-first, bounded. Each entry is the bounded summary the dashboard needs.
type HistoryEntry = {
  auditId: string;
  target: string;
  ts: string;
  severityCounts: Record<string, number>;
};
const HISTORY_CAP = 200;
const historyMem: HistoryEntry[] = [];

// Monotonic counters — NO Date.now()/Math.random() for id minting.
let auditCounter = 0;
let runCounter = 0;

// ---------------------------------------------------------------------------
// Untrusted-text hardening: escape + truncate anything sourced from the target
// before it enters an SSE frame. (PLAN-UI.md §6 trust boundary.)
// ---------------------------------------------------------------------------
const EVIDENCE_MAX = 240;

function escapeUntrusted(s: unknown, max = EVIDENCE_MAX): string {
  const raw = typeof s === "string" ? s : String(s ?? "");
  // Strip control chars (incl. the CR/LF that would break SSE framing), collapse
  // whitespace, escape HTML-significant chars, then truncate. Control chars are
  // removed by code point (avoids literal control bytes in this source file).
  const stripped = Array.from(raw)
    .map((ch) => {
      const cp = ch.codePointAt(0) ?? 0;
      return cp < 0x20 || cp === 0x7f ? " " : ch;
    })
    .join("");
  const cleaned = stripped
    .replace(/[ \t\n\r]+/g, " ")
    .trim()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

// ---------------------------------------------------------------------------
// id minting — monotonic counter + sha hash (deterministic, no clock/random).
// ---------------------------------------------------------------------------
function mintAuditId(): string {
  const n = ++auditCounter;
  const h = createHash("sha256")
    .update(`audit:${n}:${SERVER_ID}`)
    .digest("hex")
    .slice(0, 10);
  return `aud_${String(n).padStart(4, "0")}_${h}`;
}

function mintRunId(auditId: string): string {
  const n = ++runCounter;
  const h = createHash("sha256")
    .update(`run:${n}:${auditId}`)
    .digest("hex")
    .slice(0, 8);
  return `run_${String(n).padStart(4, "0")}_${h}`;
}

function mintStreamToken(): string {
  // SECURITY: CSPRNG — 256 bits of unpredictable entropy. This token is the SOLE
  // bearer auth for a per-audit SSE stream + file-issue, so it must NOT be derived
  // from counters/pid/ids (all observable/guessable → stream-hijack & IDOR). Use
  // randomBytes, never a hash of predictable inputs.
  return randomBytes(32).toString("hex");
}

// ---------------------------------------------------------------------------
// Emit: stamp seq/ts and fan out to ring buffer + live subscribers.
// ---------------------------------------------------------------------------
function emit(
  st: AuditState,
  type: string,
  data: Record<string, unknown>,
): WireEvent {
  const seq = ++st.seq;
  const evt: WireEvent = {
    auditId: st.auditId,
    runId: st.runId,
    seq,
    ts: new Date().toISOString(),
    type,
    ...data,
  };
  st.ring.push(evt);
  if (st.ring.length > RING_CAP) st.ring.shift();
  for (const push of st.subscribers) {
    try {
      push(evt);
    } catch {
      // A broken subscriber must not break emission for others.
    }
  }
  return evt;
}

// ---------------------------------------------------------------------------
// UI5a — report building (UI3 trust boundary) on completion.
// ---------------------------------------------------------------------------
// Map an in-memory AuditFinding to the RawFinding shape buildReportModel wants.
// evidenceExcerpt is already escaped here; buildReportModel sanitizes again
// (defense in depth) and labels it untrusted.
function toRawFindings(st: AuditState): RawFinding[] {
  return st.findings.map((f) => ({
    safeT: f.safeT,
    tool: f.tool,
    severity: f.severity,
    evidence: f.evidenceExcerpt,
    // probe is derived from the agent id (our own field). buildReportModel maps
    // unknown probe ids to a sanitized class name, so this is always safe.
    probe: f.agentId.replace(/^prober-/, ""),
  }));
}

// Build the bounded ReportModel and try C1; ALWAYS return a report carrying the
// model (static-renderable) so the UI never lacks a report. Never throws.
async function buildAuditReport(st: AuditState): Promise<AuditReport> {
  const model = buildReportModel(toRawFindings(st), {
    target: st.target,
    scanTs: st.createdTs,
    auditId: st.auditId,
  });
  try {
    const c1 = await renderWithC1(model);
    if (c1.ok) {
      return { mode: "c1", model, spec: c1.spec };
    }
    return { mode: "static", model, reason: c1.reason };
  } catch (err) {
    // renderWithC1 is contracted never to throw, but stay defensive.
    return {
      mode: "static",
      model,
      reason: err instanceof Error ? err.message : "c1_error",
    };
  }
}

// ---------------------------------------------------------------------------
// UI5a — ClickHouse persistence (reuse @clickhouse/client + graceful fallback,
// mirroring store/clickhouse.ts). NEVER crashes; always records to in-memory
// history so GET /history works even when ClickHouse is unreachable.
// ---------------------------------------------------------------------------
const CH_TABLE = "mcp_findings";
const CH_CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS ${CH_TABLE}
(
    ts        DateTime,
    safeT     LowCardinality(String),
    tool      LowCardinality(String),
    severity  Enum8('critical' = 1, 'high' = 2, 'medium' = 3, 'low' = 4, 'info' = 5),
    probe     String,
    prober    String,
    evidence  String
)
ENGINE = MergeTree
ORDER BY (severity, safeT, ts)
`.trim();

function chDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "1970-01-01 00:00:00";
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "").replace("Z", "");
}

function severityCountsOf(st: AuditState): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of st.findings) {
    const s = (f.severity || "low").toLowerCase();
    counts[s] = (counts[s] ?? 0) + 1;
  }
  return counts;
}

// Try a live ClickHouse insert; returns true on success, false on any failure.
// Only attempts when CLICKHOUSE_URL is configured (avoids dialing localhost in
// the demo and slowing completion). Never throws.
async function tryClickHouseInsert(st: AuditState): Promise<boolean> {
  const url = process.env.CLICKHOUSE_URL;
  if (!url) return false;
  try {
    const { createClient, ClickHouseLogLevel } = await import("@clickhouse/client");
    const username = process.env.CLICKHOUSE_USER;
    const password = process.env.CLICKHOUSE_PASSWORD;
    const database = process.env.CLICKHOUSE_DATABASE;
    const client = createClient({
      url,
      ...(username ? { username } : {}),
      ...(password ? { password } : {}),
      ...(database ? { database } : {}),
      request_timeout: 5000,
      log: { level: ClickHouseLogLevel.OFF },
    });
    try {
      const pong = await client.ping();
      if (!pong.success) throw new Error("ping failed");
      await client.command({ query: CH_CREATE_TABLE_SQL });
      const rows = st.findings.map((f) => ({
        ts: chDateTime(st.createdTs),
        safeT: f.safeT,
        tool: f.tool,
        severity: (f.severity || "low").toLowerCase(),
        probe: f.agentId.replace(/^prober-/, ""),
        prober: f.agentId,
        evidence: f.evidenceExcerpt,
      }));
      if (rows.length > 0) {
        await client.insert({ table: CH_TABLE, values: rows, format: "JSONEachRow" });
      }
      await client.close().catch(() => {});
      return true;
    } catch (e) {
      await client.close().catch(() => {});
      console.error(`[stream] clickhouse insert failed: ${(e as Error).message ?? String(e)}`);
      return false;
    }
  } catch (e) {
    console.error(`[stream] clickhouse unavailable: ${(e as Error).message ?? String(e)}`);
    return false;
  }
}

// Persist the audit: always push to in-memory history; additionally insert into
// ClickHouse when configured. Never throws.
async function persistAudit(st: AuditState): Promise<void> {
  const entry: HistoryEntry = {
    auditId: st.auditId,
    target: st.target,
    ts: st.createdTs,
    severityCounts: severityCountsOf(st),
  };
  historyMem.unshift(entry);
  if (historyMem.length > HISTORY_CAP) historyMem.length = HISTORY_CAP;
  await tryClickHouseInsert(st);
}

// Read recent history. Prefer ClickHouse when configured + reachable; else the
// in-memory list. Returns a bounded summary list. Never throws.
async function readHistory(limit = 50): Promise<{ source: string; audits: HistoryEntry[] }> {
  const url = process.env.CLICKHOUSE_URL;
  if (url) {
    try {
      const { createClient, ClickHouseLogLevel } = await import("@clickhouse/client");
      const username = process.env.CLICKHOUSE_USER;
      const password = process.env.CLICKHOUSE_PASSWORD;
      const database = process.env.CLICKHOUSE_DATABASE;
      const client = createClient({
        url,
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
        ...(database ? { database } : {}),
        request_timeout: 5000,
        log: { level: ClickHouseLogLevel.OFF },
      });
      try {
        const pong = await client.ping();
        if (!pong.success) throw new Error("ping failed");
        // The findings table has no auditId column; we surface a severity rollup
        // across persisted findings as the ClickHouse-backed history view.
        const rs = await client.query({
          query: `SELECT severity AS key, count() AS count FROM ${CH_TABLE} GROUP BY severity`,
          format: "JSONEachRow",
        });
        const rows = (await rs.json<{ key: string; count: number }>()).reduce(
          (acc, r) => {
            acc[String(r.key)] = Number(r.count);
            return acc;
          },
          {} as Record<string, number>,
        );
        await client.close().catch(() => {});
        // Blend: in-memory per-audit rows (rich) with a ClickHouse aggregate row
        // so the dashboard shows both the live list and persisted totals.
        const aggregate: HistoryEntry = {
          auditId: "clickhouse-aggregate",
          target: "(all persisted findings)",
          ts: new Date().toISOString(),
          severityCounts: rows,
        };
        return {
          source: "clickhouse",
          audits: [aggregate, ...historyMem.slice(0, limit)],
        };
      } catch (e) {
        await client.close().catch(() => {});
        console.error(`[stream] clickhouse history failed: ${(e as Error).message ?? String(e)}`);
      }
    } catch (e) {
      console.error(`[stream] clickhouse history unavailable: ${(e as Error).message ?? String(e)}`);
    }
  }
  return { source: "in-memory", audits: historyMem.slice(0, limit) };
}

// ---------------------------------------------------------------------------
// UI5a — Composio file-issue (degraded preview when no key). Reuses the
// GITHUB_CREATE_AN_ISSUE action + degraded-payload shape from actions/composio.ts
// without importing that CLI module. Never throws.
// ---------------------------------------------------------------------------
const COMPOSIO_ACTION_SLUG = "GITHUB_CREATE_AN_ISSUE";
const COMPOSIO_MAX_BODY = 60_000;
const COMPOSIO_DEFAULT_REPO = "bishnubista/mcp-audit-reports";
// Safety rail: live issues may ONLY be filed into a repo with this name.
const COMPOSIO_ALLOWED_REPO_NAME = "mcp-audit-reports";

function resolveComposioRepo(): { owner: string; repo: string; isDefault: boolean } {
  const raw = process.env.COMPOSIO_GITHUB_REPO?.trim();
  const isDefault = !raw || raw.length === 0;
  const candidate = raw && raw.length > 0 ? raw : COMPOSIO_DEFAULT_REPO;
  const normalized = candidate
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const parts = normalized.split("/").filter((p) => p.length > 0);
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    const [o, r] = COMPOSIO_DEFAULT_REPO.split("/") as [string, string];
    return { owner: o, repo: r, isDefault: true };
  }
  return { owner: parts[0], repo: parts[1], isDefault };
}

// Build the issue title/body from the audit's bounded report model (never raw
// target text — evidence is already sanitized + labeled untrusted by the model).
function buildComposioIssue(st: AuditState): { title: string; body: string } {
  const model =
    st.report?.model ??
    buildReportModel(toRawFindings(st), {
      target: st.target,
      scanTs: st.createdTs,
      auditId: st.auditId,
    });
  const sevLabel = model.overallRisk;
  const n = model.totalFindings;
  const title = `MCP Security Audit: ${n} SAFE-T finding${n === 1 ? "" : "s"} on ${st.target} (${sevLabel})`;
  const lines: string[] = [
    `# MCP Security Audit — ${st.target}`,
    "",
    `- Audit: ${st.auditId}`,
    `- Scan: ${model.scanTs}`,
    `- Overall risk: ${model.overallRisk}`,
    `- Findings: ${model.totalFindings} (critical=${model.severityCounts.critical}, high=${model.severityCounts.high}, medium=${model.severityCounts.medium}, low=${model.severityCounts.low})`,
    "",
    "## Findings",
    "",
  ];
  for (const f of model.findings) {
    lines.push(`### ${f.safeT} — ${f.probeClass} (${f.severity})`);
    lines.push(`- Tool: ${f.tool}`);
    lines.push(`- Evidence: ${f.evidenceExcerpt}`);
    lines.push("");
  }
  lines.push(model.untrustedDataNote);
  let body = lines.join("\n");
  if (body.length > COMPOSIO_MAX_BODY) {
    body = `${body.slice(0, COMPOSIO_MAX_BODY)}\n\n> Note: report truncated.`;
  }
  return { title, body };
}

type FileIssueResult =
  | { ok: true; issueUrl: string }
  | { ok: true; degraded: true; payload: unknown; reason: string };

// File the audit report as a GitHub issue via Composio. LIVE when a key + real
// repo are present; otherwise returns a degraded preview payload. Never throws.
async function fileIssueForAudit(st: AuditState): Promise<FileIssueResult> {
  const { owner, repo, isDefault } = resolveComposioRepo();
  const userId = process.env.COMPOSIO_USER_ID?.trim() || "default";
  const connectedAccountId = process.env.COMPOSIO_CONNECTED_ACCOUNT_ID?.trim() || undefined;
  const { title, body } = buildComposioIssue(st);
  const args = { owner, repo, title, body };

  const degraded = (reason: string): FileIssueResult => ({
    ok: true,
    degraded: true,
    reason,
    payload: {
      action: COMPOSIO_ACTION_SLUG,
      mode: "degraded",
      reason,
      entity: {
        userId,
        connectedAccountId: connectedAccountId ?? null,
        authPresent: Boolean(process.env.COMPOSIO_API_KEY),
      },
      sdkCall: {
        method: "composio.tools.execute",
        slug: COMPOSIO_ACTION_SLUG,
        options: {
          userId,
          ...(connectedAccountId ? { connectedAccountId } : {}),
          arguments: { owner, repo, title, body_chars: body.length },
          dangerouslySkipVersionCheck: true,
        },
      },
    },
  });

  const apiKey = process.env.COMPOSIO_API_KEY?.trim();
  if (!apiKey) return degraded("COMPOSIO_API_KEY not set");
  if (isDefault) {
    return degraded("COMPOSIO_GITHUB_REPO is not set — set it explicitly to file a live issue");
  }
  if (repo !== COMPOSIO_ALLOWED_REPO_NAME) {
    return degraded(
      `target repo "${owner}/${repo}" is outside the allowlist — live issues may only be filed into a repo named "${COMPOSIO_ALLOWED_REPO_NAME}"`,
    );
  }
  if (process.env.COMPOSIO_DRY_RUN === "1") {
    return degraded("COMPOSIO_DRY_RUN — built and validated the tool-call without filing a live issue");
  }

  try {
    const { Composio } = await import("@composio/core");
    const composio = new Composio({ apiKey });
    const attempt = async (accountId?: string) => {
      try {
        const r = await composio.tools.execute(COMPOSIO_ACTION_SLUG, {
          userId,
          ...(accountId ? { connectedAccountId: accountId } : {}),
          arguments: args,
          dangerouslySkipVersionCheck: true,
        });
        if (r.error || r.successful === false) {
          return { ok: false as const, err: String(r.error ?? "successful=false") };
        }
        return { ok: true as const, res: r };
      } catch (e) {
        return { ok: false as const, err: e instanceof Error ? e.message : String(e) };
      }
    };
    let outcome = await attempt(connectedAccountId);
    if (!outcome.ok && connectedAccountId) outcome = await attempt(undefined);
    if (!outcome.ok || !outcome.res) {
      return degraded(`live Composio call failed (${outcome.ok ? "no result" : outcome.err})`);
    }
    const data = (outcome.res.data ?? {}) as Record<string, unknown>;
    const issueUrl =
      (typeof data["html_url"] === "string" && data["html_url"]) ||
      (typeof data["url"] === "string" && (data["url"] as string)) ||
      (typeof data["number"] === "number"
        ? `https://github.com/${owner}/${repo}/issues/${data["number"]}`
        : `https://github.com/${owner}/${repo}/issues`);
    return { ok: true, issueUrl: issueUrl as string };
  } catch (e) {
    return degraded(`live Composio call failed (${e instanceof Error ? e.message : String(e)})`);
  }
}

// ---------------------------------------------------------------------------
// #2b — distinguish a REAL remote target from the seeded stdio demo target.
// The seeded path is selected when the endpoint is empty OR a sentinel value
// (`seeded`, `seeded://...`, `demo`). Only a true http(s) URL is "remote" and
// takes the SSRF-admitted McpHttpClient path. This keeps `seeded://demo-target`
// (non-https sentinel) from ever reaching admitTarget, which requires https.
// ---------------------------------------------------------------------------
function isRealRemoteEndpoint(endpoint: string): boolean {
  const e = endpoint.trim().toLowerCase();
  if (e.length === 0) return false;
  if (e === "seeded" || e === "demo") return false;
  if (e.startsWith("seeded://")) return false;
  // Real remote targets are http(s) URLs only; anything else falls through to
  // the seeded stdio target rather than being treated as a remote endpoint.
  return e.startsWith("http://") || e.startsWith("https://");
}

// ---------------------------------------------------------------------------
// The governed audit run (in-process so events stream live).
// ---------------------------------------------------------------------------
async function startAudit(st: AuditState): Promise<void> {
  // UI5a (was TODO UI2 remote target): if the request supplied a real remote
  // `endpoint` that passes SSRF admission, audit THAT via McpHttpClient (which
  // pins the resolved IP + refuses redirects). Otherwise default to the seeded
  // stdio target — the deterministic demo path. Both clients expose the same
  // { connect, listTools, callTool, close } surface so the run loop is identical.
  //
  // #2b SEEDED-SENTINEL: only a REAL http(s) endpoint takes the remote path. An
  // empty endpoint OR a sentinel (`seeded`, `seeded://...`, `demo`) is the seeded
  // stdio demo target and MUST NOT hit admitTarget (which requires https and
  // would reject `seeded://demo-target`, breaking the demo).
  let client: AuditMcpClient;
  if (st.endpoint && isRealRemoteEndpoint(st.endpoint)) {
    // #4 REMOTE-GATE: external targets are opt-in via ENABLE_REMOTE_TARGETS=1.
    // When unset, a real external endpoint is refused with a terminal audit.error
    // and we never connect. The seeded path above is unaffected by this gate.
    if (process.env.ENABLE_REMOTE_TARGETS !== "1") {
      st.status = "error";
      st.finalized = true; // #3: finalize BEFORE the terminal emit
      emit(st, "audit.error", {
        message: "remote targets disabled (set ENABLE_REMOTE_TARGETS=1 to enable external MCP endpoints)",
        code: "remote_disabled",
      });
      return;
    }
    const admitted = await admitTarget(st.endpoint);
    if (!admitted.ok) {
      // Admission failure is a clean, non-crashing audit error (400-style).
      st.status = "error";
      st.finalized = true; // #3: finalize BEFORE the terminal emit
      emit(st, "audit.error", {
        message: escapeUntrusted(`endpoint rejected by SSRF admission: ${admitted.reason}`),
        code: "admission_denied",
      });
      return;
    }
    // The audited host is the bounded human label (admit.host is validated).
    st.target = `${admitted.host}:${admitted.port}`;
    client = new McpHttpClient(st.endpoint);
  } else {
    const parts = TARGET_CMD.split(/\s+/).filter((s) => s.length > 0);
    const command = parts[0];
    if (!command) throw new Error("DEMO_TARGET_CMD is empty");
    const cmdArgs = parts.slice(1);
    client = new McpClient(command, cmdArgs);
  }

  let tools: Awaited<ReturnType<AuditMcpClient["listTools"]>> = [];

  try {
    await client.connect();
    tools = await client.listTools();

    // audit.start carries the target + the 6 prober ids (§5).
    emit(st, "audit.start", {
      target: st.target,
      probers: PROBE_IDS,
      toolCount: tools.length,
    });

    const policy: ProbePolicy = buildPolicy(SERVER_ID, tools);
    const callTool = (tool: string, payload: unknown) =>
      client.callTool(tool, payload);

    // Bridge the runner's RAW typed events into the §5 wire envelope. Untrusted
    // fields (evidenceExcerpt, message) are escaped+truncated here.
    const onEvent = (e: RunnerAgentEvent): void => {
      switch (e.type) {
        case "agent.start":
          emit(st, "agent.start", {
            agentId: e.agentId,
            safeT: e.safeT,
            tool: e.tool,
          });
          break;
        case "agent.gate":
          // §5 surfaces the governance gate verdict (allowed) per agent.
          emit(st, "agent.gate", { agentId: e.agentId, verdict: e.verdict });
          break;
        case "agent.finding": {
          const evidenceExcerpt = escapeUntrusted(e.evidenceExcerpt);
          st.findings.push({
            agentId: e.agentId,
            safeT: e.safeT,
            tool: e.tool,
            severity: e.severity,
            evidenceExcerpt,
          });
          emit(st, "agent.finding", {
            agentId: e.agentId,
            safeT: e.safeT,
            tool: e.tool,
            severity: e.severity,
            evidenceExcerpt, // UNTRUSTED, escaped+truncated, labeled below
            untrusted: true,
          });
          break;
        }
        case "agent.clean":
          emit(st, "agent.clean", { agentId: e.agentId, tool: e.tool });
          break;
        case "agent.done":
          emit(st, "agent.done", { agentId: e.agentId, ms: e.ms });
          break;
        case "agent.error":
          emit(st, "agent.error", {
            agentId: e.agentId,
            message: escapeUntrusted(e.message),
          });
          break;
      }
    };

    // Fan out the six governed probers IN-PROCESS, streaming events live.
    await runProbers(tools, callTool, policy, onEvent);

    // All six probers are terminal (done/error) here — runProbers awaits all.
    st.status = "complete";
    emit(st, "audit.complete", {
      findings: st.findings,
      reportReady: true,
    });

    // UI3 — build the bounded ReportModel (trust boundary) + try C1, then emit a
    // report.ready event. We ALWAYS include the model so the UI can render the
    // static report even when mode === "c1". This runs AFTER audit.complete so
    // the §5 agent sequence is unchanged; SSE consumers close on audit.complete,
    // so report.ready is delivered to live subscribers before that close fires
    // (audit.complete close is deferred a microtick) and is always available in
    // the GET /audits/:id snapshot + ring replay.
    try {
      const report = await buildAuditReport(st);
      st.report = report;
      // #3: report.ready is the FINAL event of a successful run. Mark finalized
      // BEFORE emitting it so any client that connects/replays concurrently with
      // this terminal frame observes a consistent finalized state and the SSE
      // replay path closes instead of hanging on a late Last-Event-ID:0.
      st.finalized = true;
      emit(st, "report.ready", {
        mode: report.mode,
        model: report.model,
        ...(report.spec !== undefined ? { spec: report.spec } : {}),
        ...(report.reason ? { reason: report.reason } : {}),
      });
    } catch (e) {
      // Report enrichment must never fail the audit. report.ready did not emit,
      // so the audit.error below becomes the terminal frame; ensure finalized.
      console.error(`[stream] report build failed: ${(e as Error).message ?? String(e)}`);
      st.status = "error";
      st.finalized = true; // #3: finalize BEFORE the terminal emit
      emit(st, "audit.error", {
        message: escapeUntrusted(
          `report build failed: ${(e as Error).message ?? String(e)}`,
        ),
      });
    }

    // UI5a — persist (ClickHouse when configured; always in-memory history).
    await persistAudit(st);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    st.status = "error";
    st.finalized = true;
    emit(st, "audit.error", { message: escapeUntrusted(message) });
  } finally {
    try {
      await client.close();
    } catch {
      // best-effort
    }
  }
}

// The 6 stable prober ids (PLAN-UI.md §5 audit.start.probers). Mirrors the
// PROBE_CLASSES catalog order without importing payloads directly.
const PROBE_IDS = [
  "prober-path-traversal",
  "prober-credential-leakage",
  "prober-description-poisoning",
  "prober-excessive-scope",
  "prober-unvalidated-outbound",
  "prober-schema-control",
];

// ---------------------------------------------------------------------------
// x402 gate (reuse x402-audit-server's semantics: unpaid -> 402; demo/paid ->
// proceed). Kept minimal here — the canonical wire shapes live in
// x402-audit-server.ts; this server only needs the GATE decision for /audits.
// ---------------------------------------------------------------------------
const PAYMENT_HEADER = "x-payment";
const X402_VERSION = 1 as const;
const PRICE_ATOMIC = "100000"; // $0.10 USDC (6 decimals), matches x402 server default
const NETWORK = process.env.X402_NETWORK ?? "base-sepolia";
const PAY_TO =
  process.env.PAY_TO_ADDRESS ?? "0x8430154a89111f27cd1bb2f1a3f81961b04391a8";
const USDC_ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // base-sepolia USDC

// Cash App rail config. Stored WITHOUT the leading $ (render "$" + tag when
// displaying). Same $0.10 price as the exact rail.
const CASHAPP_CASHTAG = (process.env.CASHAPP_CASHTAG ?? "mcpauditor").replace(
  /^\$+/,
  "",
);

// One-shot Cash App payment notes. Every 402 mints AUDIT-<nonce> using the same
// idiom as the other ids here (monotonic counter + short sha — never
// Date.now()/Math.random()); the gate consumes a note exactly once so a paid
// screenshot/note can't be replayed for a second audit. Capped FIFO so an
// attacker hammering 402s can't grow memory unboundedly.
const ISSUED_NOTES_CAP = 1000;
const issuedNotes = new Set<string>();
const issuedNoteOrder: string[] = [];
let noteCounter = 0;

function mintPaymentNote(): string {
  const n = ++noteCounter;
  const h = createHash("sha256")
    .update(`note:${n}:${CASHAPP_CASHTAG}:${SERVER_ID}`)
    .digest("hex")
    .slice(0, 8);
  const note = `AUDIT-${String(n).padStart(4, "0")}-${h}`;
  issuedNotes.add(note);
  issuedNoteOrder.push(note);
  while (issuedNoteOrder.length > ISSUED_NOTES_CAP) {
    const oldest = issuedNoteOrder.shift();
    if (oldest) issuedNotes.delete(oldest);
  }
  return note;
}

function paymentRequirements(resource: string) {
  // Mint a fresh one-shot note per 402 so the Cash App retry is bound to THIS
  // challenge (reused/foreign notes are rejected at the gate).
  const note = mintPaymentNote();
  return {
    x402Version: X402_VERSION,
    error: "X-PAYMENT header required to start an audit",
    accepts: [
      {
        scheme: "exact",
        network: NETWORK,
        maxAmountRequired: PRICE_ATOMIC,
        resource,
        description:
          "Live governed MCP security audit (SAFE-T) — streamed multi-agent run.",
        mimeType: "application/json",
        payTo: PAY_TO,
        maxTimeoutSeconds: 120,
        asset: USDC_ASSET,
        extra: { name: "USDC", version: "2" },
      },
      {
        scheme: "cashapp",
        network: "cashapp",
        maxAmountRequired: PRICE_ATOMIC,
        resource,
        description: `Pay $0.10 via Cash App to $${CASHAPP_CASHTAG} — include payment note ${note}`,
        mimeType: "application/json",
        payTo: `$${CASHAPP_CASHTAG}`,
        maxTimeoutSeconds: 600,
        asset: "USD",
        extra: {
          paymentNote: note,
          payUrl: `https://cash.app/$${CASHAPP_CASHTAG}/0.10`,
        },
      },
    ],
  };
}

// Gate decision for POST /audits. Mirrors x402-audit-server's rule:
//   - no X-PAYMENT               -> 402 (always)
//   - X-PAYMENT: demo (+flag)    -> accept (X402_DEMO_ACCEPT=1)
//   - demo header w/o flag       -> 402 (bypass closed)
//   - cashapp header (+flag)     -> accept if note matches one we issued
//                                   (one-shot); operator-trust — see below
//   - cashapp header w/o flag    -> 402 (bypass closed, same as demo)
//   - any other X-PAYMENT        -> accept (P1: no remote facilitator wired here;
//                                   real verify/settle is x402-audit-server's job)
type GateResult =
  | { ok: true; mode: "demo" | "paid" | "cashapp" }
  | { ok: false; status: number; body: unknown };

// Parse a base64(JSON) X-PAYMENT header into the cashapp shape, or null if it
// isn't one. Never throws — non-base64/non-JSON headers just fall through to
// the existing non-demo rejection path.
function parseCashappPayment(
  raw: string,
): { note: string; payerCashtag: string } | null {
  try {
    const decoded = JSON.parse(
      Buffer.from(raw, "base64").toString("utf8"),
    ) as {
      scheme?: unknown;
      payload?: { note?: unknown; payerCashtag?: unknown };
    };
    if (!decoded || typeof decoded !== "object") return null;
    if (decoded.scheme !== "cashapp") return null;
    return {
      note: typeof decoded.payload?.note === "string" ? decoded.payload.note : "",
      payerCashtag:
        typeof decoded.payload?.payerCashtag === "string"
          ? decoded.payload.payerCashtag
          : "(unknown)",
    };
  } catch {
    return null;
  }
}

function x402Gate(req: Request, resource: string): GateResult {
  const raw = (req.headers.get(PAYMENT_HEADER) ?? "").trim();
  if (raw.length === 0) {
    return { ok: false, status: 402, body: paymentRequirements(resource) };
  }
  const demoAccept = process.env.X402_DEMO_ACCEPT === "1";
  const isDemo = raw.toLowerCase() === "demo";
  if (isDemo) {
    if (!demoAccept) {
      return {
        ok: false,
        status: 402,
        body: {
          ...paymentRequirements(resource),
          error:
            "demo payment header presented but X402_DEMO_ACCEPT is not set (bypass closed)",
        },
      };
    }
    return { ok: true, mode: "demo" };
  }

  // Cash App rail. SECURITY: Cash App P2P payments have NO API-verifiable
  // receipt, so this rail is OPERATOR-TRUST only — it is honored solely under
  // the SAME X402_DEMO_ACCEPT=1 flag that gates `demo` (never silently), and
  // the presented note must be one THIS server minted, consumed one-shot.
  const cashapp = parseCashappPayment(raw);
  if (cashapp) {
    if (!demoAccept) {
      return {
        ok: false,
        status: 402,
        body: {
          ...paymentRequirements(resource),
          error:
            "cashapp payment header presented but X402_DEMO_ACCEPT is not set (bypass closed — cashapp is operator-trust mode, no API verification)",
        },
      };
    }
    if (cashapp.note.length === 0 || !issuedNotes.has(cashapp.note)) {
      return {
        ok: false,
        status: 402,
        body: {
          ...paymentRequirements(resource),
          error:
            "cashapp payment note missing, not issued by this server, or already used (notes are one-shot; re-request to mint a fresh AUDIT-<nonce>)",
        },
      };
    }
    issuedNotes.delete(cashapp.note); // one-shot: a note can mint exactly one audit
    console.error(
      `[stream] x402 settlement mode "cashapp (operator-trust, no API verification)" note=${cashapp.note} payer=${cashapp.payerCashtag}`,
    );
    return { ok: true, mode: "cashapp" };
  }

  // SECURITY: do NOT treat the mere presence of an X-PAYMENT header as proof of
  // payment (that is a fail-open auth bypass). This streaming server accepts ONLY
  // demo-mode payment; real onchain verify+settle lives in x402-audit-server.ts.
  // A non-demo payment header is refused here and pointed at the settling path.
  return {
    ok: false,
    status: 402,
    body: {
      ...paymentRequirements(resource),
      error:
        "non-demo X-PAYMENT must be verified+settled via the x402 settlement service (serve:x402); this stream server accepts only `X-PAYMENT: demo` with X402_DEMO_ACCEPT=1",
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP helpers + CORS.
// ---------------------------------------------------------------------------
function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, X-PAYMENT, Last-Event-ID, Authorization",
    "Access-Control-Expose-Headers": "X-PAYMENT-RESPONSE",
  };
}

function json(
  body: unknown,
  status: number,
  extra?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(), ...extra },
  });
}

// Serialize one wire event as an SSE frame. `id:` = seq for Last-Event-ID replay.
function sseFrame(evt: WireEvent): string {
  // data is single-line JSON (our escaping guarantees no embedded newlines in
  // untrusted fields; JSON.stringify escapes any that slip through anyway).
  return `id: ${evt.seq}\nevent: ${evt.type}\ndata: ${JSON.stringify(evt)}\n\n`;
}

function authOk(st: AuditState, url: URL, req: Request): boolean {
  const q = url.searchParams.get("token");
  const header = req.headers.get("authorization");
  const bearer = header?.startsWith("Bearer ")
    ? header.slice("Bearer ".length).trim()
    : header?.trim();
  const provided = q ?? bearer ?? "";
  // Constant-ish comparison (length + value); tokens are fixed length here.
  return provided.length > 0 && provided === st.streamToken;
}

// ---------------------------------------------------------------------------
// Request handler.
// ---------------------------------------------------------------------------
async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { pathname } = url;

  // CORS preflight.
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // GET /health
  if (req.method === "GET" && pathname === "/health") {
    return json(
      {
        status: "ok",
        service: "audit-stream-server",
        port: PORT,
        target: SERVER_ID,
        activeAudits: audits.size,
        demoMode: process.env.X402_DEMO_ACCEPT === "1",
        x402: {
          rails: ["exact", "cashapp"],
          cashapp: {
            payTo: `$${CASHAPP_CASHTAG}`,
            // Operator-trust: Cash App P2P has no API-verifiable receipt, so
            // the rail only settles when the demo flag is set.
            mode: "operator-trust (no API verification)",
            enabled: process.env.X402_DEMO_ACCEPT === "1",
          },
        },
      },
      200,
    );
  }

  // GET /history — recent audits {auditId, target, ts, severityCounts} from
  // ClickHouse (when configured + reachable) or the in-memory list. Never throws.
  if (req.method === "GET" && pathname === "/history") {
    const limitRaw = Number(url.searchParams.get("limit") ?? "50");
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, HISTORY_CAP) : 50;
    const hist = await readHistory(limit);
    return json({ source: hist.source, count: hist.audits.length, audits: hist.audits }, 200);
  }

  // POST /audits — x402 gate -> mint ids -> kick off async governed audit.
  if (req.method === "POST" && pathname === "/audits") {
    const resource = `${url.protocol}//${url.host}/audits`;
    const gate = x402Gate(req, resource);
    if (!gate.ok) {
      return json(gate.body, gate.status);
    }

    // Body is optional; githubUrl/endpoint are provenance/remote-target inputs.
    // A non-empty `endpoint` opts into the remote-target path (SSRF-admitted in
    // startAudit). No endpoint -> the seeded deterministic target (demo default).
    let body: { githubUrl?: string; endpoint?: string } = {};
    try {
      const text = await req.text();
      if (text.trim().length > 0) body = JSON.parse(text);
    } catch {
      // Tolerate empty/malformed body — seeded target needs no input.
    }

    const rawEndpoint =
      typeof body.endpoint === "string" && body.endpoint.trim().length > 0
        ? body.endpoint.trim()
        : undefined;

    const auditId = mintAuditId();
    const runId = mintRunId(auditId);
    const streamToken = mintStreamToken();
    const st: AuditState = {
      auditId,
      runId,
      streamToken,
      status: "running",
      seq: 0,
      ring: [],
      findings: [],
      subscribers: new Set(),
      createdSeq: auditCounter,
      // UI5a: default to the seeded target label; remote runs overwrite it with
      // the admitted host:port inside startAudit().
      target: SERVER_ID,
      ...(rawEndpoint ? { endpoint: rawEndpoint } : {}),
      createdTs: new Date().toISOString(),
      finalized: false,
    };
    audits.set(auditId, st);

    // Kick off the governed audit ASYNC. Events accumulate in the ring buffer so
    // a client that connects to /events slightly later still replays from seq 0.
    void startAudit(st).catch((err) => {
      const message = err instanceof Error ? err.message : String(err);
      if (st.status === "running") {
        st.status = "error";
        st.finalized = true; // #3: finalize BEFORE the terminal emit
        emit(st, "audit.error", { message: escapeUntrusted(message) });
      }
    });

    return json(
      {
        auditId,
        runId,
        streamToken,
        paymentMode: gate.mode,
        // Cash App mints are operator-trust settled (no API receipt) — label
        // them so the operator/frontend can tell the rails apart. Additive
        // field; the auditId/streamToken contract above is unchanged.
        ...(gate.mode === "cashapp" ? { settlement: "cashapp" } : {}),
        // The final target label is resolved at run start (admitted host:port for
        // remote, or the seeded id). Echo the initial label; the audit.start
        // event carries the authoritative value.
        target: st.target,
        remote: Boolean(rawEndpoint),
        // Convenience for clients: where to stream and snapshot.
        eventsUrl: `/audits/${auditId}/events?token=${streamToken}`,
        // #6: the snapshot is now token-gated (IDOR fix); include the token.
        snapshotUrl: `/audits/${auditId}?token=${streamToken}`,
      },
      201,
    );
  }

  // Routes under /audits/:id
  const auditMatch = pathname.match(/^\/audits\/([^/]+)(\/events)?$/);
  if (auditMatch) {
    const auditId = decodeURIComponent(auditMatch[1] ?? "");
    const isEvents = Boolean(auditMatch[2]);
    const st = audits.get(auditId);
    if (!st) {
      return json({ error: "audit_not_found", auditId }, 404);
    }

    // GET /audits/:id/events — SSE (auth by streamToken).
    if (isEvents && req.method === "GET") {
      if (!authOk(st, url, req)) {
        return json({ error: "unauthorized", detail: "invalid or missing streamToken" }, 401);
      }

      // Reconnect support: replay events with seq > lastEventId.
      const lastEventIdRaw =
        req.headers.get("last-event-id") ?? url.searchParams.get("lastEventId") ?? "";
      const lastEventId = Number.parseInt(lastEventIdRaw, 10);
      const replayFrom = Number.isFinite(lastEventId) && lastEventId > 0 ? lastEventId : 0;

      const encoder = new TextEncoder();
      let pushFn: ((e: WireEvent) => void) | null = null;

      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          const send = (evt: WireEvent): void => {
            try {
              controller.enqueue(encoder.encode(sseFrame(evt)));
            } catch {
              // controller closed — drop.
            }
          };

          // 1) Replay buffered events strictly after replayFrom.
          const lastBufferedSeq = st.ring.length
            ? (st.ring[st.ring.length - 1] as WireEvent).seq
            : 0;
          for (const evt of st.ring) {
            if (evt.seq > replayFrom) send(evt);
          }

          // 2) #3: If the audit is finalized, the terminal frame (report.ready or
          // audit.error) is already in the ring and was just replayed above for
          // any client whose replayFrom is below it. Nothing further will EVER be
          // emitted, so close UNCONDITIONALLY after replay — never subscribe.
          // Subscribing here would hang forever (e.g. a late `Last-Event-ID: 0`
          // client: replayFrom=0 < lastBufferedSeq, so the old guard fell through
          // to subscribe and waited on a terminal event that already fired).
          if (st.finalized) {
            controller.close();
            return;
          }

          // 3) Subscribe for live events; close on the FINAL event. For a
          // successful run that is report.ready (emitted after audit.complete);
          // for a failed run it is audit.error.
          pushFn = (evt: WireEvent): void => {
            send(evt);
            if (evt.type === "report.ready" || evt.type === "audit.error") {
              // Give the frame a tick to flush, then close + unsubscribe.
              queueMicrotask(() => {
                if (pushFn) st.subscribers.delete(pushFn);
                try {
                  controller.close();
                } catch {
                  // already closed
                }
              });
            }
          };
          st.subscribers.add(pushFn);

          // If it went terminal between replay and subscribe, flush the tail.
          if (st.status !== "running") {
            for (const evt of st.ring) {
              if (evt.seq > Math.max(replayFrom, lastBufferedSeq)) send(evt);
            }
          }
        },
        cancel() {
          if (pushFn) st.subscribers.delete(pushFn);
        },
      });

      return new Response(stream, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "X-Accel-Buffering": "no", // disable proxy buffering (nginx/Render)
          ...corsHeaders(),
        },
      });
    }

    // GET /audits/:id — final snapshot (fallback for clients that miss the stream).
    // #6 IDOR: auditIds are deterministic, so this snapshot leaks PAID results to
    // anyone who guesses an id. Require the SAME streamToken auth as the SSE /
    // file-issue routes; 401 without a valid token.
    if (!isEvents && req.method === "GET") {
      if (!authOk(st, url, req)) {
        return json({ error: "unauthorized", detail: "invalid or missing streamToken" }, 401);
      }
      return json(
        {
          auditId: st.auditId,
          runId: st.runId,
          status: st.status,
          target: st.target,
          findings: st.findings,
          events: st.ring,
          eventCount: st.seq,
          // UI3 — the completed report (mode + bounded model [+ validated C1 spec
          // when mode === "c1"]). null until the run completes.
          report: st.report ?? null,
        },
        200,
      );
    }
  }

  // POST /audits/:id/file-issue — Composio: file the audit report as a GitHub
  // issue. Returns {issueUrl} on live success, else {degraded:true, payload}.
  // Auth by streamToken (same gate as /events). Never throws.
  const fileIssueMatch = pathname.match(/^\/audits\/([^/]+)\/file-issue$/);
  if (fileIssueMatch && req.method === "POST") {
    const auditId = decodeURIComponent(fileIssueMatch[1] ?? "");
    const st = audits.get(auditId);
    if (!st) return json({ error: "audit_not_found", auditId }, 404);
    if (!authOk(st, url, req)) {
      return json({ error: "unauthorized", detail: "invalid or missing streamToken" }, 401);
    }
    const result = await fileIssueForAudit(st);
    return json(result, 200);
  }

  return json(
    {
      error: "not_found",
      routes: [
        "GET /health",
        "GET /history",
        "POST /audits",
        "GET /audits/:id/events?token=…",
        "GET /audits/:id",
        "POST /audits/:id/file-issue?token=…",
      ],
    },
    404,
  );
}

// ---------------------------------------------------------------------------
// Boot.
// ---------------------------------------------------------------------------
const server = Bun.serve({
  port: PORT,
  idleTimeout: 255, // an audit run streams for a while; keep SSE alive
  fetch: handle,
});

console.error(
  `[stream] audit-stream-server listening on http://localhost:${server.port}`,
);
console.error(`[stream] target=${SERVER_ID} cmd="${TARGET_CMD}"`);
console.error(
  `[stream] CORS origin=${ALLOWED_ORIGIN} demoMode=${process.env.X402_DEMO_ACCEPT === "1"}`,
);
console.error(
  "[stream] POST /audits -> {auditId,streamToken}; GET /audits/:id/events -> SSE; GET /audits/:id -> snapshot; GET /health -> 200",
);
