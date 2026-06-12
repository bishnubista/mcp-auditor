# MCP Auditor — Web UI

Next.js (App Router) UI for the governed MCP security auditor. The centerpiece
is a **live view of six SAFE-T security agents** hunting vulnerabilities in real
time, consuming the `PLAN-UI.md §5` SSE event protocol.

## Run

```bash
bun install
bun run dev      # http://localhost:3000 — defaults to the built-in MOCK stream
bun run build    # production build
```

## Mock vs. backend

The UI consumes the SSE stream **directly from the Render origin** (never proxied
through a Next route handler — `PLAN-UI.md §4`). For standalone demoing it also
ships a built-in mock stream that emits the `§5` sequence on a timer.

| env | behavior |
|-----|----------|
| `NEXT_PUBLIC_AUDIT_BACKEND_URL` unset | mock stream (dev default) |
| `NEXT_PUBLIC_AUDIT_BACKEND_URL=https://…` | real backend: `POST /audits` → `{auditId, streamToken}` → `EventSource GET /audits/:id/events?token=…` |
| `NEXT_PUBLIC_MOCK=1` | force mock even when a backend URL is set |

When a backend URL is configured, a **mock-stream toggle** appears in the form.

## Structure

```text
app/
  page.tsx                  server component — hero + prober legend, mounts the client panel
  layout.tsx                root layout + globals
  globals.css               security/terminal theme (Tailwind v4 @theme tokens)
  components/
    LiveAuditPanel.tsx      CLIENT — subscribes, folds §5 events, renders cards/trail/report
    AgentCard.tsx           one of six cards: idle→probing→found/clean + gate badge
    AuditTrail.tsx          live event log
    StaticReport.tsx        required report renderer (C1/UI5 slots in behind this seam)
    InputForm.tsx           GitHub link + MCP endpoint + seeded-demo quick option
    SeverityBadge.tsx       severity pill
    GithubProvenance.tsx    owner/repo provenance (safe https link only)
lib/
  protocol.ts               §5 event types + the 6-prober catalog (frozen contract)
  audit-state.ts            pure reducer — keys by agentId, ignores out-of-order/dup seq
  mock-stream.ts            built-in §5 mock (browser-only, no Bun/Node APIs)
  connect.ts                mock vs backend selection + EventSource wiring
  safe.ts                   trust boundary: safe-url checks, evidence clamp
```

## Trust boundary (`PLAN-UI.md §6`)

All target-derived evidence is **untrusted data**. It is rendered as plain-text
React children (escaped) only — **no `dangerouslySetInnerHTML`**, no raw HTML or
markdown-HTML, no arbitrary links (only `https://github.com` provenance links we
reconstruct, plus same-document `#` anchors).

## Server-code constraint

No Bun-only APIs in server components or shared modules (Next runs on Node in
Vercel). Bun is used only as the dev/build runner.
