# MCP Server Auditor

A multi-agent system that **audits live MCP servers for SAFE-T security flaws** under a
governance funnel, synthesizes a cited report, **publishes it to the open web**, and
**monetizes access via x402**. Every probe is governed and audited; every finding is grounded
in the SAFE-MCP technique catalog.

Built for the **Context Engineering Challenge — "agents that act on the web."**

📄 **Published audit:** [`cited.md`](./cited.md) — the agent's citation-grounded MCP
security report, with an on-chain **x402** settlement (0.1 USDC on Base Sepolia,
[verifiable tx](https://sepolia.basescan.org/tx/0xda0c5b5b77067f87988f36aca33aa78ef7b806a76ea26e54d4de52c9a8302f12)).

---

## What it does (end to end)

```text
              ┌─────────────────────────────┐
              │  Governance funnel (Guild)  │  permission gate + audit trail
              └──────────────┬──────────────┘  (executeProbe = the ONLY path to a tool)
   ┌──────────────┐  enumerate │
   │ Target MCP   │◄───────────│  Orchestrator agent
   │ server       │◄──┐        │
   │ (seeded /    │   │   ┌─────┴─────── fan-out: 6 parallel SAFE-T probers ───────┐
   │  real)       │   │   P1 path-traversal  P2 cred-leak  P3 desc-poisoning       │
   └──────────────┘   │   P4 excessive-scope P5 outbound   P6 clean control        │
                      └────────────────────┬─────────────────────────────────────┘
                              findings.jsonl│ (deterministic order)
                       ┌──────────────────┐ │  ┌────────────┐
                       │ Synthesizer      │─┴─►│ ClickHouse │ severity dashboard
                       │ cited SAF-T report│    └────────────┘
                       └───────┬───────────┘
            ┌──────────────────┼────────────────────┬─────────────────┐
     Composio → GitHub   cited.md (Senso)     x402 paid service   audit.jsonl
     (real issue)        (publish, agent web) (402→pay→report)    (governance proof)
```

Run it all deterministically with one command:

```bash
bun run demo:local      # governed audit → 6 probers → cited report → sponsor action (dry-run)
```

---

## Challenge requirements → how we meet them

| Requirement | Implementation |
|-------------|----------------|
| Autonomous agent doing **real work on the open web** | Auditor enumerates + probes a live MCP server, files a **real GitHub issue** via Composio |
| Action verbs: publish / monitor / **orchestrate** / **transact** | orchestrate = 6-agent fan-out · publish = cited.md + GitHub issue · monitor = tool-surface scan · transact = x402 |
| **Grounded in ground-truth knowledge** | Every finding keyed to a **SAFE-MCP / SAF-T** technique; cited.md links the catalog |
| **3+ sponsor tools** | Composio, ClickHouse, Guild (governance), Render, + x402 rail |
| **Publish output to `cited.md`** | `bun run publish:cited` → Senso `sdk.senso.ai` (offline-render fallback) |
| **Monetize with payment rails** | **x402** service: unpaid `POST /audit` → `402` w/ payment terms → pay → `200` + report |

---

## Multi-agent + governance guarantees

- **Multi-agent**: 6 SAFE-T probers fan out in parallel (`runner.ts`), one per technique class.
- **Governance funnel**: `executeProbe()` is the *only* path a prober can reach a target tool.
  `demo:local` statically asserts no prober calls `callTool(` directly (funnel-breach guard).
- **Complete audit trail**: one audit entry written **before** each probe dispatches — exactly
  6 entries, all matched to findings (`demo:local` verifies the tuples).
- **Deterministic**: findings sorted by probe-class order, written once; identical bytes per run.
- **Negative control**: a clean `get_weather` tool must yield **zero** findings (discrimination, not just detection).

---

## Commands

```bash
bun run demo:local      # the deterministic gate + stage demo (no creds needed)
bun run orchestrate -- bun run ../target-server/src/index.ts   # raw governed audit
bun run synthesize      # findings.jsonl → out/audit-report.md
bun run file-report     # file the report as a REAL GitHub issue (Composio)
bun run publish:cited   # publish to cited.md (Senso); --offline to render locally
bun run serve:x402      # start the x402-monetized audit service
bun run dashboard       # ClickHouse severity dashboard (in-memory fallback)
```

Target server (the thing being audited):

```bash
bun run ../target-server/src/index.ts   # stdio transport (used by demo:local)
bun run ../target-server/src/http.ts    # HTTP transport (Render-deployable; see DEPLOY.md)
```

---

## Configuration

Copy `auditor/.env.example` → `auditor/.env` and fill in keys (Bun auto-loads it).
**Posture: real APIs by default** — a missing key makes that integration fail loud
(nonzero exit), not silently mock. Offline/demo modes are explicit opt-ins.

| Integration | Status | Needs |
|-------------|--------|-------|
| Composio → GitHub | ✅ live (self-heals stale connections) | `COMPOSIO_API_KEY`, `COMPOSIO_GITHUB_REPO` |
| x402 payment rail | ✅ 402→settle wired | `PAY_TO_ADDRESS`, facilitator, funded client |
| ClickHouse | ✅ live or in-memory | `CLICKHOUSE_URL` (+user/pass) |
| cited.md / Senso | wired; offline fallback | `CITED_API_KEY` |
| Render deploy | config-ready | `RENDER_API_KEY` (see `target-server/DEPLOY.md`) |
| Guild ("Harness") | local audit.jsonl | no public Guild SDK exists; swap 2 constants if provided |

> **Note on taxonomy:** `SAFE-T####` ids are this auditor's internal probe taxonomy, grounded in
> the SAF-MCP framework. Citations show our probe class as the finding's description and link the
> SAF-MCP catalog as the source — they never present a mismatched upstream technique name.

---

## Security & ethics

The bundled target server is a **seeded, self-owned, deliberately vulnerable** MCP server for
demonstration. The auditor only probes servers explicitly allowlisted in the governance policy —
that allowlist *is* the governance demo. All seeded secrets are fake placeholders; outbound
actions are simulated (no real network calls from the target).
