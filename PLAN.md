# PLAN.md — MCP Server Auditor (Hackathon Build)

> **Single source of truth.** Subagents: read this file + `tasks.yaml` before doing anything.
> Codebase lives in `mcp-auditor/`. Coordination state lives in THIS folder (`tasks.yaml`, `progress.jsonl`).

## 1. What we're building

**MCP Server Auditor** — a multi-agent system that connects to a live (seeded-vulnerable) MCP server,
enumerates its exposed tools, fans out parallel SAFE-T prober agents against them under Guild AI
(Harness) governance, and synthesizes a cited security audit report filed via Composio.

**One-sentence pitch:** Every company is shipping MCP servers; nobody is auditing them — we built the
governed, multi-agent auditor that does.

### Hackathon gates (all must hold)
- ✅ **Harness (= Guild AI)** is load-bearing: permissions which MCP servers/tools each prober may touch + audit trail of every probe.
- ✅ **Multi-agent**: orchestrator → 6 parallel SAFE-T prober agents → synthesizer (reuses the deterministic 6-worker pattern from the existing `llm-vulnerability-scan` skill).
- ✅ **Sponsor use**: Guild (governance), Composio (dual-use: target MCP surface + files findings as GitHub issue), Bedrock/Claude (probe generation + synthesis), ClickHouse (findings store + severity dashboard), Render (hosts seeded target).
- ✅ **3-hour guardrail**: every block below ends demoable; stub-first, real-later.

## 2. Architecture

```text
                          ┌─────────────────────────────┐
                          │  Guild AI (Harness)         │
                          │  permissioning + audit log  │
                          └──────────────┬──────────────┘
                                         │ gates every probe
┌──────────────┐   enumerate   ┌─────────▼─────────┐
│ Seeded vuln  │◄──────────────│   Orchestrator    │
│ MCP server   │               │      agent        │
│ (Render)     │◄──┐           └─────────┬─────────┘
└──────────────┘   │ probes              │ fan-out (parallel)
                   │     ┌───────────────┼───────────────────┐
                   │  ┌──┴───┐ ┌──────┐ ┌┴─────┐ ┌──────┐ ...│ 6 probers,
                   └──┤ P1   │ │ P2   │ │ P3   │ │ P4   │    │ one per
                      │cred  │ │prompt│ │data  │ │scope │    │ SAFE-T class
                      │leak  │ │inject│ │access│ │viol. │    │
                      └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘    │
                         └────────┴───┬────┴────────┴────────┘
                              findings│(JSONL)
                            ┌─────────▼─────────┐    ┌────────────┐
                            │ Synthesizer agent │───►│ ClickHouse │──► severity
                            │ cited SAFE-T audit│    │ findings   │    dashboard
                            └─────────┬─────────┘    └────────────┘
                                      │ files report
                            ┌─────────▼─────────┐
                            │ Composio → GitHub │
                            │ issue w/ report   │
                            └───────────────────┘
```

### Critical path vs. stretch (Codex blocker #5: ONE mandatory live sponsor integration)
**Critical path (must work, localhost):** seeded stdio MCP server → orchestrator `tools/list` →
parallel probers through governance `probeExecutor` → `findings.jsonl` → synthesized `audit-report.md`.
**Mandatory live sponsor action:** Composio files the report as a GitHub issue.
**Local-adapter by default:** Guild governance = local `audit.jsonl` gate (identical logic) + Guild dashboard screenshots.
**CUT by default (stretch only, only after `demo:local` is green):** ClickHouse, Render, Bedrock payload variants.

| # | Component | Tech | Critical path? |
|---|-----------|------|----------------|
| 1 | Seeded vulnerable MCP server | TypeScript (bun), stdio transport, 4–6 tools each embedding one SAFE-T flaw | ✅ |
| 2 | Orchestrator | TS: MCP client connect → `tools/list` → dispatch probers | ✅ |
| 3 | Prober runner, 6 probe classes | ONE module: `runner.ts` executes six static SAFE-T probe classes in parallel; payloads from skill `references/safe-t-checklist.md` | ✅ |
| 4 | Governance `probeExecutor` | gate(probe) → allow/deny + audit event; ALL probes must go through it; local `audit.jsonl` backend, Guild backend optional | ✅ |
| 5 | Synthesizer | Merges findings → cited report (`SAFE-T####` keys); template-merge, no LLM required | ✅ |
| 6 | Composio action | File report as GitHub issue (the one mandatory live sponsor integration) | ✅ live action |
| 7 | ClickHouse dashboard | Severity rollup | ❌ stretch |
| 8 | Render deploy | Public target URL | ❌ stretch |
| 9 | Bedrock payload variants | Claude-generated probe variants on top of static catalog | ❌ stretch |

### Top-level acceptance (Codex blocker #6 — the anti-fake-done gate)
`bun run demo:local` — starts target server, enumerates tools, runs ALL probes through the
governance executor, writes `findings.jsonl` + `audit-report.md` + `audit.jsonl`, and **exits
nonzero if any required artifact is missing or empty**. Nothing is "done" until this passes.

## 3. Model roles & consensus protocol

| Role | Model | Does |
|------|-------|------|
| **Orchestrator** | Fable 5 (this session) | Owns PLAN.md + tasks.yaml, spawns/sequences subagents, integrates, resolves conflicts |
| **Implementor** | Opus 4.8 subagents | Build components in parallel per `tasks.yaml`; report via `progress.jsonl` |
| **Adversarial reviewer** | Codex (`codex exec`, model gpt-5.5, high reasoning) | Reviews plan, then implementation; must-fix blockers only |
| **Progress tracker** | One dedicated lightweight agent | Continuously reads `tasks.yaml` + `progress.jsonl` vs. the clock; reports what is DONE, what is in flight, what is behind; recommends cuts per the cut order (stretch only: T7 → T8 → T9-Bedrock-variants; T6/Composio is the mandatory live integration and is NEVER cut — its degraded mode is the printed tool-call payload, not removal) |

**Codex verdict rule (HARD):** every Codex review MUST end with `VERDICT: approve` or
`VERDICT: revise` + must-fix blockers only. No verdict = re-prompt once for verdict only.
Implementation may not start (plan phase) and code may not be committed (implement phase)
without an explicit `VERDICT: approve`.

**Time-box rule (3-hour guardrail):** each Codex review is capped at ~10 min wall-clock and
max 2 revise→re-review cycles per phase. If still `revise` after 2 cycles, orchestrator applies
blockers it agrees with, records the disagreement in `progress.jsonl`, and proceeds — the clock
wins over perfect consensus.

**Consensus loop (used twice):**
1. **Plan phase**: Fable drafts PLAN.md → Codex adversarial review → apply blockers → re-review → `VERDICT: approve` required before implementation.
2. **Implement phase**: Opus subagents build → Fable integrates → Codex reviews diff → fix → re-review → approve → commit (feature branch, never main).

## 4. Subagent coordination contract

- **`tasks.yaml`** — the task board. Fields: `id`, `title`, `status` (todo|claimed|done|blocked), `owner`, `depends_on`, `outputs` (exact file paths), `acceptance` (how to verify).
- **`progress.jsonl`** — append-only event log. One JSON object per line:
  `{"ts": "<ISO8601>", "agent": "<name>", "task": "<id>", "event": "claim|progress|done|blocked", "detail": "...", "files": []}`

**Subagent protocol (every Opus subagent follows this):**
1. Read `PLAN.md` + `tasks.yaml` + last 20 lines of `progress.jsonl`.
2. Claim your assigned task: append a `claim` event.
3. Build ONLY your task's `outputs`. Do not touch other tasks' files.
4. On completion: append `done` event listing files written + how acceptance was verified.
5. If blocked: append `blocked` event with what you need; do NOT improvise outside scope.

## 5. 3-hour timeline (each block ends demoable)

- [ ] **T+0:00–0:45 — Minimal vertical slice (NOTHING else on critical path)**
  - [ ] Local stdio MCP server with seeded flaws → orchestrator `tools/list` → **one deterministic probe** → first `findings.jsonl` entry
  - [ ] Render / Bedrock / Guild / Composio / ClickHouse explicitly OUT of this block
  - *Demoable: "agent connected, surface mapped, first real finding"*
- [ ] **T+0:45–1:45 — Probe fan-out under governance**
  - [ ] Governance `probeExecutor` (local `audit.jsonl` backend); ALL probes routed through it
  - [ ] Six SAFE-T probe classes executing in parallel via `runner.ts`
  - [ ] `findings.jsonl` ≥3 true positives; zero findings on the clean tool
  - *Demoable: "parallel probers under a governance gate, audit trail visible"*
- [ ] **T+1:45–2:20 — Synthesis + the one live sponsor action**
  - [ ] Synthesizer → cited SAFE-T `audit-report.md`
  - [ ] `bun run demo:local` green end-to-end (the anti-fake-done gate)
  - [ ] Composio files report as GitHub issue (mandatory live integration)
  - *Demoable: full autonomy loop trigger→probe→report→action*
- [ ] **T+2:20–2:45 — Stretch, ONLY if demo:local is green**: ClickHouse dashboard, then Render, then Bedrock variants
- [ ] **T+2:45–3:00 — Buffer + demo rehearsal** (no new work; verify any stretch item live or demote it to screenshot)

## 6. Demo script (3 min) — LOCALHOST ONLY (Codex blocker #7)
1. Problem: everyone ships MCP servers, nobody audits them.
2. Kick off `demo:local` against the seeded target — deterministic, rehearsed.
3. Watch enumeration → 6 probers fan out in parallel.
4. Show the governance audit trail gating each probe (audit.jsonl live + Guild dashboard screenshot) — governance is the point.
5. Cited SAFE-T report → Composio files it as a GitHub issue live (the ONE live external action).
6. Stretch items (Render URL, ClickHouse dashboard) appear ONLY if verified green before the final 15-min buffer; otherwise screenshots.
Impact: continuous, governed MCP security review.

## 7. Risks & mitigations
| Risk | Mitigation |
|------|------------|
| Guild API onboarding stalls | Local `audit.jsonl` audit trail + Guild dashboard screenshots; gate logic identical |
| Probes too clever / nondeterministic | Seeded flaws are KNOWN; probes target them specifically; demo is rehearsed |
| Composio/GitHub auth stalls | Print the report; show Composio tool-call log |
| Render deploy slow | Demo against localhost; Render URL is bonus |
| Time overrun | Each block demoable; cut stretch items only (T7 ClickHouse → T8 Render → Bedrock variants). T6/Composio is never cut — if auth fails its degraded mode is printing the exact tool-call payload |

## 8. Ethics framing (judges will ask)
Target is a **seeded, self-deployed, deliberately vulnerable MCP server we own**. The auditor only
probes servers explicitly allowlisted in Guild — that IS the demo of governance.
