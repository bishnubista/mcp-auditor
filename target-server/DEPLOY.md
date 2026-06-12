# Deploy the seeded target to Render (T8, stretch)

Make the seeded vulnerable MCP server reachable at a **public URL** over the MCP
Streamable HTTP transport, so the auditor can probe a live remote target instead of a
local stdio pipe.

> **This is additive and bonus.** The on-stage demo stays localhost/stdio
> (`bun run demo:local`). Nothing here changes the stdio path or the seeded flaws —
> `src/http.ts` and `src/index.ts` both register the **same** tools from `src/tools.ts`.

## What ships

| File | Role |
|------|------|
| `src/http.ts` | Streamable HTTP MCP entrypoint. Binds `$PORT` (Render injects it; default `8787`). `POST /mcp` = MCP, `GET /health` = Render health check. |
| `Dockerfile` | Builds a Bun image and runs `bun run src/http.ts`. (Bun isn't a native Render runtime, so this is a Docker web service.) |
| `render.yaml` | Render Blueprint: one Docker web service, `rootDir` scoped to `mcp-auditor/target-server`, `healthCheckPath: /health`. |

## Option A — Render Dashboard (Blueprint)

1. Push this repo to GitHub (Render reads the Blueprint from the repo).
2. Render Dashboard → **New** → **Blueprint**.
3. Select the repo. Render finds `mcp-auditor/target-server/render.yaml` and provisions
   the `seeded-vulnerable-target` Docker web service.
4. **Apply**. Render builds the Dockerfile, runs `bun run src/http.ts`, and waits for
   `GET /health` to return 200 before marking the service live.

## Option B — Render CLI

```bash
# Auth once (needs RENDER_API_KEY or interactive login):
render login

# From the repo root, with the Blueprint present:
render blueprint launch        # provisions services from render.yaml
# or trigger a deploy for an existing service:
render deploys create <service-id> --wait
```

> Not run in this build: no `render` CLI and no `RENDER_API_KEY` were available in the
> hackathon environment, so the deploy is **config-ready but not executed**. The config
> above is verified deployable (typecheck clean, server proven reachable locally — see below).

## Resulting URL shape

Render assigns:

```text
https://seeded-vulnerable-target.onrender.com
```

(or `https://seeded-vulnerable-target-XXXX.onrender.com` if the name is taken). The MCP
endpoint is then:

```text
https://seeded-vulnerable-target.onrender.com/mcp      # MCP Streamable HTTP
https://seeded-vulnerable-target.onrender.com/health   # 200 health check
```

## Point the auditor at it

The auditor's orchestrator currently spawns the target over **stdio**. To probe the
remote Render target instead, connect an MCP **Streamable HTTP** client to the `/mcp`
URL (the auditor already depends on `@modelcontextprotocol/sdk`, which ships
`StreamableHTTPClientTransport`):

```ts
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("https://seeded-vulnerable-target.onrender.com/mcp"),
);
await client.connect(transport);   // then tools/list, tools/call as usual
```

The seeded flaws (path traversal, cred leak, description poisoning, excessive scope,
unvalidated outbound) are identical to the stdio target — same `tools.ts`.

## Verify a live deploy

```bash
BASE=https://seeded-vulnerable-target.onrender.com

# Health
curl -s $BASE/health        # -> {"status":"ok","transport":"streamable-http","tools":6}

# MCP initialize
curl -s -X POST $BASE/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

# tools/list -> should return all 6 tools
curl -s -X POST $BASE/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Local reachability proof (the real acceptance — verified in this build)

```bash
cd mcp-auditor/target-server
PORT=8787 bun run src/http.ts &
curl -s localhost:8787/health
# -> {"status":"ok","transport":"streamable-http","tools":6}   (HTTP 200)
# initialize + tools/list over POST /mcp return all 6 tools:
#   read_file, get_config, search_docs, run_query, send_notification, get_weather
```
