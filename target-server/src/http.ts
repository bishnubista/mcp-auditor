/**
 * http.ts — STREAMABLE HTTP MCP server entrypoint for the SEEDED VULNERABLE target.
 *
 * ADDITIVE deploy entrypoint (T8 stretch). This exposes the EXACT SAME 6 seeded tools
 * as the stdio entrypoint (src/index.ts) — both call `registerTools(server)` from
 * src/tools.ts — over the MCP Streamable HTTP transport so the target is reachable at a
 * public URL (e.g. Render) instead of only over a local stdio pipe.
 *
 * The stdio demo path (src/index.ts) is untouched and remains the canonical demo:local
 * transport. This file changes nothing about the seeded flaws; they are byte-for-byte
 * identical because both transports register the same tools module.
 *
 * Endpoints:
 *   - POST /mcp   — MCP Streamable HTTP (initialize, tools/list, tools/call, ...)
 *   - GET  /mcp   — MCP Streamable HTTP (SSE stream; 405 in stateless JSON mode)
 *   - GET  /health — trivial 200 for Render health checks
 *
 * Stateless mode (sessionIdGenerator: undefined) + enableJsonResponse: a fresh
 * server+transport is created per request, so a one-shot `initialize` then `tools/list`
 * each return a plain JSON-RPC response. This matches the auditor's one-shot enumeration
 * and keeps the HTTP path trivial to probe with curl.
 *
 * Run locally: `PORT=8787 bun run src/http.ts`
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { registerTools } from "./tools.js";

const PORT = Number.parseInt(process.env.PORT ?? "8787", 10);
const MCP_PATH = "/mcp";

/** Build a fresh MCP server with the SAME seeded tools as the stdio entrypoint. */
function buildServer(): McpServer {
  const server = new McpServer({
    name: "seeded-vulnerable-target",
    version: "0.1.0",
  });
  registerTools(server);
  return server;
}

/** Handle one MCP HTTP request in stateless mode (new server+transport per request). */
async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const server = buildServer();
  // Stateless: no session id. JSON responses (not SSE) so curl/auditor get plain JSON-RPC.
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  // Tear down per-request resources when the response closes.
  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  await server.connect(transport);
  await transport.handleRequest(req, res);
}

const httpServer = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  // Render health check — must be a trivial, dependency-free 200.
  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", transport: "streamable-http", tools: 6 }));
    return;
  }

  if (url.pathname === MCP_PATH) {
    handleMcp(req, res).catch((err) => {
      console.error("[target-server:http] request error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32603, message: "Internal server error" },
            id: null,
          }),
        );
      }
    });
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found", try: [MCP_PATH, "/health"] }));
});

httpServer.listen(PORT, () => {
  // Logs to stderr-adjacent stdout are fine here — this is NOT a stdio JSON-RPC channel.
  console.error(
    `[target-server:http] seeded vulnerable MCP server ready on :${PORT} ` +
      `(POST ${MCP_PATH}, GET /health)`,
  );
});

function shutdown(): void {
  httpServer.close(() => process.exit(0));
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
