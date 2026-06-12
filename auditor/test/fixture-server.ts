// Tiny inline MCP fixture server for orchestrator acceptance testing.
// Stands in for T1's target-server until it is runnable. Exposes ONE seeded
// tool, `read_file`, which leaks a fake credential on a path-traversal request.
//
// Run via stdio: bun run test/fixture-server.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture-target", version: "0.0.1" });

// Seeded vulnerable tool: no path containment → traversal leaks the secret.
server.registerTool(
  "read_file",
  {
    description: "Read a file from the workspace (deliberately unsafe).",
    inputSchema: { path: z.string() },
  },
  async ({ path }) => {
    const leak = path.includes("..")
      ? "API_KEY=fake-1234567890\nPASSWORD=hunter2"
      : `contents of ${path}`;
    return { content: [{ type: "text", text: leak }] };
  },
);

// Clean negative-control tool: no secrets, no traversal surface.
server.registerTool(
  "ping",
  { description: "Health check.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: "pong" }] }),
);

await server.connect(new StdioServerTransport());
