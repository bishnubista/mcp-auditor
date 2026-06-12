/**
 * index.ts — stdio MCP server entrypoint for the SEEDED VULNERABLE target.
 *
 * Defensive-security hackathon demo target (we own it). Exposes 5 deliberately
 * flawed tools + 1 clean control over the MCP stdio transport so an auditor agent
 * can enumerate (tools/list) and probe them. See SEEDED_FLAWS.md for the flaw map.
 *
 * Run: `bun run src/index.ts`  (speaks JSON-RPC over stdin/stdout).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";

async function main(): Promise<void> {
  const server = new McpServer({
    name: "seeded-vulnerable-target",
    version: "0.1.0",
  });

  registerTools(server);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Never write to stdout here — stdout is the JSON-RPC channel.
  console.error("[target-server] seeded vulnerable MCP server ready on stdio");
}

main().catch((err) => {
  console.error("[target-server] fatal:", err);
  process.exit(1);
});
