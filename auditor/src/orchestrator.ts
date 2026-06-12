// Auditor orchestrator — the MCP CLIENT entrypoint.
//
// 1. Spawn/connect to a target MCP server over stdio (command from argv).
// 2. tools/list → print enumerated tools as pretty JSON (the demo moment).
// 3. Fan out the six SAFE-T probers (T3 runner) IN PARALLEL — each invokes its
//    target tool EXCLUSIVELY through the governance executor (T4's executeProbe,
//    the only permitted tool-call path), producing findings.
// 4. Findings are appended to ../out/findings.jsonl by the runner.
//
// Usage:
//   bun run src/orchestrator.ts -- <command> [args...]
//   e.g. bun run src/orchestrator.ts -- bun run ../target-server/src/index.ts

import { McpClient } from "./mcp-client.ts";
import { runProbers, buildPolicy, FINDINGS_PATH } from "./probers/runner.ts";

const SERVER_ID = "target-local";

async function main(): Promise<void> {
  // argv: [bun, orchestrator.ts, "--", command, ...args]  ("--" optional)
  const raw = process.argv.slice(2);
  const argv = raw[0] === "--" ? raw.slice(1) : raw;
  const command = argv[0];
  const args = argv.slice(1);

  if (!command) {
    console.error(
      "usage: bun run src/orchestrator.ts -- <command> [args...]\n" +
        "  e.g. bun run src/orchestrator.ts -- bun run ../target-server/src/index.ts",
    );
    process.exit(2);
  }

  const client = new McpClient(command, args);
  console.error(`[orchestrator] connecting to target: ${command} ${args.join(" ")}`);
  await client.connect();

  // --- Step 2: enumerate ---------------------------------------------------
  const tools = await client.listTools();
  console.error(`[orchestrator] enumerated ${tools.length} tool(s):`);
  // The demo moment: pretty-print the discovered tool surface to stdout.
  console.log(JSON.stringify(tools, null, 2));

  // --- Step 3: fan out all six SAFE-T probers in parallel through governance -
  // T3 runner: each prober invokes its target tool EXCLUSIVELY via executeProbe
  // (the only permitted tool-call path) and appends findings to findings.jsonl.
  // The governance policy is scoped to exactly the probed tools on this server.
  const policy = buildPolicy(SERVER_ID, tools);

  // The single callTool primitive the governance executor is allowed to invoke.
  const callTool = (tool: string, payload: unknown) => client.callTool(tool, payload);

  const results = await runProbers(tools, callTool, policy);

  await client.close();

  // --- One-line summary (the demo's discrimination proof) ------------------
  const findings = results.filter((r) => r.isFinding);
  const safeTs = new Set(findings.map((r) => r.safeT));
  const weatherClean =
    findings.filter((r) => r.tool === "get_weather").length === 0;
  console.error(
    `[orchestrator] SUMMARY: ${findings.length} findings across ${safeTs.size} SAFE-T classes, ` +
      `get_weather ${weatherClean ? "clean" : "DIRTY (false positive!)"}.`,
  );
  console.error(`[orchestrator] done. findings → ${FINDINGS_PATH}`);
}

main().catch((err) => {
  console.error("[orchestrator] fatal:", err);
  process.exit(1);
});
