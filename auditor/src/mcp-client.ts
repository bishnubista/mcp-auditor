// Thin wrapper around the MCP SDK client over a stdio transport.
// Spawns the target server as a child process, speaks MCP, exposes the four
// operations the auditor needs: connect / listTools / callTool / close.
//
// SDK: @modelcontextprotocol/sdk@1.29.0 (API verified against installed .d.ts).

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Shape we surface to the orchestrator. Mirrors the SDK's tool entry but kept
// narrow so the rest of the codebase doesn't import SDK types directly.
export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: unknown;
}

// SDK callTool result content items (text is the only kind the probes inspect).
export interface ToolResultContentText {
  type: "text";
  text: string;
}

export interface ToolCallResult {
  content: unknown[];
  isError?: boolean;
}

export class McpClient {
  private client: Client;
  private transport: StdioClientTransport;
  private connected = false;

  /**
   * @param command target server executable (e.g. "bun")
   * @param args    args for the target server (e.g. ["run", "src/index.ts"])
   * @param cwd     working dir for the spawned server (optional)
   */
  constructor(command: string, args: string[] = [], cwd?: string) {
    this.transport = new StdioClientTransport({
      command,
      args,
      ...(cwd ? { cwd } : {}),
      // Inherit env so the child sees PATH etc.; stderr piped through so the
      // target server's logs don't corrupt the stdout JSON-RPC stream.
      env: process.env as Record<string, string>,
      stderr: "inherit",
    });
    this.client = new Client(
      { name: "mcp-auditor", version: "0.1.0" },
      { capabilities: {} },
    );
  }

  async connect(): Promise<void> {
    await this.client.connect(this.transport);
    this.connected = true;
  }

  async listTools(): Promise<ToolInfo[]> {
    const res = await this.client.listTools();
    return res.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));
  }

  /**
   * Invoke a target tool. Returns the raw SDK result (content array + isError).
   *
   * FUNNEL INVARIANT (governance integrity): this stays a thin transport
   * primitive with NO policy of its own. It is public ONLY so the orchestrator
   * can wire it as the single `callTool` primitive handed INTO the governance
   * funnel (executeProbe). Probers must NEVER call this directly — they receive
   * a CallToolFn that is only ever invoked from inside executeProbe(). This is
   * enforced statically by the funnel guard in scripts/demo-local.ts, which fails
   * the gate if any file under src/probers/** invokes `.callTool(` itself.
   */
  async callTool(name: string, args: unknown): Promise<ToolCallResult> {
    const res = await this.client.callTool({
      name,
      arguments: (args ?? {}) as Record<string, unknown>,
    });
    return res as ToolCallResult;
  }

  async close(): Promise<void> {
    if (!this.connected) return;
    await this.client.close();
    this.connected = false;
  }
}

// Flatten a tool result's content array to a single text blob for pattern
// matching. Non-text parts are JSON-stringified so nothing is silently dropped.
export function resultText(res: ToolCallResult): string {
  if (!res || !Array.isArray(res.content)) return "";
  return res.content
    .map((c) => {
      if (c && typeof c === "object" && (c as ToolResultContentText).type === "text") {
        return (c as ToolResultContentText).text;
      }
      return JSON.stringify(c);
    })
    .join("\n");
}
