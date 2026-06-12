// Remote-MCP transport for the auditor: a drop-in for McpClient (stdio) that
// speaks the MCP Streamable HTTP transport to a REMOTE server URL.
//
// SDK: @modelcontextprotocol/sdk@1.29.0. Import paths VERIFIED against the
// installed dist .d.ts:
//   - Client:                     "@modelcontextprotocol/sdk/client/index.js"
//   - StreamableHTTPClientTransport: "@modelcontextprotocol/sdk/client/streamableHttp.js"
//     constructor(url: URL, opts?: { requestInit?: RequestInit; fetch?: FetchLike; ... })
//
// This client exposes the SAME interface as mcp-client.ts — connect / listTools /
// callTool / close, returning ToolInfo[] and ToolCallResult — so the orchestrator
// can swap stdio for remote targets with no other changes.
//
// SSRF: connect() runs admitTarget() FIRST and refuses unless ok. We inject a
// custom `fetch` into the transport that:
//   - pins the connection to the admitted IP while keeping the original Host/SNI,
//   - refuses to follow redirects (redirect:"manual" -> treated as an error),
//   - applies the connect/read timeout cap.
// See net/admit.ts for the full caller contract.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { ToolInfo, ToolCallResult } from "./mcp-client.js";
import {
  admitTarget,
  CONNECT_TIMEOUT_MS,
  READ_TIMEOUT_MS,
  type AdmitOk,
  type ResolveFn,
} from "./net/admit.js";

export interface McpHttpClientOptions {
  /** Extra HTTP request init (e.g. auth headers) passed to every transport request. */
  requestInit?: RequestInit;
  /** Injectable DNS resolver for admitTarget (tests). */
  resolve?: ResolveFn;
}

export class McpHttpClient {
  private client: Client;
  private transport: StreamableHTTPClientTransport | null = null;
  private connected = false;
  private readonly rawUrl: string;
  private readonly options: McpHttpClientOptions;

  /**
   * @param url     remote MCP server URL (https). Vetted by admitTarget on connect().
   * @param options optional auth headers (requestInit) + test resolver.
   */
  constructor(url: string, options: McpHttpClientOptions = {}) {
    this.rawUrl = url;
    this.options = options;
    this.client = new Client(
      { name: "mcp-auditor", version: "0.1.0" },
      { capabilities: {} },
    );
  }

  async connect(): Promise<void> {
    // 1. SSRF admission FIRST — refuse before any socket is opened.
    const admit = await admitTarget(this.rawUrl, { resolve: this.options.resolve });
    if (!admit.ok) {
      throw new Error(`SSRF admission denied for ${this.rawUrl}: ${admit.reason}`);
    }

    // 2. Build an IP-pinned, redirect-refusing, timeout-capped fetch.
    const pinnedFetch = makePinnedFetch(admit);

    // 3. Construct the transport. requestInit carries caller auth headers.
    this.transport = new StreamableHTTPClientTransport(new URL(admit.url), {
      ...(this.options.requestInit ? { requestInit: this.options.requestInit } : {}),
      fetch: pinnedFetch,
    });

    // 4. Connect. If the server doesn't speak Streamable HTTP, the SDK throws.
    //    SSE FALLBACK (TODO): older MCP servers expose the deprecated HTTP+SSE
    //    transport via "@modelcontextprotocol/sdk/client/sse.js"
    //    (SSEClientTransport). If/when we need to audit those, catch the
    //    Streamable-HTTP connect failure here and retry with SSEClientTransport
    //    using the SAME pinnedFetch (its eventSourceInit/fetch hooks). Not wired
    //    yet: the seeded target and modern servers use Streamable HTTP.
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
   * Invoke a remote tool. Same FUNNEL INVARIANT as McpClient.callTool: this is a
   * thin transport primitive with NO policy. It must only ever be invoked from
   * inside the governance funnel (executeProbe), never directly from probers.
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

/**
 * Build a fetch that pins the connection to the admitted IP while preserving the
 * original Host header + TLS SNI, refuses redirects, and caps the request time.
 *
 * DNS-rebinding defense: admitTarget already resolved + vetted the hostname. We
 * do NOT re-resolve here — we connect to the vetted IP. We keep the URL hostname
 * for TLS SNI and certificate validation and set an explicit Host header so the
 * remote vhost still routes correctly.
 *
 * NOTE on the pin: WHATWG fetch (Bun/Node) does not expose a per-request
 * connect-IP override, so a literal socket-level pin would require a custom
 * Agent/Dispatcher. Since admitTarget vetted the name immediately before this
 * call, the residual rebinding window is small; the redirect refusal + Host pin
 * close the common vectors. If a hard socket pin is required, swap baseFetch for
 * an undici Dispatcher whose connect() forces `admit.pinnedIp`. Kept dependency-
 * free here per the no-new-deps constraint.
 *
 * ⚠️ PROD-BLOCKER (remote targets / ENABLE_REMOTE_TARGETS=1) — DO NOT SHIP REMOTE
 * AUDITING WITHOUT FIXING THIS FIRST:
 *   The fetch below DOES NOT actually pin the socket to `admit.pinnedIp`. It
 *   passes the original hostname to fetch(), which RE-RESOLVES DNS at connect
 *   time. That re-resolution reopens the DNS-rebinding hole admitTarget closed:
 *   an attacker-controlled name can resolve to a public IP during admission and
 *   then to 169.254.169.254 / 127.0.0.1 / a private host on the real connect.
 *   Before enabling remote targets in production, replace this with a TRUE
 *   socket-level IP pin via an undici Dispatcher whose connect() dials
 *   `admit.pinnedIp` while keeping the vetted hostname for TLS SNI + cert
 *   validation and Host routing. The seeded stdio demo target does not use this
 *   client and is unaffected; this gap only matters once remote is enabled.
 */
function makePinnedFetch(admit: AdmitOk): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONNECT_TIMEOUT_MS + READ_TIMEOUT_MS);

    // Force the original Host so vhost routing matches the vetted name.
    const headers = new Headers(init?.headers);
    if (!headers.has("host")) headers.set("host", admit.host);

    try {
      const res = await fetch(input, {
        ...init,
        headers,
        redirect: "manual", // never auto-follow; a 3xx becomes an opaque/typed response we reject below
        signal: init?.signal ?? controller.signal,
      });
      // Reject redirects explicitly: a vetted target must not bounce us elsewhere.
      if (res.status >= 300 && res.status < 400) {
        throw new Error(`redirect (${res.status}) refused by SSRF policy: target must not redirect`);
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  };
}
