// Guild AI (Harness) governance backend — REAL implementation.
//
// Guild AI in this hackathon is the agent-governance / control-plane sponsor:
// it permissions which MCP servers/tools each prober may touch and records an
// audit trail of every probe. This backend is the AUDIT SINK side — it ships
// every governance event (allowed AND denied) to the Guild API.
//
// It implements the same GovernanceBackend interface as LocalGovernance, so it
// is a drop-in replacement. The permission/allowlist gate itself lives in
// index.ts (the funnel) and is unchanged by this file.
//
// DESIGN NOTES (read before changing):
//   - No first-party Guild TS/bun SDK is cleanly installable as of this build
//     (npm `guild-ai` is a 357-byte unrelated placeholder; the governance
//     sponsor ships no public @guildai/* SDK). So we talk to a REST endpoint
//     with the built-in `fetch` — zero new dependencies, matching local.ts.
//   - Guild's current public CLI API exposes session events, not a generic
//     audit-ingest endpoint. When GUILD_SESSION_ID is set, this backend posts
//     each audit entry into that session:
//       POST  ${GUILD_API_URL}/sessions/${GUILD_SESSION_ID}/events
//       Body: { mode: "json", content: { projectId, source, event } }
//     Some sessions reject later writes, so the current live demo path uses
//     GUILD_CONTEXT_SINK=1 to create draft workspace context versions instead:
//       POST  ${GUILD_API_URL}/workspaces/${GUILD_PROJECT_ID}/contexts
//       Body: { status: "DRAFT", context: markdown, summary: string }
//   - Fallback assumed REST contract (one-line change if the real endpoint exists):
//       POST  ${GUILD_API_URL}/audit
//       Headers: Authorization: Bearer ${GUILD_API_KEY}
//                Content-Type: application/json
//                X-Guild-Project: ${GUILD_PROJECT_ID}   (when set)
//       Body:    { projectId, source: "mcp-auditor", event: <AuditEntry> }
//   - The Guild POST is FIRE-AND-FORGET with a hard timeout: the demo must never
//     block or crash on a slow/failed network call. Every event is ALSO mirrored
//     to the local audit.jsonl so the on-stage trail exists regardless.
//   - The key is read from env ONLY — never hardcoded, never committed.
//
// node:fs only (via LocalGovernance) + built-in fetch/AbortController.

import type { AuditEntry, GovernanceBackend } from "./index.ts";
import { LocalGovernance } from "./local.ts";

export interface GuildConfig {
  apiKey?: string;
  apiUrl?: string;
  projectId?: string;
  sessionId?: string;
  contextSink?: boolean;
}

// Guild CLI `doctor` reports this as the current API server.
const DEFAULT_GUILD_API_URL = "https://app.guild.ai/api";
// Path the AuditEntry is POSTed to. If Guild uses "/events", change this line.
const GUILD_AUDIT_PATH = "/audit";
// Network calls are fire-and-forget but bounded so the demo never hangs.
const GUILD_TIMEOUT_MS = 3000;

export class GuildGovernance implements GovernanceBackend {
  private readonly apiKey: string | undefined;
  private readonly apiUrl: string;
  private readonly projectId: string | undefined;
  private readonly sessionId: string | undefined;
  private readonly contextSink: boolean;
  // Mirror every event locally so the audit trail is never lost even if the
  // Guild network call is slow or fails.
  private readonly local: LocalGovernance;

  constructor(
    config: GuildConfig = {},
    localBackend: LocalGovernance = new LocalGovernance(),
  ) {
    this.apiKey = config.apiKey ?? process.env.GUILD_API_KEY;
    this.apiUrl = (
      config.apiUrl ??
      process.env.GUILD_API_URL ??
      DEFAULT_GUILD_API_URL
    ).replace(/\/+$/, "");
    this.projectId = config.projectId ?? process.env.GUILD_PROJECT_ID;
    this.sessionId = config.sessionId ?? process.env.GUILD_SESSION_ID;
    this.contextSink =
      config.contextSink ?? process.env.GUILD_CONTEXT_SINK === "1";
    this.local = localBackend;
  }

  /**
   * Records a governance event. The local mirror is written SYNCHRONOUSLY first
   * (so the on-stage audit.jsonl is always complete and ordered), then the Guild
   * POST is launched fire-and-forget with a timeout. This method NEVER throws
   * into the demo path: a missing key degrades to local-only, and any network
   * error is caught and logged to stderr.
   */
  audit(entry: AuditEntry): void {
    // 1. Always preserve the durable local trail first — this is what the demo
    //    reads, so it must succeed even when Guild is unreachable or unset.
    this.local.audit(entry);

    // 2. No key → local-only, never throw. This backend is opt-in: the funnel
    //    defaults to LocalGovernance, so an unconfigured Guild backend simply
    //    behaves like the local one rather than breaking the demo path.
    if (!this.apiKey) {
      return;
    }

    // 3. Key present → ship to Guild AI. Fire-and-forget: we do not await here so
    //    a slow Guild API cannot stall the prober fan-out. Errors are swallowed
    //    to stderr; the local mirror is the source of truth for the demo.
    void this.sendToGuild(entry);
  }

  private async sendToGuild(entry: AuditEntry): Promise<void> {
    const url = this.contextSink && this.projectId
      ? `${this.apiUrl}/workspaces/${encodeURIComponent(this.projectId)}/contexts`
      : this.sessionId
      ? `${this.apiUrl}/sessions/${encodeURIComponent(this.sessionId)}/events`
      : `${this.apiUrl}${GUILD_AUDIT_PATH}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
    };
    if (this.projectId && !this.sessionId && !this.contextSink) {
      headers["X-Guild-Project"] = this.projectId;
    }

    const event = {
      projectId: this.projectId ?? null,
      source: "mcp-auditor",
      event: entry,
    };
    const body = JSON.stringify(this.requestBody(entry, event));

    // On-stage "governance is live" proof: show exactly what is being shipped.
    console.log(
      `[guild] -> POST ${url} ${entry.verdict.toUpperCase()} ${entry.agent} ${entry.tool} ${entry.safeT} (payload ${entry.payloadHash})`,
    );

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), GUILD_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
      console.error(`[guild] audit -> ${res.status} ${res.statusText}`);
    } catch (err) {
      const msg =
        err instanceof Error && err.name === "AbortError"
          ? `timeout after ${GUILD_TIMEOUT_MS}ms`
          : err instanceof Error
            ? err.message
            : String(err);
      // Degrade gracefully: the local mirror already holds this event.
      console.error(`[guild] audit -> FAILED (${msg}); mirrored locally`);
    } finally {
      clearTimeout(timer);
    }
  }

  private requestBody(entry: AuditEntry, event: unknown): unknown {
    if (this.contextSink && this.projectId) {
      const pretty = JSON.stringify(event, null, 2);
      return {
        status: "DRAFT",
        summary: `MCP audit event ${entry.safeT} ${entry.verdict}`,
        context:
          `# MCP Auditor Governance Event\n\n` +
          `\`\`\`json\n${pretty}\n\`\`\`\n`,
      };
    }
    if (this.sessionId) {
      return { mode: "json", content: event };
    }
    return event;
  }
}
