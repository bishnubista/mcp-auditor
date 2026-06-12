// Guild AI governance backend — STUB.
//
// >>> WIRE REAL GUILD SDK HERE IF TIME PERMITS <<<
//
// This implements the same GovernanceBackend interface as LocalGovernance so it
// is a drop-in replacement for the audit sink. In the demo, governance = Guild AI
// (Harness): permissioning which MCP servers/tools each prober may touch + an
// audit trail of every probe.
//
// Behavior contract for the hackathon:
//   - constructor takes { apiKey, projectId }.
//   - audit() throws NotImplemented UNLESS env GUILD_API_KEY is set.
//   - When GUILD_API_KEY IS set, we still log locally (never lose the trail) and
//     console.log exactly WHAT WOULD BE SENT to Guild — no real network call yet.
//
// node:fs only (via LocalGovernance) — no external dependencies.

import type { AuditEntry, GovernanceBackend } from "./index.ts";
import { LocalGovernance } from "./local.ts";

export interface GuildConfig {
  apiKey?: string;
  projectId?: string;
}

export class GuildGovernance implements GovernanceBackend {
  private readonly apiKey: string | undefined;
  private readonly projectId: string | undefined;
  // Mirror every event locally so the audit trail is never lost while the real
  // Guild SDK is unwired.
  private readonly local: LocalGovernance;

  constructor(config: GuildConfig = {}, localBackend: LocalGovernance = new LocalGovernance()) {
    this.apiKey = config.apiKey ?? process.env.GUILD_API_KEY;
    this.projectId = config.projectId ?? process.env.GUILD_PROJECT_ID;
    this.local = localBackend;
  }

  audit(entry: AuditEntry): void {
    if (!this.apiKey) {
      throw new Error(
        "GuildGovernance not implemented: set GUILD_API_KEY (or pass apiKey) to use the Guild backend stub.",
      );
    }

    // Always preserve the local trail first.
    this.local.audit(entry);

    // STUB: in the real integration, replace this with a Guild SDK call, e.g.
    //   await guild.events.record({ projectId: this.projectId, ...entry })
    const wouldSend = {
      destination: "guild-ai",
      projectId: this.projectId ?? "<unset>",
      event: entry,
    };
    console.log(
      `[guild:STUB] WOULD send audit event to Guild AI -> ${JSON.stringify(wouldSend)}`,
    );
  }
}
