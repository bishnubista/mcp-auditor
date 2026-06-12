// Local governance backend: writes one audit event per probe (allowed AND denied)
// to out/audit.jsonl. Allowlist enforcement itself lives in index.ts (the funnel);
// this backend is the durable audit trail.
//
// node:fs only — no external dependencies.

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { AuditEntry, GovernanceBackend } from "./index.ts";

// Default audit log location: mcp-auditor/out/audit.jsonl
// __dirname here is .../mcp-auditor/auditor/src/governance, so climb to mcp-auditor/.
const DEFAULT_AUDIT_PATH = resolve(
  import.meta.dir,
  "../../../out/audit.jsonl",
);

export class LocalGovernance implements GovernanceBackend {
  private readonly auditPath: string;

  constructor(auditPath: string = DEFAULT_AUDIT_PATH) {
    this.auditPath = auditPath;
    mkdirSync(dirname(this.auditPath), { recursive: true });
  }

  audit(entry: AuditEntry): void {
    appendFileSync(this.auditPath, `${JSON.stringify(entry)}\n`, "utf8");
  }

  get path(): string {
    return this.auditPath;
  }
}
