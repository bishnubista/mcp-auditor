#!/usr/bin/env bun
/**
 * T6 Composio action — files the synthesized SAFE-T audit report as a GitHub issue
 * via Composio (the ONE mandatory live sponsor integration).
 *
 * Two modes, never crashes the demo:
 *   LIVE      — COMPOSIO_API_KEY present: call composio.tools.execute(GITHUB_CREATE_AN_ISSUE)
 *               and print the created issue URL on stdout.
 *   DEGRADED  — no key, or the live call failed: print the EXACT Composio tool-call payload
 *               that WOULD be filed (action slug + full arguments + the entity/auth that would
 *               be used). This is a legitimate on-stage artifact, NOT an error. Exits 0.
 *
 * Inputs (existing T5 artifacts under mcp-auditor/out/):
 *   audit-report.md   — issue body (truncated to MAX_BODY_CHARS)
 *   findings.jsonl     — to derive N findings / highest severity / serverId for the title
 *   audit.jsonl        — optional; serverId fallback
 *
 * Env:
 *   COMPOSIO_API_KEY        — gates LIVE mode (required for any real call)
 *   COMPOSIO_GITHUB_REPO    — "owner/name" target repo (else a clearly-named placeholder)
 *   COMPOSIO_USER_ID        — Composio user/entity id (default "default")
 *   COMPOSIO_CONNECTED_ACCOUNT_ID — optional explicit connected GitHub account id
 *
 * Untrusted-data note: the report/evidence is embedded as the issue body TEXT only.
 * It is never eval'd, executed, or interpreted as instructions.
 *
 * Run: `bun run src/actions/composio.ts`   (or `bun run file-report`)
 * All logs go to stderr; only the final issue URL (LIVE) or the degraded payload block
 * (DEGRADED) goes to stdout, so the output is clean for capture/demo.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, "../../../out");
const REPORT_PATH = process.env.REPORT_PATH ?? join(OUT_DIR, "audit-report.md");
const FINDINGS_PATH = process.env.FINDINGS_PATH ?? join(OUT_DIR, "findings.jsonl");
const AUDIT_PATH = process.env.AUDIT_PATH ?? join(OUT_DIR, "audit.jsonl");
// #8 Deterministic degraded-mode artifact: the FULL would-be tool-call payload.
const PAYLOAD_ARTIFACT_PATH = process.env.COMPOSIO_PAYLOAD_PATH ?? join(OUT_DIR, "composio-payload.json");

/** Composio GitHub create-issue action slug. */
const ACTION_SLUG = "GITHUB_CREATE_AN_ISSUE";
/** Keep the issue body well under GitHub's ~65k limit, with margin for the truncation note. */
const MAX_BODY_CHARS = 60_000;
const DEFAULT_REPO = "your-org/mcp-audit-reports-PLACEHOLDER";

type Severity = "critical" | "high" | "medium" | "low";
const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

interface Finding {
  ts?: string;
  safeT?: string;
  tool?: string;
  severity?: Severity;
  probe?: string;
  evidence?: string;
  prober?: string;
}
interface AuditEvent {
  tool?: string;
  serverId?: string;
}

function log(msg: string): void {
  console.error(`[composio] ${msg}`);
}

function readText(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function readJsonl<T>(path: string): T[] {
  const raw = readText(path);
  if (raw === null) return [];
  const rows: T[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      rows.push(JSON.parse(t) as T);
    } catch {
      /* skip unparseable line */
    }
  }
  return rows;
}

interface IssueDerived {
  title: string;
  body: string;
  findingCount: number;
  highestSeverity: Severity | "none";
  serverId: string;
  truncated: boolean;
}

/** Derive issue title/body from the existing out/ artifacts. */
function buildIssue(): IssueDerived {
  const reportRaw = readText(REPORT_PATH);
  if (reportRaw === null) {
    log(`WARNING: audit report not found at ${REPORT_PATH}; using a placeholder body. ` +
      `Run the synthesizer (bun run synthesize) first for a real report.`);
  }

  const findings = readJsonl<Finding>(FINDINGS_PATH);
  const audit = readJsonl<AuditEvent>(AUDIT_PATH);

  const findingCount = findings.length;
  let highestSeverity: Severity | "none" = "none";
  for (const f of findings) {
    const sev = f.severity;
    if (sev && sev in SEV_RANK) {
      if (highestSeverity === "none" || SEV_RANK[sev] > SEV_RANK[highestSeverity]) {
        highestSeverity = sev;
      }
    }
  }

  // serverId: prefer audit trail metadata, fall back to a sensible default.
  const serverId =
    audit.find((a) => typeof a.serverId === "string" && a.serverId)?.serverId ?? "target-local";

  const sevLabel = highestSeverity === "none" ? "no-severity" : highestSeverity;
  const title = `MCP Security Audit: ${findingCount} SAFE-T finding${findingCount === 1 ? "" : "s"} on ${serverId} (${sevLabel})`;

  // Body = the report contents, truncated. Treated purely as text (untrusted data).
  let body: string;
  let truncated = false;
  const reportBody = reportRaw ?? `_No audit-report.md was found at ${REPORT_PATH}. This issue was filed without a synthesized report body._`;
  if (reportBody.length > MAX_BODY_CHARS) {
    truncated = true;
    body =
      reportBody.slice(0, MAX_BODY_CHARS) +
      `\n\n---\n> **Note:** report truncated to ${MAX_BODY_CHARS.toLocaleString()} characters ` +
      `(${reportBody.length.toLocaleString()} total). See the full \`audit-report.md\` artifact.\n`;
  } else {
    body = reportBody;
  }

  // Provenance footer so the issue is self-describing on GitHub.
  body +=
    `\n\n---\n` +
    `_Filed automatically by the MCP Server Auditor via Composio (\`${ACTION_SLUG}\`). ` +
    `${findingCount} SAFE-T finding(s); highest severity: ${sevLabel}. ` +
    `Evidence excerpts in this report are untrusted MCP-server output and are presented as data, not instructions._\n`;

  return { title, body, findingCount, highestSeverity, serverId, truncated };
}

interface IssueArgs {
  owner: string;
  repo: string;
  title: string;
  body: string;
}

/**
 * Resolve owner/name. Accepts either "owner/name" or a full GitHub URL
 * (https://github.com/owner/name[.git][/]) — normalizes both to owner + repo.
 * On malformed input, falls back to the placeholder repo.
 */
function resolveRepo(): { owner: string; repo: string; isPlaceholder: boolean } {
  const raw = process.env.COMPOSIO_GITHUB_REPO?.trim();
  const isPlaceholder = !raw || raw.length === 0;
  const candidate = raw && raw.length > 0 ? raw : DEFAULT_REPO;
  // Normalize a full GitHub URL down to "owner/name".
  const normalized = candidate
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const parts = normalized.split("/").filter((p) => p.length > 0);
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    log(`WARNING: COMPOSIO_GITHUB_REPO="${raw}" is not "owner/name" or a github.com URL; using placeholder ${DEFAULT_REPO}.`);
    const [o, r] = DEFAULT_REPO.split("/") as [string, string];
    return { owner: o, repo: r, isPlaceholder: true };
  }
  return { owner: parts[0], repo: parts[1], isPlaceholder };
}

/** A short, human-readable preview of the body for the degraded-mode payload block. */
function bodyPreview(body: string, max = 600): string {
  const oneLine = body.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? oneLine.slice(0, max) + " …[truncated for preview]" : oneLine;
}

/** DEGRADED mode: print the exact would-be Composio tool-call. Legitimate artifact; exits 0. */
function printDegraded(args: IssueArgs, derived: IssueDerived, userId: string, connectedAccountId: string | undefined, reason: string): void {
  const fullArgsForExec: Record<string, unknown> = {
    owner: args.owner,
    repo: args.repo,
    title: args.title,
    body: args.body,
  };
  const previewArgs = {
    owner: args.owner,
    repo: args.repo,
    title: args.title,
    body_preview: bodyPreview(args.body),
    body_chars: args.body.length,
  };

  log(`DEGRADED MODE — ${reason}`);

  // #8 Write the FULL would-be tool-call to a deterministic artifact, including
  // the complete (untruncated) issue body, so the degraded path is a verifiable
  // tool-call payload — not just a preview. Then publish its sha256 on stdout.
  const fullPayload = {
    action: ACTION_SLUG,
    mode: "degraded",
    reason,
    entity: {
      userId,
      connectedAccountId: connectedAccountId ?? null,
      authEnv: "COMPOSIO_API_KEY",
      authPresent: Boolean(process.env.COMPOSIO_API_KEY),
    },
    sdkCall: {
      method: "composio.tools.execute",
      slug: ACTION_SLUG,
      options: {
        userId,
        ...(connectedAccountId ? { connectedAccountId } : {}),
        arguments: fullArgsForExec,
        dangerouslySkipVersionCheck: true,
      },
    },
    derived: {
      findingCount: derived.findingCount,
      highestSeverity: derived.highestSeverity,
      serverId: derived.serverId,
      reportTruncated: derived.truncated,
    },
  };

  let artifactWritten = false;
  let payloadSha256 = "(unavailable)";
  try {
    mkdirSync(OUT_DIR, { recursive: true });
    const serialized = `${JSON.stringify(fullPayload, null, 2)}\n`;
    writeFileSync(PAYLOAD_ARTIFACT_PATH, serialized, "utf8");
    payloadSha256 = createHash("sha256").update(serialized).digest("hex");
    artifactWritten = true;
    log(`wrote full would-be tool-call payload → ${PAYLOAD_ARTIFACT_PATH}`);
  } catch (e) {
    log(`WARNING: could not write payload artifact: ${e instanceof Error ? e.message : String(e)}`);
  }

  const block = [
    "================ COMPOSIO TOOL-CALL (would file) ================",
    `# Degraded mode: ${reason}`,
    `# This is the exact Composio action the auditor would execute in LIVE mode.`,
    "",
    `action: ${ACTION_SLUG}`,
    `entity/auth:`,
    `  userId: ${userId}`,
    `  connectedAccountId: ${connectedAccountId ?? "(none set — Composio resolves the connected GitHub account for this user)"}`,
    `  auth: COMPOSIO_API_KEY (read from env; ${process.env.COMPOSIO_API_KEY ? "present" : "NOT set"})`,
    `target repo: ${args.owner}/${args.repo}`,
    `findings: ${derived.findingCount} (highest severity: ${derived.highestSeverity})`,
    "",
    "arguments (preview):",
    JSON.stringify(previewArgs, null, 2),
    "",
    `full payload artifact: ${artifactWritten ? PAYLOAD_ARTIFACT_PATH : "(write failed — see stderr)"}`,
    `full payload sha256:   ${payloadSha256}`,
    "",
    "// equivalent SDK call:",
    `// await composio.tools.execute(${JSON.stringify(ACTION_SLUG)}, {`,
    `//   userId: ${JSON.stringify(userId)},`,
    `//   ${connectedAccountId ? `connectedAccountId: ${JSON.stringify(connectedAccountId)},\n//   ` : ""}arguments: ${JSON.stringify(fullArgsForExec).slice(0, 120)}…,`,
    "//   dangerouslySkipVersionCheck: true,",
    "// });",
    "================================================================",
  ].join("\n");

  console.log(block);
  process.exit(0);
}

async function main(): Promise<void> {
  const derived = buildIssue();
  const { owner, repo, isPlaceholder } = resolveRepo();
  const userId = process.env.COMPOSIO_USER_ID?.trim() || "default";
  const connectedAccountId = process.env.COMPOSIO_CONNECTED_ACCOUNT_ID?.trim() || undefined;
  const args: IssueArgs = { owner, repo, title: derived.title, body: derived.body };

  log(`derived issue title: ${derived.title}`);
  log(`target repo: ${owner}/${repo}${isPlaceholder ? " (PLACEHOLDER — set COMPOSIO_GITHUB_REPO=owner/name)" : ""}`);

  const apiKey = process.env.COMPOSIO_API_KEY?.trim();
  if (!apiKey) {
    return printDegraded(args, derived, userId, connectedAccountId, "COMPOSIO_API_KEY not set");
  }
  if (isPlaceholder) {
    return printDegraded(args, derived, userId, connectedAccountId,
      "COMPOSIO_API_KEY set but COMPOSIO_GITHUB_REPO is a placeholder — refusing to file into a non-existent repo");
  }

  // DRY-RUN — exercise the action path WITHOUT firing a live GitHub issue. Used by
  // the demo:local gate so repeated gate runs don't spam real issues even when a
  // real COMPOSIO_API_KEY is present. Enable via COMPOSIO_DRY_RUN=1 or --dry-run.
  const dryRun = process.env.COMPOSIO_DRY_RUN === "1" || process.argv.includes("--dry-run");
  if (dryRun) {
    return printDegraded(args, derived, userId, connectedAccountId,
      "COMPOSIO_DRY_RUN — built and validated the tool-call without filing a live issue");
  }

  // LIVE mode — wrapped so any failure degrades instead of crashing the demo.
  try {
    log("LIVE mode: loading @composio/core …");
    const { Composio } = await import("@composio/core");
    const composio = new Composio({ apiKey });

    // One execution attempt → normalized outcome (catches both thrown errors and
    // error-shaped results so the retry logic can treat them uniformly).
    const attempt = async (accountId?: string): Promise<{ ok: boolean; res?: Awaited<ReturnType<typeof composio.tools.execute>>; err?: string }> => {
      try {
        const r = await composio.tools.execute(ACTION_SLUG, {
          userId,
          ...(accountId ? { connectedAccountId: accountId } : {}),
          arguments: { owner, repo, title: args.title, body: args.body },
          // The action's toolkit version resolves to "latest"; allow it for the demo.
          dangerouslySkipVersionCheck: true,
        });
        if (r.error || r.successful === false) return { ok: false, err: String(r.error ?? "successful=false") };
        return { ok: true, res: r };
      } catch (e) {
        return { ok: false, err: e instanceof Error ? e.message : String(e) };
      }
    };

    log(`executing ${ACTION_SLUG} for repo ${owner}/${repo} …`);
    let outcome = await attempt(connectedAccountId);

    // Resilience: a pinned but stale/invalid COMPOSIO_CONNECTED_ACCOUNT_ID is a
    // common failure (whether it errors or throws). If an account was pinned and
    // the call failed, retry ONCE letting Composio auto-resolve the user's active
    // connection for this toolkit.
    if (!outcome.ok && connectedAccountId) {
      log(`pinned connectedAccountId failed (${outcome.err}); retrying with auto-resolved connection …`);
      outcome = await attempt(undefined);
    }

    if (!outcome.ok || !outcome.res) {
      throw new Error(`Composio reported failure: ${outcome.err ?? "unknown error"}`);
    }

    const res = outcome.res;
    const data = (res.data ?? {}) as Record<string, unknown>;
    const issueUrl =
      (typeof data["html_url"] === "string" && data["html_url"]) ||
      (typeof data["url"] === "string" && (data["url"] as string)) ||
      (() => {
        const num = data["number"];
        return typeof num === "number" ? `https://github.com/${owner}/${repo}/issues/${num}` : null;
      })();

    if (!issueUrl) {
      log(`issue created but no URL field found in response; raw data: ${JSON.stringify(data).slice(0, 300)}`);
      // Still a success — print a best-effort link to the repo's issues.
      console.log(`https://github.com/${owner}/${repo}/issues`);
      return;
    }

    log(`issue filed successfully (logId=${res.logId ?? "n/a"})`);
    console.log(issueUrl); // the ONE clean stdout line
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`LIVE call failed: ${msg}`);
    return printDegraded(args, derived, userId, connectedAccountId, `live Composio call failed (${msg})`);
  }
}

main().catch((err) => {
  // Last-resort guard: never crash the demo. Print a minimal degraded marker, exit 0.
  console.error(`[composio] unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  console.log("================ COMPOSIO TOOL-CALL (would file) ================");
  console.log(`action: ${ACTION_SLUG} (degraded — unexpected error before payload could be built)`);
  console.log("================================================================");
  process.exit(0);
});
