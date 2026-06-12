#!/usr/bin/env bun
/**
 * T11 — Publish the agent's audit output to cited.md (challenge requirement).
 *
 * cited.md (https://cited.md, operated by Senso.ai) is a real agent-native
 * publishing layer: publishers POST structured, citation-grounded content that
 * agents can read, cite, and pay for. This action renders our SAFE-T audit as a
 * citation-rich `cited.md` document and PUBLISHES it for real.
 *
 * PUBLISH POSTURE (real APIs, not local-only):
 *   - REAL (default): if CITED_API_KEY (Senso org key) is set, POST the document
 *     to the live Senso content API and print the returned published URL. This is
 *     a REAL action on the open web.
 *   - MISSING CREDENTIAL: if CITED_API_KEY is unset and NEITHER --offline nor
 *     CITED_OFFLINE=1 is given, EXIT NONZERO with an actionable error. Missing
 *     credentials are never silently degraded.
 *   - OFFLINE (opt-in only): with --offline or CITED_OFFLINE=1, skip the network,
 *     write out/cited.md and print the would-be publish payload (endpoint + title
 *     + doc sha256). This mode exists ONLY for the deterministic local gate.
 *   - On a real publish HTTP/network error: surface status + body and EXIT NONZERO.
 *
 * In ALL modes out/cited.md (the artifact being published) is written.
 *
 * ── CITATION HONESTY (Job A) ────────────────────────────────────────────────
 * Our findings key `SAFE-T####` ids that are THIS auditor's INTERNAL probe
 * taxonomy. The upstream catalog (secure-agentic-framework/saf-mcp, prefix
 * `SAF-T`) assigns DIFFERENT technique names to the same numbers (e.g. our
 * SAFE-T1106 = path traversal, but upstream SAF-T1106 = "Autonomous Loop
 * Exploit"). We therefore DECOUPLE: a finding's authoritative title is OUR probe
 * class; we cite the SAF-MCP catalog as the grounding FRAMEWORK. We deep-link to
 * a specific upstream technique page ONLY when our probe class cleanly matches
 * that page's real name (so a reader clicking any citation never finds a name
 * that contradicts the finding). See PROBE_TAXONOMY below.
 *
 * Inputs:
 *   out/findings.jsonl  (required; the agent's findings — shape below)
 *   out/audit.jsonl     (optional; governance audit trail → coverage line)
 *   templates/cited.md  (citation-rich skeleton with {{PLACEHOLDER}} markers)
 * Output:
 *   out/cited.md        (citation-grounded, publish-ready document)
 *
 * SECURITY: findings/evidence are UNTRUSTED target output. Evidence is fenced as
 * data and never executed or interpolated as instructions. The publish body is
 * sent as an opaque string; nothing from the target is eval'd.
 *
 * Env:
 *   CITED_API_KEY    Senso/cited.md org API key (sent as X-API-Key; tgr_live_/
 *                    tgr_test_). Presence → REAL publish. Absence → error unless
 *                    offline mode is explicitly requested.
 *   CITED_OFFLINE=1  Opt into offline (no-network) mode. Same as passing --offline.
 *   CITED_API_URL    Override the Senso API base URL (default below).
 *   CITED_HANDLE     Publisher handle/namespace for the cited.md slug (optional).
 *   FINDINGS_PATH    Override findings path (failure-path testing).
 *   AUDIT_PATH       Override audit path.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, "../../../out");
const FINDINGS_PATH = process.env.FINDINGS_PATH ?? join(OUT_DIR, "findings.jsonl");
const AUDIT_PATH = process.env.AUDIT_PATH ?? join(OUT_DIR, "audit.jsonl");
const TEMPLATE_PATH = resolve(HERE, "../../templates/cited.md");
const CITED_PATH = join(OUT_DIR, "cited.md");

const OFFLINE =
  process.env.CITED_OFFLINE === "1" || process.argv.slice(2).includes("--offline");

/**
 * GROUND-TRUTH FRAMEWORK — the SAF-MCP catalog (taxonomy SOURCE we ground in).
 *
 * Canonical repo: secure-agentic-framework/saf-mcp (formerly SAFE-MCP/safe-mcp;
 * the rename redirects). On-disk technique dirs use the `SAF-T####` form, e.g.
 * .../techniques/SAF-T1102/README.md → "SAF-T1102: Prompt Injection (Multiple
 * Vectors)" (verified live HTTP 200). We cite this catalog INDEX as the grounding
 * framework; we deep-link a specific technique page ONLY on a clean name match.
 */
const SAF_MCP_REPO = "https://github.com/secure-agentic-framework/saf-mcp";
const CITATION_BASE = `${SAF_MCP_REPO}/tree/main/techniques`;

/**
 * cited.md / Senso publish API (verified from docs.senso.ai + public references):
 *   - base URL : https://sdk.senso.ai/api/v1
 *   - auth     : X-API-Key: <org key>   (tgr_live_ / tgr_test_)
 *   - create   : POST /content/raw   body { title, summary, text }
 *                → HTTP 202 { id: <content_id> }; published content is served at
 *                  cited.md/<handle>/<slug>.
 * Base URL + path are isolated as constants for a one-line swap if the venue
 * contract differs. Override the base with CITED_API_URL.
 */
const CITED_API_BASE = process.env.CITED_API_URL ?? "https://sdk.senso.ai/api/v1";
const CITED_PUBLISH_PATH = "/content/raw";

type Severity = "critical" | "high" | "medium" | "low";
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

interface Finding {
  ts: string;
  safeT: string;
  tool: string;
  severity: Severity;
  probe: string;
  evidence: string;
  prober: string;
}
interface AuditEvent {
  tool?: string;
  verdict?: string;
  serverId?: string;
}

/**
 * PER-FINDING PROBE TAXONOMY (honest mapping).
 *
 * Keyed by OUR internal SAFE-T#### id. Each entry carries:
 *   - title       : the authoritative human name of OUR probe class. This is what
 *                   labels the finding — NOT any upstream technique name.
 *   - description : one-line plain-English description of what we actually probed.
 *   - deepLink    : when true, our probe class CLEANLY matches the same-numbered
 *                   upstream SAF-T technique, so we may deep-link that page and
 *                   show its real upstream name as a "related upstream technique".
 *                   When false, the upstream same-number technique name CONTRADICTS
 *                   our finding (e.g. SAF-T1106 = "Autonomous Loop Exploit" vs our
 *                   path traversal), so we DO NOT deep-link it — we cite the
 *                   catalog index instead and never display the mismatched name.
 *   - upstreamName: the REAL upstream technique name at that number (verified),
 *                   shown ONLY when deepLink is true and clearly marked "related".
 *
 * Verified upstream titles (live, secure-agentic-framework/saf-mcp):
 *   SAF-T1102 Prompt Injection (Multiple Vectors)   ← clean match for our 1102
 *   SAF-T1104 Over-Privileged Tool Abuse            (≈ excessive scope, but kept
 *                                                     index-grounded to be safe)
 *   SAF-T1106 Autonomous Loop Exploit               ← CONTRADICTS our path traversal
 *   SAF-T1402 Instruction Stenography — Tool Metadata Poisoning ← CONTRADICTS our outbound
 *   SAF-T1502 File-Based Credential Harvest         (≈ credential leak, kept index-grounded)
 */
interface ProbeTaxonomyEntry {
  title: string;
  description: string;
  deepLink: boolean;
  upstreamName?: string;
}
const PROBE_TAXONOMY: Record<string, ProbeTaxonomyEntry> = {
  "SAFE-T1106": {
    title: "Path Traversal",
    description:
      "Sandbox-escaping file read (../) that returned a file outside the tool's intended directory.",
    deepLink: false, // upstream SAF-T1106 = "Autonomous Loop Exploit" (contradicts)
  },
  "SAFE-T1502": {
    title: "Credential Leakage",
    description:
      "Plaintext secrets (DB password, API/signing keys) disclosed in tool output.",
    deepLink: false, // upstream SAF-T1502 = "File-Based Credential Harvest" (adjacent, not identical)
  },
  "SAFE-T1102": {
    title: "Tool-Description Poisoning / Prompt Injection",
    description:
      "Instruction-override text embedded in advertised tool metadata (a prompt-injection vector).",
    deepLink: true, // clean match: upstream SAF-T1102 = "Prompt Injection (Multiple Vectors)"
    upstreamName: "Prompt Injection (Multiple Vectors)",
  },
  "SAFE-T1104": {
    title: "Excessive Scope / Unauthorized Data Access",
    description:
      "A tool advertised narrow scope but returned rows from an off-limits table.",
    deepLink: false, // upstream SAF-T1104 = "Over-Privileged Tool Abuse" (adjacent, not identical)
  },
  "SAFE-T1402": {
    title: "Unvalidated Outbound Action",
    description:
      "A notification/egress tool honored an arbitrary attacker-supplied destination URL.",
    deepLink: false, // upstream SAF-T1402 = "Instruction Stenography" (contradicts)
  },
};

const UNMAPPED_ID = "SAFE-T (unmapped)";

function log(msg: string): void {
  // All diagnostics to stderr; stdout carries only the published URL / offline block.
  console.error(msg);
}

function die(msg: string): never {
  console.error(`[cited] ERROR: ${msg}`);
  process.exit(1);
}

function readJsonl<T>(path: string, required: boolean): T[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    if (required) die(`required input not found: ${path}`);
    return [];
  }
  const rows: T[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      rows.push(JSON.parse(t) as T);
    } catch {
      log(`[cited] WARN: skipping unparseable line in ${path}`);
    }
  }
  return rows;
}

/** Normalize a finding's SAFE-T#### id to the catalog's SAF-T#### dir slug. */
function techniqueSlug(safeT: string): string {
  const m = /SAFE-?T(\d{3,4})/i.exec(safeT);
  return m ? `SAF-T${m[1]}` : safeT;
}

function taxonomy(safeT: string): ProbeTaxonomyEntry {
  return (
    PROBE_TAXONOMY[safeT] ?? {
      title: "Unclassified Probe Finding",
      description: "A finding from a probe class without an internal taxonomy entry.",
      deepLink: false,
    }
  );
}

/** Derive a clean human title from the probe field as a fallback (e.g.
 * "unvalidated-outbound-action" → "Unvalidated Outbound Action"). */
function titleFromProbe(probe: string): string {
  return (probe || "finding")
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(" ");
}

/**
 * Honest citation for a finding. We ALWAYS ground in the SAF-MCP catalog.
 * - deepLink=true  → link the specific upstream technique page (clean name match)
 *                    and clearly mark the upstream name as a "related" technique.
 * - deepLink=false → link the catalog INDEX (the grounding framework), and do NOT
 *                    show the same-numbered upstream name (it would contradict).
 */
function citationFor(safeT: string): { url: string; label: string } {
  const t = taxonomy(safeT);
  if (t.deepLink) {
    const slug = techniqueSlug(safeT);
    return {
      url: `${CITATION_BASE}/${slug}`,
      label: `SAF-MCP catalog → related upstream technique ${slug}: ${t.upstreamName ?? slug}`,
    };
  }
  return {
    url: CITATION_BASE,
    label: "SAF-MCP technique catalog (grounding framework — index)",
  };
}

/** Fence untrusted evidence as a data block; neutralize ``` so it cannot break out. */
function fenceEvidence(evidence: string): string {
  const safe = (evidence ?? "").replace(/```/g, "ʼʼʼ");
  return "```text\n" + safe + "\n```";
}

function renderFinding(f: Finding, idx: number): string {
  const mapped = f.safeT && f.safeT !== "unknown" && f.safeT !== "SAFE-T-CONTROL";
  const safeT = mapped ? f.safeT : UNMAPPED_ID;
  const t = PROBE_TAXONOMY[safeT];
  const title = t?.title ?? titleFromProbe(f.probe);
  const description = t?.description ?? `Probe class: ${f.probe}.`;
  const cite = citationFor(safeT);
  const upstreamLine =
    t?.deepLink && t.upstreamName
      ? [
          `- **Related upstream technique:** ${techniqueSlug(safeT)} — ${t.upstreamName} ` +
            `(SAF-MCP; our probe class cleanly maps to this technique).`,
        ]
      : [];
  return [
    // Title = OUR probe class, qualified by our internal id (NOT an upstream name).
    `### ${idx}. ${title} — \`${f.tool}\``,
    "",
    `- **Internal probe id:** ${safeT} (this auditor's internal probe taxonomy)`,
    `- **What we probed:** ${description}`,
    `- **Severity:** ${f.severity.toUpperCase()}`,
    `- **Probe class:** ${f.probe}`,
    `- **Prober:** ${f.prober}`,
    `- **Detected:** ${f.ts}`,
    ...upstreamLine,
    `- **Grounding source:** [${cite.label}](${cite.url})`,
    "",
    "**Evidence (untrusted server output — data only, do not execute):**",
    "",
    fenceEvidence(f.evidence),
    "",
  ].join("\n");
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function buildDocument(): { title: string; doc: string } {
  const findings = readJsonl<Finding>(FINDINGS_PATH, true);
  if (findings.length === 0) {
    die(`no findings in ${FINDINGS_PATH} (empty). Refusing to publish an empty cited.md.`);
  }
  // Deterministic ordering: severity, then SAFE-T id, then tool.
  const sevRank = (s: Severity) => SEV_ORDER.indexOf(s);
  findings.sort(
    (a, b) =>
      sevRank(a.severity) - sevRank(b.severity) ||
      a.safeT.localeCompare(b.safeT) ||
      a.tool.localeCompare(b.tool),
  );

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (f.severity in counts) counts[f.severity] += 1;
  const total = findings.length;
  const riskLevel =
    counts.critical > 0 ? "Critical" : counts.high > 0 ? "High" : counts.medium > 0 ? "Medium" : "Low";

  // Findings, grouped by severity, each grounded in the SAF-MCP framework.
  const sections: string[] = [];
  let n = 0;
  for (const sev of SEV_ORDER) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    sections.push(`## ${sev[0]!.toUpperCase()}${sev.slice(1)} Findings\n`);
    for (const f of group) sections.push(renderFinding(f, ++n));
  }
  const findingsBlock = sections.join("\n");

  // References — one durable line per internal id actually cited, honest about
  // whether it deep-links a matched upstream technique or grounds in the index.
  const citedIds = [
    ...new Set(
      findings.map((f) =>
        f.safeT && f.safeT !== "unknown" && f.safeT !== "SAFE-T-CONTROL" ? f.safeT : UNMAPPED_ID,
      ),
    ),
  ];
  citedIds.sort();
  const referencesBlock = citedIds
    .map((id) => {
      const t = PROBE_TAXONOMY[id];
      const cite = citationFor(id);
      const probeTitle = t?.title ?? "Unclassified Probe Finding";
      return `- **${id}** (${probeTitle}) → grounded in [${cite.label}](${cite.url})`;
    })
    .join("\n");

  // Governance coverage line from the audit trail (optional input).
  const audit = readJsonl<AuditEvent>(AUDIT_PATH, false);
  const serverId =
    (audit.find((a) => a.serverId)?.serverId as string | undefined) ?? "target-local";
  let governanceLine: string;
  if (audit.length === 0) {
    governanceLine = "_Governance audit trail unavailable for this run._";
  } else {
    const allowed = audit.filter((a) => a.verdict === "allowed").length;
    const denied = audit.filter((a) => a.verdict === "denied").length;
    governanceLine =
      `**Governance coverage:** all ${audit.length} probe(s) were routed through the audit gate ` +
      `(${allowed} allowed, ${denied} denied) and recorded in \`audit.jsonl\` — no tool was invoked outside the gate.`;
  }

  const scanTs = findings[findings.length - 1]?.ts ?? new Date().toISOString();
  const title = `MCP Security Audit — ${total} finding(s) on ${serverId} (${riskLevel} risk)`;

  let tpl: string;
  try {
    tpl = readFileSync(TEMPLATE_PATH, "utf8");
  } catch {
    die(`cited.md template not found: ${TEMPLATE_PATH}`);
  }

  const doc = tpl
    .replaceAll("{{TITLE}}", title)
    .replaceAll("{{TARGET_SERVER}}", serverId)
    .replaceAll("{{SCAN_TIMESTAMP}}", scanTs)
    .replaceAll("{{CITATION_BASE}}", CITATION_BASE)
    .replaceAll("{{SAF_MCP_REPO}}", SAF_MCP_REPO)
    .replaceAll("{{SCOPE}}", "Governed probe sweep of a single allowlisted, live MCP server over stdio.")
    .replaceAll("{{CRITICAL_COUNT}}", String(counts.critical))
    .replaceAll("{{HIGH_COUNT}}", String(counts.high))
    .replaceAll("{{MEDIUM_COUNT}}", String(counts.medium))
    .replaceAll("{{LOW_COUNT}}", String(counts.low))
    .replaceAll("{{TOTAL_COUNT}}", String(total))
    .replaceAll("{{RISK_LEVEL}}", riskLevel)
    .replaceAll("{{GOVERNANCE_LINE}}", governanceLine)
    .replaceAll("{{FINDINGS}}", findingsBlock)
    .replaceAll("{{REFERENCES}}", referencesBlock);

  return { title, doc };
}

/** Build the Senso /content/raw request body. Markdown goes in `text`. */
function publishBody(title: string, doc: string): { title: string; summary: string; text: string } {
  return {
    title,
    summary: title,
    text: doc, // Senso content/raw expects the body under `text`.
  };
}

/**
 * REAL publish to the Senso (cited.md) content API. POSTs the document and prints
 * the published URL. On HTTP/network error, surfaces status+body and EXITS NONZERO.
 */
async function publishReal(title: string, doc: string, apiKey: string): Promise<void> {
  const endpoint = `${CITED_API_BASE}${CITED_PUBLISH_PATH}`;
  const digest = sha256(doc);
  const handle = process.env.CITED_HANDLE?.trim();
  log(`[cited] publish: REAL → POST ${endpoint} (doc sha256=${digest.slice(0, 12)})`);

  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "X-API-Key": apiKey,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(publishBody(title, doc)),
      signal: AbortSignal.timeout(20_000),
    });
  } catch (err) {
    die(
      `real publish to ${endpoint} failed (network/timeout): ${(err as Error).message}. ` +
        `Document was written to ${CITED_PATH}; re-run when the API is reachable, ` +
        `or pass --offline for the local gate.`,
    );
  }

  const text = await res.text();
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    parsed = undefined;
  }

  if (!res.ok) {
    // 401/403 etc. — surface status + body and exit nonzero. No pretend-success.
    die(
      `real publish to ${endpoint} returned HTTP ${res.status} ${res.statusText}. ` +
        `Response body: ${text.slice(0, 800)}`,
    );
  }

  // Success (Senso returns 202 with { id }). Resolve the served cited.md URL.
  const obj = parsed ?? {};
  const contentId =
    (obj.id as string | undefined) ??
    (obj.content_id as string | undefined) ??
    ((obj.data as Record<string, unknown> | undefined)?.id as string | undefined);
  const explicitUrl =
    (obj.url as string | undefined) ??
    (obj.cited_url as string | undefined) ??
    ((obj.data as Record<string, unknown> | undefined)?.url as string | undefined);
  const slug = (obj.slug as string | undefined) ?? contentId;
  const publishedUrl =
    explicitUrl ??
    (handle && slug ? `https://cited.md/${handle}/${slug}` : undefined) ??
    (slug ? `https://cited.md/${slug}` : undefined) ??
    "(published — URL not present in response)";

  log(`[cited] publish: REAL ok (HTTP ${res.status}, content id=${contentId ?? "?"})`);
  // stdout carries ONLY the published URL.
  console.log(`cited.md publish: live — ${publishedUrl}`);
}

/**
 * OFFLINE (opt-in) — no network. Print the would-be publish payload so the
 * deterministic gate has a stable artifact. stdout carries the offline block.
 */
function publishOffline(title: string, doc: string): void {
  const endpoint = `${CITED_API_BASE}${CITED_PUBLISH_PATH}`;
  const digest = sha256(doc);
  log(`[cited] publish: OFFLINE (explicit) — wrote ${CITED_PATH}, no network call made.`);
  const payload = {
    endpoint,
    method: "POST",
    headers: { "X-API-Key": "<CITED_API_KEY>", "Content-Type": "application/json" },
    body: { title, summary: title, text_sha256: digest, format: "markdown" },
  };
  console.log("cited.md publish: offline (--offline / CITED_OFFLINE=1) — wrote " + CITED_PATH);
  console.log("would-be publish payload:");
  console.log(JSON.stringify(payload, null, 2));
}

async function main(): Promise<void> {
  const { title, doc } = buildDocument();
  mkdirSync(OUT_DIR, { recursive: true });
  // Always write the artifact being published, regardless of mode.
  writeFileSync(CITED_PATH, doc, "utf8");
  log(`[cited] wrote ${CITED_PATH} (${doc.length} bytes, sha256=${sha256(doc).slice(0, 12)})`);

  const apiKey = process.env.CITED_API_KEY?.trim();

  if (apiKey) {
    // REAL publish is the default posture whenever a key is present.
    await publishReal(title, doc, apiKey);
    process.exit(0);
  }

  if (OFFLINE) {
    // Explicit opt-in local mode (deterministic gate only).
    publishOffline(title, doc);
    process.exit(0);
  }

  // No key and no explicit offline flag → fail loudly. Real-by-default posture.
  die(
    "CITED_API_KEY is not set, so there is nothing to publish to cited.md. " +
      "Set CITED_API_KEY (your Senso org key — see https://senso.ai) to publish for real, " +
      "or pass --offline (or CITED_OFFLINE=1) to write out/cited.md locally for the gate. " +
      `The document was written to ${CITED_PATH}.`,
  );
}

main();
