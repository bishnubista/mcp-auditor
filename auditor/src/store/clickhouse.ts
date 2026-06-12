/**
 * T7 (STRETCH) — ClickHouse findings store + severity dashboard.
 *
 * Reads out/findings.jsonl, connects to ClickHouse (only when CLICKHOUSE_URL is
 * set / reachable), ensures schema, inserts findings, runs the severity rollup
 * query, and prints a dashboard-style table to stdout.
 *
 * GRACEFUL DEGRADATION (hard requirement): if ClickHouse is unreachable, this
 * does NOT crash — it prints a clearly-labeled notice and computes the SAME
 * rollup in-memory from findings.jsonl, prints the dashboard, and exits 0.
 * The demo always shows a dashboard.
 *
 * This module is ADDITIVE and independent of demo:local — it does not touch
 * the core pipeline.
 *
 * Usage:
 *   bun run src/store/clickhouse.ts                 # default findings path
 *   bun run src/store/clickhouse.ts -- <findings.jsonl path>
 *   CLICKHOUSE_URL=http://localhost:8123 bun run src/store/clickhouse.ts
 */

import { createClient, ClickHouseLogLevel } from "@clickhouse/client";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const TABLE = "mcp_findings";

// Severity rank used for stable ordering both live and in-memory.
const SEVERITY_RANK: Record<string, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  info: 5,
};

/** Frozen finding shape from findings.jsonl. */
interface Finding {
  ts: string;
  safeT: string;
  tool: string;
  severity: string;
  probe: string;
  prober: string;
  evidence: string;
}

interface RollupRow {
  key: string;
  count: number;
}

// ---------------------------------------------------------------------------
// Schema + dashboard queries (kept in sync with src/store/schema.sql).
// ---------------------------------------------------------------------------
const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS ${TABLE}
(
    ts        DateTime,
    safeT     LowCardinality(String),
    tool      LowCardinality(String),
    severity  Enum8('critical' = 1, 'high' = 2, 'medium' = 3, 'low' = 4, 'info' = 5),
    probe     String,
    prober    String,
    evidence  String
)
ENGINE = MergeTree
ORDER BY (severity, safeT, ts)
`.trim();

const SEVERITY_ROLLUP_SQL = `
SELECT severity AS key, count() AS count
FROM ${TABLE}
GROUP BY severity
ORDER BY severity ASC
`.trim();

const SAFET_ROLLUP_SQL = `
SELECT safeT AS key, count() AS count
FROM ${TABLE}
GROUP BY safeT
ORDER BY count DESC, safeT ASC
`.trim();

// ---------------------------------------------------------------------------
// findings.jsonl loading
// ---------------------------------------------------------------------------
function defaultFindingsPath(): string {
  // src/store -> auditor -> mcp-auditor/out/findings.jsonl
  return resolve(__dirname, "../../../out/findings.jsonl");
}

function loadFindings(path: string): Finding[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`[clickhouse] cannot read findings file: ${path}`);
    console.error(`[clickhouse] ${(err as Error).message}`);
    process.exit(1);
  }
  const findings: Finding[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      findings.push(JSON.parse(trimmed) as Finding);
    } catch {
      console.error(`[clickhouse] skipping malformed line: ${trimmed.slice(0, 80)}`);
    }
  }
  if (findings.length === 0) {
    console.error(`[clickhouse] no findings parsed from ${path} — nothing to report.`);
    process.exit(1);
  }
  return findings;
}

/** Convert ISO ts to a ClickHouse-friendly DateTime string (UTC, seconds). */
function toClickHouseDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "1970-01-01 00:00:00";
  // 'YYYY-MM-DD HH:MM:SS' in UTC
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "").replace("Z", "");
}

// ---------------------------------------------------------------------------
// In-memory rollup (degradation path) — identical grouping semantics to SQL.
// ---------------------------------------------------------------------------
function rollupBySeverity(findings: Finding[]): RollupRow[] {
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (SEVERITY_RANK[a.key] ?? 99) - (SEVERITY_RANK[b.key] ?? 99));
}

function rollupBySafeT(findings: Finding[]): RollupRow[] {
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.safeT, (counts.get(f.safeT) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

// ---------------------------------------------------------------------------
// Dashboard rendering
// ---------------------------------------------------------------------------
function renderTable(title: string, header: string, rows: RollupRow[]): string {
  const keyWidth = Math.max(header.length, ...rows.map((r) => r.key.length), 8);
  const countWidth = Math.max(5, ...rows.map((r) => String(r.count).length));
  const total = rows.reduce((s, r) => s + r.count, 0);

  const line = `+${"-".repeat(keyWidth + 2)}+${"-".repeat(countWidth + 2)}+`;
  const out: string[] = [];
  out.push(title);
  out.push(line);
  out.push(`| ${header.padEnd(keyWidth)} | ${"count".padStart(countWidth)} |`);
  out.push(line);
  for (const r of rows) {
    out.push(`| ${r.key.padEnd(keyWidth)} | ${String(r.count).padStart(countWidth)} |`);
  }
  out.push(line);
  out.push(`| ${"TOTAL".padEnd(keyWidth)} | ${String(total).padStart(countWidth)} |`);
  out.push(line);
  return out.join("\n");
}

function printDashboard(
  source: string,
  bySeverity: RollupRow[],
  bySafeT: RollupRow[],
): void {
  console.log("");
  console.log("==================================================================");
  console.log("  MCP AUDITOR — SECURITY FINDINGS DASHBOARD");
  console.log(`  source: ${source}`);
  console.log("==================================================================");
  console.log("");
  console.log(renderTable("Findings by severity", "severity", bySeverity));
  console.log("");
  console.log(renderTable("Findings by SAFE-T class", "safeT", bySafeT));
  console.log("");
}

// ---------------------------------------------------------------------------
// ClickHouse live path
// ---------------------------------------------------------------------------
async function tryLivePath(findings: Finding[]): Promise<boolean> {
  const url = process.env.CLICKHOUSE_URL ?? "http://localhost:8123";
  const username = process.env.CLICKHOUSE_USER;
  const password = process.env.CLICKHOUSE_PASSWORD;
  const database = process.env.CLICKHOUSE_DATABASE;

  const client = createClient({
    url,
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
    ...(database ? { database } : {}),
    request_timeout: 5000,
    // Silence the client's internal connection-refused WARN so the degradation
    // notice we print ourselves is the only signal in the demo output.
    log: { level: ClickHouseLogLevel.OFF },
  });

  try {
    const pong = await client.ping();
    if (!pong.success) {
      throw new Error(`ping failed: ${"error" in pong ? String(pong.error) : "unknown"}`);
    }
    console.error(`[clickhouse] connected to ${url} — running live path.`);

    // Ensure schema (idempotent).
    await client.command({ query: CREATE_TABLE_SQL });

    // Insert findings.
    const rows = findings.map((f) => ({
      ts: toClickHouseDateTime(f.ts),
      safeT: f.safeT,
      tool: f.tool,
      severity: f.severity,
      probe: f.probe,
      prober: f.prober,
      evidence: f.evidence,
    }));
    await client.insert({
      table: TABLE,
      values: rows,
      format: "JSONEachRow",
    });
    console.error(`[clickhouse] inserted ${rows.length} findings into ${TABLE}.`);

    // Run rollup queries.
    const sevRs = await client.query({ query: SEVERITY_ROLLUP_SQL, format: "JSONEachRow" });
    const bySeverity = (await sevRs.json<RollupRow>()).map((r) => ({
      key: String(r.key),
      count: Number(r.count),
    }));
    const safeRs = await client.query({ query: SAFET_ROLLUP_SQL, format: "JSONEachRow" });
    const bySafeT = (await safeRs.json<RollupRow>()).map((r) => ({
      key: String(r.key),
      count: Number(r.count),
    }));

    printDashboard(`ClickHouse @ ${url} (table ${TABLE})`, bySeverity, bySafeT);
    await client.close();
    return true;
  } catch (err) {
    await client.close().catch(() => {});
    console.error(
      `[clickhouse] live path unavailable: ${(err as Error).message ?? String(err)}`,
    );
    return false;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const argPath = process.argv[2];
  const findingsPath = argPath ? resolve(argPath) : defaultFindingsPath();
  const findings = loadFindings(findingsPath);

  const live = await tryLivePath(findings);

  if (!live) {
    console.error(
      "[clickhouse] ClickHouse unavailable — rendering local severity rollup instead.",
    );
    const bySeverity = rollupBySeverity(findings);
    const bySafeT = rollupBySafeT(findings);
    printDashboard(`in-memory (degraded) — ${findingsPath}`, bySeverity, bySafeT);
  }

  process.exit(0);
}

main().catch((err) => {
  // Last-resort guard: never crash the demo. Degrade fully in-memory.
  console.error(`[clickhouse] unexpected error: ${(err as Error).message ?? String(err)}`);
  process.exit(0);
});
