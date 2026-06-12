-- MCP Server Auditor — ClickHouse findings store (T7, STRETCH)
-- Idempotent schema + severity rollup queries for the security dashboard.
-- Finding shape (frozen): {ts, safeT, tool, severity, probe, evidence, prober}

-- ---------------------------------------------------------------------------
-- Findings table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mcp_findings
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
ORDER BY (severity, safeT, ts);

-- ---------------------------------------------------------------------------
-- Dashboard query 1 — counts by severity (ordered by severity rank)
-- ---------------------------------------------------------------------------
SELECT
    severity,
    count() AS count
FROM mcp_findings
GROUP BY severity
ORDER BY severity ASC;

-- ---------------------------------------------------------------------------
-- Dashboard query 2 — counts by SAFE-T class (safeT)
-- ---------------------------------------------------------------------------
SELECT
    safeT,
    count() AS count
FROM mcp_findings
GROUP BY safeT
ORDER BY count DESC, safeT ASC;
