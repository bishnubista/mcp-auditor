# Dockerfile — deploys the LIVE audit-stream-server (Bun) as a Render web service.
#
# WHY A DOCKER SERVICE
# --------------------
# Bun is not a first-class native Render runtime, so the streaming backend ships
# as a Docker image. Render builds this image and runs `bun run serve:stream`
# (src/service/audit-stream-server.ts), which binds to $PORT (Render injects it)
# and exposes POST /audits (x402-gated), GET /audits/:id/events (SSE), GET /audits/:id,
# GET /history, and GET /health.
#
# SEEDED TARGET CO-LOCATION (critical)
# ------------------------------------
# audit-stream-server.ts resolves the seeded stdio target RELATIVE to its own file:
#   ROOT_FROM_HERE   = ../../../  (from auditor/src/service/) -> the dir holding auditor/
#   SEEDED_TARGET    = <ROOT>/target-server/src/index.ts
# and at run time spawns `bun run <ROOT>/target-server/src/index.ts` as the audited
# MCP server. So the image MUST place auditor/ and target-server/ as SIBLINGS:
#   /app/auditor/src/service/audit-stream-server.ts  ->  ../../../ == /app
#   /app/target-server/src/index.ts                  (spawned seeded target)
# The seeded target also reads fixtures from target-server/sandbox + secrets (all
# <fake-demo-value> placeholders) and needs its own node_modules.
#
# BUILD CONTEXT must be the REPO ROOT (which contains auditor/ and target-server/).
# On Render set: dockerfilePath = auditor/Dockerfile, dockerContext = . (repo root),
# rootDir = (empty / repo root). See auditor/render.stream.yaml.

# --- deps for the auditor (streaming server) ---
FROM oven/bun:1 AS auditor-deps
WORKDIR /app/auditor
COPY auditor/package.json auditor/bun.lock ./
RUN bun install --frozen-lockfile

# --- deps for the seeded target (spawned at audit time) ---
FROM oven/bun:1 AS target-deps
WORKDIR /app/target-server
COPY target-server/package.json target-server/bun.lock ./
RUN bun install --frozen-lockfile

# --- runtime image: auditor/ + target-server/ as siblings under /app ---
FROM oven/bun:1 AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Seeded target: source + fixtures (sandbox/secrets) + resolved deps.
COPY --from=target-deps /app/target-server/node_modules ./target-server/node_modules
COPY target-server/package.json target-server/bun.lock ./target-server/
COPY target-server/src ./target-server/src
COPY target-server/sandbox ./target-server/sandbox
COPY target-server/secrets ./target-server/secrets

# Auditor (the streaming backend): resolved deps + full source.
COPY --from=auditor-deps /app/auditor/node_modules ./auditor/node_modules
COPY auditor/package.json auditor/bun.lock ./auditor/
COPY auditor/src ./auditor/src
COPY auditor/templates ./auditor/templates
COPY auditor/tsconfig.json ./auditor/tsconfig.json

# The server reads PORT from env (Render injects $PORT). Default for plain docker run.
ENV PORT=8910
EXPOSE 8910

# Container-level healthcheck hits the server's GET /health (200).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e "fetch('http://localhost:'+(process.env.PORT||8910)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

WORKDIR /app/auditor
CMD ["bun", "run", "src/service/audit-stream-server.ts"]
