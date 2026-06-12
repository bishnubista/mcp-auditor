# Dockerfile — deploys the seeded vulnerable target MCP server over Streamable HTTP.
#
# Bun is not a first-class native Render runtime, so this target ships as a Docker
# web service. Render builds this image and runs `bun run src/http.ts`, which binds
# to $PORT (Render injects it) and exposes POST /mcp + GET /health.
#
# This image runs the HTTP entrypoint ONLY. The stdio entrypoint (src/index.ts) and the
# local demo:local pipeline are unaffected — this file is additive deploy config.

FROM oven/bun:1-slim AS deps
WORKDIR /app
# Install deps against the lockfile for reproducible builds.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:1-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Bring in resolved dependencies, then the source (src/ + sandbox/ + secrets/ fixtures
# the seeded tools read from — all <fake-demo-value> placeholders).
COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock ./
COPY src ./src
COPY sandbox ./sandbox
COPY secrets ./secrets

# Render provides $PORT at runtime; default to 8787 for plain `docker run`.
ENV PORT=8787
EXPOSE 8787

CMD ["bun", "run", "src/http.ts"]
