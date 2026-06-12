# Dockerfile — deploys the Next.js auditor UI as a Render web service.
#
# WHY DOCKER
# ----------
# The repo standardizes on Bun, which isn't a first-class native Render runtime,
# so the UI ships as a Docker image (matching auditor/ and target-server/). The
# image is built from next.config.ts `output: "standalone"`, which traces only
# the runtime deps the server actually imports — a much smaller image than COPYing
# the full node_modules.
#
# BUILD-TIME BACKEND URL (critical)
# ---------------------------------
# Next.js inlines NEXT_PUBLIC_* vars at BUILD time, not run time. The streaming
# backend origin must therefore arrive as a Docker build ARG before `bun run build`,
# or the deployed bundle won't know where the backend is. Render exposes a service's
# env vars to the Docker build, so render.yaml sets NEXT_PUBLIC_AUDIT_BACKEND_URL
# and this Dockerfile promotes it ARG -> ENV before the build step.

# --- deps: resolve from the lockfile for reproducible installs ---
FROM oven/bun:1 AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# --- build: produce the standalone server bundle ---
FROM oven/bun:1 AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Backend origin baked into the client bundle (see header note). Empty default =>
# the UI falls back to its built-in mock stream (lib/connect.ts isMockMode()).
ARG NEXT_PUBLIC_AUDIT_BACKEND_URL=""
ENV NEXT_PUBLIC_AUDIT_BACKEND_URL=${NEXT_PUBLIC_AUDIT_BACKEND_URL}
ENV NEXT_TELEMETRY_DISABLED=1

RUN bun run build

# --- runtime: minimal standalone image ---
FROM oven/bun:1-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# server.js binds to HOSTNAME:PORT; 0.0.0.0 so Render can reach it.
ENV HOSTNAME=0.0.0.0

# The standalone output: server.js + minimal node_modules + traced .next server files.
COPY --from=build /app/.next/standalone ./
# Static assets (CSS/JS chunks) and any public/ files are NOT in standalone — copy them in.
COPY --from=build /app/.next/static ./.next/static

# Render injects $PORT at runtime; default to 3000 for plain `docker run`.
ENV PORT=3000
EXPOSE 3000

CMD ["bun", "run", "server.js"]
