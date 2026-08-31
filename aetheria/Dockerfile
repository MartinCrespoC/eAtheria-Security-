# ============================================================
# AETHERIA Security Platform — "todo solito" Dockerfile
#
# Single image that boots the whole platform on `docker compose up`:
#   1. Waits for PostgreSQL
#   2. Applies Prisma migrations automatically
#   3. Seeds the static catalog (CWE, licenses, AI providers/models)
#   4. Auto-generates runtime secrets (persisted in a volume)
#   5. Starts Next.js
#
# It ships the FULL node_modules (including the Prisma CLI and tsx) so the
# entrypoint can run migrations + seeding at runtime. WhatsApp (QR linking)
# runs on Baileys — a pure-Node client — so no browser is needed in the image.
# ============================================================

# --- Stage 1: Dependencies (full install incl. dev tools: prisma CLI, tsx) ---
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS deps

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* .npmrc ./
COPY prisma ./prisma/
RUN npm ci

# --- Stage 2: Build ---
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# NODE_OPTIONS heap cap for low-memory build hosts: tsc/next build spills
# to swap instead of growing until the kernel OOM killer fires.
# Public env inlined into the client bundle at build time
ARG NEXT_PUBLIC_TURNSTILE_SITE_KEY
ENV NEXT_PUBLIC_TURNSTILE_SITE_KEY=$NEXT_PUBLIC_TURNSTILE_SITE_KEY

# Build-only placeholder so `prisma generate` / `next build` validation passes
# in environments without a real database (CI). Overridden at runtime.
ARG DATABASE_URL="postgresql://build:build@localhost:5432/build"
ENV DATABASE_URL=$DATABASE_URL

ENV NEXT_TELEMETRY_DISABLED=1 \
  NODE_ENV=production \
  NODE_OPTIONS=--max-old-space-size=2048

# Generate the Prisma client, then build Next.js
RUN npx prisma generate
RUN npm run build

# --- Stage 3: Production Runner ---
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS runner
WORKDIR /app

ENV NODE_ENV=production \
  NEXT_TELEMETRY_DISABLED=1 \
  PORT=3000 \
  HOSTNAME=0.0.0.0

# Fonts (used by next/og satori for OG images), openssl (secret generation),
# curl (healthcheck). No browser needed — WhatsApp runs on Baileys (pure Node).
# p7zip-full provides `7z`, used by the upload pipeline to extract .7z and
# .rar archives (7z reads RAR incl. RAR5; `unrar` is non-free in Debian).
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  fonts-liberation \
  fonts-noto-color-emoji \
  openssl \
  curl \
  ca-certificates \
  p7zip-full \
  && rm -rf /var/lib/apt/lists/*

# Application: regular build + full node_modules so the entrypoint can run
# `prisma migrate deploy` / `tsx prisma/seed-catalog.ts` and Baileys
# (a serverExternalPackage) resolves straight from node_modules at runtime.
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/prisma ./prisma
# Security-rules + BugHunter seeds (entrypoint runs them on every boot —
# idempotent upserts). prisma/seed-data/bughunter-*.json rides along with the
# prisma/ copy above.
COPY --from=builder /app/scripts/seed-security-rules.ts ./scripts/seed-security-rules.ts
COPY --from=builder /app/scripts/seed-bughunter.ts ./scripts/seed-bughunter.ts
# Runtime config: `next start` loads this file from the project dir. Without
# it, experimental.proxyClientMaxBodySize falls back to the 10MB default and
# large archive uploads get truncated mid-body ("Failed to parse body as
# FormData"). Header/CSP config is already baked into the build output.
COPY --from=builder /app/next.config.ts ./next.config.ts

# Entrypoint: wait for DB -> migrate -> seed catalog -> start
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Run as the unprivileged `node` user (uid 1000). Pre-create the
# volume-mounted writable dirs with matching ownership so named volumes
# inherit it on first mount: uploads, .secrets, .baileys_auth.
RUN mkdir -p /app/uploads /app/.secrets /app/.baileys_auth \
  && chown -R node:node /app
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=5 \
  CMD curl -f http://localhost:3000/api/setup/status >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
