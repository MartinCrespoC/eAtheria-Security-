#!/bin/sh
# ============================================================
# AETHERIA Security Platform — container entrypoint
#
# Makes the platform boot "todo solito" (fully autonomous):
#   1. Ensures NEXTAUTH_SECRET / ENCRYPTION_KEY exist (auto-generates and
#      persists them in a volume so they survive restarts).
#   2. Waits until PostgreSQL accepts connections.
#   3. Applies Prisma migrations (idempotent).
#   4. Seeds the static catalog: CWE, licenses, AI providers/models (idempotent).
#   5. Starts the Next.js production server.
# ============================================================
set -e

echo "[AETHERIA] Booting platform..."

# ── 1. Runtime secrets ────────────────────────────────────────────────────────
# Priority: value provided via environment  >  persisted value  >  auto-generate.
SECRETS_DIR="${SECRETS_DIR:-/app/.secrets}"
SECRETS_FILE="$SECRETS_DIR/runtime.env"
mkdir -p "$SECRETS_DIR"

read_persisted() {
  # read_persisted KEY  -> prints the stored value (if any)
  [ -f "$SECRETS_FILE" ] || return 0
  grep "^$1=" "$SECRETS_FILE" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d "'"
}

if [ -z "$NEXTAUTH_SECRET" ]; then
  NEXTAUTH_SECRET="$(read_persisted NEXTAUTH_SECRET)"
  if [ -z "$NEXTAUTH_SECRET" ]; then
    NEXTAUTH_SECRET="$(openssl rand -base64 32)"
    echo "NEXTAUTH_SECRET='$NEXTAUTH_SECRET'" >> "$SECRETS_FILE"
    echo "[AETHERIA] Generated NEXTAUTH_SECRET (persisted to $SECRETS_FILE)"
  fi
fi

if [ -z "$ENCRYPTION_KEY" ]; then
  ENCRYPTION_KEY="$(read_persisted ENCRYPTION_KEY)"
  if [ -z "$ENCRYPTION_KEY" ]; then
    ENCRYPTION_KEY="$(openssl rand -hex 32)"
    echo "ENCRYPTION_KEY='$ENCRYPTION_KEY'" >> "$SECRETS_FILE"
    echo "[AETHERIA] Generated ENCRYPTION_KEY (persisted to $SECRETS_FILE)"
  fi
fi
export NEXTAUTH_SECRET ENCRYPTION_KEY

# ── 2. Wait for the database ─────────────────────────────────────────────────
echo "[AETHERIA] Waiting for database..."
i=0
until node -e "const{PrismaClient}=require('@prisma/client');const p=new PrismaClient();p.\$connect().then(()=>process.exit(0)).catch(()=>process.exit(1))" >/dev/null 2>&1; do
  i=$((i+1))
  if [ "$i" -ge 60 ]; then
    echo "[AETHERIA] ERROR: database not reachable after ~120s" >&2
    exit 1
  fi
  echo "[AETHERIA]   database not ready yet (attempt $i/60)..."
  sleep 2
done
echo "[AETHERIA] Database is ready."

# ── 3. Apply migrations (idempotent) ─────────────────────────────────────────
echo "[AETHERIA] Applying database migrations..."
npx prisma migrate deploy

# ── 4. Seed static catalog (idempotent, create-only) ─────────────────────────
echo "[AETHERIA] Seeding catalog (CWE, licenses, AI providers/models)..."
npx tsx prisma/seed-catalog.ts

# ── 4b. Seed security engine rules (idempotent upserts) ──────────────────────
# Without these the L1 deterministic engines (taint/secrets/IaC) run blind:
# scans report "Reglas DB: 0 sources, 0 sinks..." and find nothing.
echo "[AETHERIA] Seeding security rules (taint/secrets/IaC/compliance)..."
npx tsx scripts/seed-security-rules.ts

# ── 4c. Seed BugHunter knowledge base (idempotent upserts, offline) ─────────
# Vendored snapshot in prisma/seed-data/bughunter-*.json — no git clone needed.
echo "[AETHERIA] Seeding BugHunter knowledge base (hunt skills)..."
npx tsx scripts/seed-bughunter.ts

# ── 5. Start the app ─────────────────────────────────────────────────────────
echo "[AETHERIA] Launching on port ${PORT:-3000}..."
exec npx next start -H 0.0.0.0 -p "${PORT:-3000}"
