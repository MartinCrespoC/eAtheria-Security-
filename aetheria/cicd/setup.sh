#!/usr/bin/env bash
# ============================================================
# AETHERIA — CI/CD Module Setup
# Installs everything needed to run the platform, the MCP server
# and (optionally) the Docker stacks.
#
#   ./setup.sh                          # deps + prisma + MCP build
#   ./setup.sh --install-prereqs        # zero-server: Node 20 + Docker + git/zip (Debian/Ubuntu, root/sudo)
#   ./setup.sh --install-prereqs --with-docker   # full from-zero bootstrap
#   ./setup.sh --with-docker            # + build & start docker stacks
#   ./setup.sh --skip-platform          # only the MCP server
#   ./setup.sh --skip-mcp               # only the platform
#   ./setup.sh --help
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WITH_DOCKER=false
SKIP_PLATFORM=false
SKIP_MCP=false
INSTALL_PREREQS=false

for arg in "$@"; do
  case "$arg" in
    --with-docker)     WITH_DOCKER=true ;;
    --skip-platform)   SKIP_PLATFORM=true ;;
    --skip-mcp)        SKIP_MCP=true ;;
    --install-prereqs) INSTALL_PREREQS=true ;;
    --help|-h)
      sed -n '2,14p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) echo "Unknown option: $arg (use --help)"; exit 1 ;;
  esac
done

info()  { echo -e "\033[36m▸ $*\033[0m"; }
ok()    { echo -e "\033[32m✔ $*\033[0m"; }
warn()  { echo -e "\033[33m⚠ $*\033[0m"; }
die()   { echo -e "\033[31m✖ $*\033[0m" >&2; exit 1; }

# ── OS prerequisites (zero-server bootstrap) ────────────────
# Installs Node.js 20 (NodeSource), Docker Engine + Compose plugin
# (official repo), git and zip on Debian/Ubuntu. Requires root or sudo.
if $INSTALL_PREREQS; then
  info "Installing OS prerequisites (Debian/Ubuntu)..."
  SUDO=""
  [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  command -v apt-get >/dev/null || die "--install-prereqs only supports apt-based systems (Debian/Ubuntu)"

  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq ca-certificates curl gnupg git zip unzip jq

  if ! command -v node >/dev/null || [ "$(node -e 'console.log(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)" -lt 20 ]; then
    info "Installing Node.js 20 (NodeSource)..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO -E bash -
    $SUDO apt-get install -y nodejs
  fi
  ok "Node $(node -v)"

  if ! command -v docker >/dev/null; then
    info "Installing Docker Engine + Compose plugin..."
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update -qq
    $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    $SUDO systemctl enable --now docker
    [ -n "$SUDO" ] && $SUDO usermod -aG docker "$(whoami)" && warn "Added to docker group — log out/in (or run: newgrp docker)"
  fi
  ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
fi

# ── Prerequisites check ──────────────────────────────────────
info "Checking prerequisites..."
command -v node >/dev/null || die "Node.js not found. Re-run with --install-prereqs or install Node >= 20"
NODE_MAJOR=$(node -e 'console.log(process.versions.node.split(".")[0])')
[ "$NODE_MAJOR" -ge 20 ] || die "Node >= 20 required (found $(node -v))"
command -v npm >/dev/null || die "npm not found"
ok "Node $(node -v) · npm $(npm -v)"

if $WITH_DOCKER; then
  command -v docker >/dev/null || die "Docker not found. Re-run with --install-prereqs or install Docker"
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin not found"
  ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
fi

# ── Platform ─────────────────────────────────────────────────
if ! $SKIP_PLATFORM; then
  info "Installing platform dependencies (${ROOT})..."
  (cd "$ROOT" && npm ci)
  ok "Platform dependencies installed"

  info "Generating Prisma client..."
  (cd "$ROOT" && npx prisma generate)
  ok "Prisma client generated"

  # Migrations only if a database is reachable (local dev without docker)
  if [ -n "${DATABASE_URL:-}" ]; then
    info "DATABASE_URL set — applying migrations and seed..."
    (cd "$ROOT" && npx prisma migrate deploy && npx prisma db seed) \
      && ok "Database migrated + seeded" \
      || warn "Migration/seed failed — run manually: npx prisma migrate deploy && npx prisma db seed"
  else
    warn "DATABASE_URL not set — migrations skipped (docker compose handles them on boot)"
  fi
fi

# ── MCP server ───────────────────────────────────────────────
if ! $SKIP_MCP; then
  info "Building MCP server..."
  (cd "$ROOT/mcp-server" && npm ci && npm run build)
  ok "MCP server built (mcp-server/dist/index.js)"
fi

# ── Docker ───────────────────────────────────────────────────
if $WITH_DOCKER; then
  if ! $SKIP_PLATFORM; then
    info "Building & starting platform stack (db + redis + app)..."
    (cd "$ROOT" && docker compose up -d --build)
    ok "Platform up → http://localhost:3000 (setup wizard on first boot)"
  fi
  if ! $SKIP_MCP; then
    info "Building & starting MCP server (StreamableHTTP :3100)..."
    (cd "$ROOT/cicd/docker" && docker compose -f docker-compose.mcp.yml up -d --build)
    ok "MCP HTTP endpoint → http://localhost:3100/mcp"
  fi
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Setup complete"
echo ""
echo "Next steps:"
echo "  1. Platform:     cd ${ROOT} && docker compose up -d   (or npm run dev)"
echo "  2. Create an API key in the dashboard → Settings → API Keys"
echo "  3. GitHub CI:    copy the workflow from cicd/README.md §2"
echo "                   and add secret AETHERIA_API_KEY to your repo"
echo "  4. MCP remote:   docker compose -f cicd/docker/docker-compose.mcp.yml up -d"
echo "                   → point Devin/agents at http://<host>:3100/mcp"
echo "  5. Full docs:    ${SCRIPT_DIR}/README.md"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
