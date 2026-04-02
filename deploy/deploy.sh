#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# deploy.sh — Build Eraser on Mac and ship it to the LXC
# Run from anywhere on your Mac.
#
# Prerequisites:
#   • Go 1.21+ installed
#   • SSH alias "eraser-server" configured (see README)
#
# Usage:  ./deploy.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SSH_HOST="eraser-server"
REMOTE_BIN="/opt/eraser/eraser"
REMOTE_DATA="/opt/eraser/data/brokers.yaml"

# Resolve the eraser source tree (sibling of deploy/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ERASER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "══════════════════════════════════════════════════"
echo " Eraser Deploy"
echo "══════════════════════════════════════════════════"
echo "Source:  $ERASER_ROOT"
echo "Target:  $SSH_HOST"
echo ""

# ── 1. Cross-compile ──────────────────────────────────────
echo "→ Building linux/amd64 binary …"
cd "$ERASER_ROOT"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o deploy/eraser-linux ./cmd/eraser
echo "  → Built deploy/eraser-linux ($(du -h deploy/eraser-linux | cut -f1))"

# ── 2. Upload binary ──────────────────────────────────────
echo "→ Uploading binary …"
scp deploy/eraser-linux "${SSH_HOST}:${REMOTE_BIN}"
ssh "$SSH_HOST" "chmod 0755 ${REMOTE_BIN}"

# ── 3. Upload broker data ─────────────────────────────────
echo "→ Uploading brokers.yaml …"
scp "$ERASER_ROOT/data/brokers.yaml" "${SSH_HOST}:${REMOTE_DATA}"

# ── 4. Restart service ────────────────────────────────────
echo "→ Restarting eraser service …"
ssh "$SSH_HOST" 'sudo systemctl restart eraser'

# ── 5. Quick health check (wait a moment for startup) ────
sleep 2
if ssh "$SSH_HOST" 'curl -sf http://127.0.0.1:8080 >/dev/null 2>&1'; then
  HEALTH="healthy ✓"
else
  HEALTH="NOT YET RESPONDING (may still be starting)"
fi

# ── 6. Done ────────────────────────────────────────────────
GIT_HASH=$(git -C "$ERASER_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
echo ""
echo "══════════════════════════════════════════════════"
echo " ✅  Deployed!  commit ${GIT_HASH}"
echo " Service: ${HEALTH}"
echo " URL:     http://192.168.99.50:8080"
echo "══════════════════════════════════════════════════"

# Clean up local cross-compiled binary
rm -f deploy/eraser-linux
