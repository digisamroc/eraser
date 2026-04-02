#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# eraser-health.sh — Simple health check for Eraser
# Installed as a cron job on the LXC (runs every 5 min).
# Restarts the service if it stops responding.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

if ! curl -sf --max-time 5 http://127.0.0.1:8080 >/dev/null 2>&1; then
  echo "$(date -Iseconds) Eraser not responding — restarting"
  systemctl restart eraser
else
  # Uncomment the next line for verbose logging:
  # echo "$(date -Iseconds) Eraser OK"
  :
fi
