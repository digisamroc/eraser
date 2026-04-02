#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# eraser-backup.sh — Daily backup of Eraser data
# Installed to /etc/cron.daily/eraser-backup on the LXC.
#
# • Uses sqlite3 .backup for crash-safe DB copies
# • Keeps 30 days of backups, deletes older
# ─────────────────────────────────────────────────────────────
set -euo pipefail

BACKUP_DIR="/var/backups/eraser"
DATE="$(date +%Y%m%d)"
DATA_DIR="/var/lib/eraser"

mkdir -p "$BACKUP_DIR"

# ── SQLite safe backup ────────────────────────────────────
DB_FILE="$DATA_DIR/history.db"
if [[ -f "$DB_FILE" ]]; then
  sqlite3 "$DB_FILE" ".backup '${BACKUP_DIR}/history-${DATE}.db'"
  echo "$(date -Iseconds) backed up history.db"
else
  echo "$(date -Iseconds) no history.db found — skipping"
fi

# ── Config backup ─────────────────────────────────────────
CONFIG_FILE="$DATA_DIR/config.yaml"
if [[ -f "$CONFIG_FILE" ]]; then
  cp "$CONFIG_FILE" "${BACKUP_DIR}/config-${DATE}.yaml"
  chmod 0600 "${BACKUP_DIR}/config-${DATE}.yaml"
  echo "$(date -Iseconds) backed up config.yaml"
fi

# ── Retention: remove anything older than 30 days ─────────
find "$BACKUP_DIR" -type f -mtime +30 -delete
echo "$(date -Iseconds) pruned backups older than 30 days"
