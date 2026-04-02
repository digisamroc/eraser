#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# setup-lxc.sh — One-time provisioning for the Eraser LXC
# Run this as root INSIDE the freshly created Debian 12 container.
#
# Usage:  chmod +x setup-lxc.sh && sudo ./setup-lxc.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

echo "══════════════════════════════════════════════════"
echo " Eraser LXC Setup"
echo "══════════════════════════════════════════════════"

# ── 0. Must be root ─────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run this script as root (sudo ./setup-lxc.sh)"
  exit 1
fi

# ── 1. Update packages ─────────────────────────────────────
echo ""
echo "→ Updating system packages …"
apt-get update -qq
apt-get upgrade -y -qq

# ── 2. Install dependencies ────────────────────────────────
echo "→ Installing ufw, fail2ban, sqlite3, curl …"
apt-get install -y -qq ufw fail2ban sqlite3 curl

# ── 3. Create eraser system user ───────────────────────────
echo "→ Creating 'eraser' system user …"
if id eraser &>/dev/null; then
  echo "  (user already exists — skipping)"
else
  useradd --system --shell /usr/sbin/nologin --create-home --home-dir /home/eraser eraser
fi

# ── 4. Directory structure ─────────────────────────────────
echo "→ Creating directory structure …"

# Binary + static data
mkdir -p /opt/eraser/data
chown root:root /opt/eraser
chmod 0755 /opt/eraser
chown root:root /opt/eraser/data
chmod 0755 /opt/eraser/data

# Runtime data (config, SQLite DB) — writable by eraser only
mkdir -p /var/lib/eraser
chown eraser:eraser /var/lib/eraser
chmod 0700 /var/lib/eraser

# Symlink so Eraser's default ~/.eraser/ path resolves correctly
if [[ ! -L /home/eraser/.eraser ]]; then
  ln -s /var/lib/eraser /home/eraser/.eraser
  chown -h eraser:eraser /home/eraser/.eraser
  echo "  → Symlinked /home/eraser/.eraser → /var/lib/eraser"
fi

# ── 5. Install systemd unit ───────────────────────────────
echo "→ Installing eraser.service …"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$SCRIPT_DIR/eraser.service" ]]; then
  cp "$SCRIPT_DIR/eraser.service" /etc/systemd/system/eraser.service
else
  echo "  WARNING: eraser.service not found next to this script."
  echo "  Copy it manually to /etc/systemd/system/eraser.service"
fi
systemctl daemon-reload
systemctl enable eraser.service
echo "  → Service enabled (will start after first deploy)"

# ── 6. Firewall (ufw) ─────────────────────────────────────
echo "→ Configuring firewall …"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 8080/tcp comment 'Eraser web UI'
echo "y" | ufw enable
echo "  → UFW active: SSH (22) + Eraser (8080)"

# ── 7. Fail2ban ────────────────────────────────────────────
echo "→ Enabling fail2ban …"
systemctl enable fail2ban
systemctl start fail2ban
echo "  → fail2ban running (default SSH jail)"

# ── 8. Backup directory ───────────────────────────────────
echo "→ Creating backup directory …"
mkdir -p /var/backups/eraser
chown root:root /var/backups/eraser
chmod 0750 /var/backups/eraser

echo ""
echo "══════════════════════════════════════════════════"
echo " ✅  LXC setup complete!"
echo ""
echo " Next steps:"
echo "   1. From your Mac, run:  ./deploy.sh"
echo "   2. Open http://192.168.99.50:8080"
echo "══════════════════════════════════════════════════"
