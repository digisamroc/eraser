# Eraser — Proxmox LXC Deployment Guide

> **Audience:** Brandon (or anyone with Proxmox who hasn't used LXC before).
> **Scope:** LAN-only deployment. No internet exposure, no reverse proxy, no SSL.
> Eraser binds directly to `0.0.0.0:8080` and is accessible from any device on
> the local network.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  LAN  (192.168.99.0/24)                            │
│                                                     │
│  Mac / Phone / etc.                                 │
│       │                                             │
│       │  http://192.168.99.50:8080                  │
│       ▼                                             │
│  ┌──────────────────────────────────────┐           │
│  │  Proxmox Host  192.168.99.20        │           │
│  │                                      │           │
│  │  ┌────────────────────────────────┐  │           │
│  │  │  LXC 200  "eraser"            │  │           │
│  │  │  Debian 12  192.168.99.50     │  │           │
│  │  │                                │  │           │
│  │  │  eraser binary → :8080        │  │           │
│  │  │  SQLite  → /var/lib/eraser/   │  │           │
│  │  └────────────────────────────────┘  │           │
│  └──────────────────────────────────────┘           │
└─────────────────────────────────────────────────────┘
```

**Filesystem layout inside the LXC:**

```
/opt/eraser/              # Binary + static data (root-owned, 0755)
├── eraser                # Go binary
└── data/
    └── brokers.yaml      # Data broker list

/var/lib/eraser/          # Runtime data (eraser:eraser, 0700)
├── config.yaml           # User configuration (PII + SMTP creds)
└── history.db            # SQLite database

/home/eraser/.eraser → /var/lib/eraser   # Symlink for default paths
```

---

## Prerequisites

| Item | Details |
|------|---------|
| **Proxmox VE** | 7.x or 8.x with web UI access |
| **Debian 12 template** | Downloaded in Proxmox (see Step 1) |
| **LAN** | Subnet `192.168.99.0/24`, gateway at router |
| **Go** | 1.21+ on your Mac (`brew install go` if needed) |
| **SSH key** | A keypair on your Mac (`ssh-keygen` if you don't have one) |

---

## Step 1 — Download the Debian 12 LXC Template

1. Open the Proxmox web UI: **https://192.168.99.20:8006**
2. In the left sidebar, click on your **storage** (usually `local`).
3. Click **CT Templates** in the content panel.
4. Click **Templates** (the button at the top).
5. In the search box, type `debian-12`.
6. Select **debian-12-standard** (e.g., `debian-12-standard_12.7-1_amd64.tar.zst`).
7. Click **Download** and wait for it to finish.

> **What's an LXC template?** It's a compressed filesystem image — think of it
> as a minimal Debian install packaged up. Proxmox uses it to create lightweight
> containers that share the host kernel but have their own filesystem, network,
> and process space. Much lighter than a full VM.

---

## Step 2 — Create the LXC Container

1. In the Proxmox web UI, click **Create CT** (top-right).
2. Fill in these settings across the wizard tabs:

### General tab
| Field | Value |
|-------|-------|
| **CT ID** | `200` (or any free ID) |
| **Hostname** | `eraser` |
| **Password** | Choose a root password (you'll use it for initial login) |
| **SSH public key** | Paste your Mac's public key (`cat ~/.ssh/id_ed25519.pub`) |
| **Unprivileged** | ✅ Checked |

### Template tab
| Field | Value |
|-------|-------|
| **Storage** | `local` |
| **Template** | `debian-12-standard_12.7-1_amd64.tar.zst` |

### Disks tab
| Field | Value |
|-------|-------|
| **Storage** | `local-lvm` (or wherever your LXC disks live) |
| **Disk size** | `4` GB |

### CPU tab
| Field | Value |
|-------|-------|
| **Cores** | `1` |

### Memory tab
| Field | Value |
|-------|-------|
| **Memory** | `512` MB |
| **Swap** | `256` MB |

### Network tab
| Field | Value |
|-------|-------|
| **Bridge** | `vmbr0` |
| **IPv4** | `Static` |
| **IPv4 Address** | `192.168.99.50/24` |
| **Gateway** | Your router IP (e.g., `192.168.99.1`) |

### DNS tab
Leave defaults (inherits from Proxmox host), or set:
| Field | Value |
|-------|-------|
| **DNS server** | `192.168.99.1` (your router) or `1.1.1.1` |

3. Click **Finish** to create the container.
4. Select the new container in the sidebar and click **Start**.

---

## Step 3 — First Login and Setup

### Option A: Console (easy)
1. Select container `200` in Proxmox sidebar.
2. Click **Console**.
3. Log in as `root` with the password you set.

### Option B: SSH (preferred)
```bash
ssh root@192.168.99.50
```

### Copy setup files into the container

From your Mac, copy the entire `deploy/` directory:

```bash
cd ~/git/eraser/eraser
scp -r deploy/ root@192.168.99.50:/root/deploy/
```

### Run the setup script

Inside the LXC (as root):

```bash
cd /root/deploy
chmod +x *.sh
./setup-lxc.sh
```

This script will:
- Update all system packages
- Install `ufw`, `fail2ban`, `sqlite3`, `curl`
- Create the `eraser` system user (no login shell)
- Create `/opt/eraser/data/` and `/var/lib/eraser/`
- Symlink `/home/eraser/.eraser` → `/var/lib/eraser/`
- Install the systemd unit file
- Enable the firewall (SSH + port 8080 only)
- Enable fail2ban (SSH protection)

> The eraser service is **enabled but not started** — there's no binary yet.
> That comes in the next step.

---

## Step 4 — Configure SSH Alias on Your Mac

Add this to `~/.ssh/config` on your Mac:

```
Host eraser-server
    HostName 192.168.99.50
    User root
    IdentityFile ~/.ssh/id_ed25519
```

Test it:

```bash
ssh eraser-server 'hostname'
# Should print: eraser
```

> **Why `root`?** The deploy script needs `sudo systemctl restart eraser`.
> Using root keeps it simple for a personal LAN setup. If you prefer, create a
> deploy user with passwordless sudo for `systemctl restart eraser` instead.

---

## Step 5 — Deploy Eraser

From your Mac:

```bash
cd ~/git/eraser/eraser/deploy
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Cross-compile the Go binary for linux/amd64
2. Upload it to `/opt/eraser/eraser` on the LXC
3. Upload `data/brokers.yaml`
4. Restart the systemd service
5. Print the deployed git commit hash

You should see:

```
══════════════════════════════════════════════════
 ✅  Deployed!  commit abc1234
 Service: healthy ✓
 URL:     http://192.168.99.50:8080
══════════════════════════════════════════════════
```

---

## Step 6 — Access the Web UI

Open in any browser on your LAN:

```
http://192.168.99.50:8080
```

You'll see the Eraser setup wizard. Complete it to configure your email
provider and personal info. (Pris handles the email configuration details.)

---

## Step 7 — Install Backup Cron (Recommended)

Inside the LXC (as root):

```bash
cp /root/deploy/eraser-backup.sh /etc/cron.daily/eraser-backup
chmod +x /etc/cron.daily/eraser-backup
```

This runs once per day and:
- Creates a crash-safe SQLite backup of `history.db`
- Copies `config.yaml`
- Stores backups in `/var/backups/eraser/`
- Automatically deletes backups older than 30 days

Verify it works:

```bash
/etc/cron.daily/eraser-backup
ls -la /var/backups/eraser/
```

---

## Step 8 — Install Health Check Cron (Optional)

Inside the LXC (as root):

```bash
cp /root/deploy/eraser-health.sh /usr/local/bin/eraser-health
chmod +x /usr/local/bin/eraser-health
```

Add a cron entry:

```bash
crontab -e
```

Add this line:

```
*/5 * * * * /usr/local/bin/eraser-health >> /var/log/eraser-health.log 2>&1
```

This checks every 5 minutes and restarts the service if it's down.

---

## Updating Eraser

When you pull new code (or make changes):

```bash
cd ~/git/eraser/eraser
git pull                          # if pulling from remote
cd deploy
./deploy.sh
```

That's it. The deploy script handles build → upload → restart.

### Pre-update safety

Before major updates, take a Proxmox snapshot:

1. In Proxmox web UI, select container `200`.
2. Click **Snapshots** → **Take Snapshot**.
3. Name it (e.g., `pre-update-2026-04-15`).

If something breaks, restore the snapshot instantly.

---

## Troubleshooting

### "Connection refused" when accessing port 8080

```bash
# Is the service running?
ssh eraser-server 'systemctl status eraser'

# Check logs
ssh eraser-server 'journalctl -u eraser -n 50 --no-pager'

# Is the port open?
ssh eraser-server 'ss -tlnp | grep 8080'

# Is the firewall allowing it?
ssh eraser-server 'ufw status'
```

### Service won't start

```bash
# Check for errors
ssh eraser-server 'journalctl -u eraser -n 100 --no-pager'
```

Common causes:
- **Binary not deployed:** Run `./deploy.sh` first.
- **Permission denied:** Binary must be executable: `chmod 0755 /opt/eraser/eraser`
- **Missing config:** If Eraser requires config on first run, check `/var/lib/eraser/`.

### "Permission denied" during deploy

- Check your SSH key is in `~/.ssh/config` and matches what's on the LXC.
- Verify with: `ssh -v eraser-server 'echo ok'`

### Service keeps restarting (crash loop)

```bash
# Watch it live
ssh eraser-server 'journalctl -u eraser -f'
```

Look for the error message. Common fixes:
- Missing `brokers.yaml` → re-run `./deploy.sh`
- Database locked → check if another process is using the DB
- Port already in use → `ss -tlnp | grep 8080`

### Can't reach from other devices on LAN

1. Verify the container has the right IP: `ip addr show` inside the LXC.
2. Verify your device is on the same subnet (`192.168.99.x`).
3. Check the firewall: `ufw status` should show port 8080 ALLOW.
4. Try from the Proxmox host: `curl http://192.168.99.50:8080`

### Disk space running low

```bash
# Check disk usage
ssh eraser-server 'df -h /'

# Check backup size
ssh eraser-server 'du -sh /var/backups/eraser/'

# Prune old backups manually
ssh eraser-server 'find /var/backups/eraser -type f -mtime +7 -delete'
```

### Viewing logs

```bash
# Live tail
ssh eraser-server 'journalctl -u eraser -f'

# Last 100 lines
ssh eraser-server 'journalctl -u eraser -n 100 --no-pager'

# Since last boot
ssh eraser-server 'journalctl -u eraser -b --no-pager'

# Fail2ban status
ssh eraser-server 'fail2ban-client status sshd'
```

---

## File Reference

| File | Purpose | Where it runs |
|------|---------|---------------|
| `eraser.service` | systemd unit file | Installed to `/etc/systemd/system/` on LXC |
| `setup-lxc.sh` | One-time LXC provisioning | Run once inside the LXC as root |
| `deploy.sh` | Build + upload + restart | Run from your Mac |
| `eraser-backup.sh` | Daily SQLite + config backup | Installed as `/etc/cron.daily/eraser-backup` |
| `eraser-health.sh` | Restart if unresponsive | Installed as cron job (every 5 min) |

---

## Quick Reference

| Item | Value |
|------|-------|
| **LXC IP** | `192.168.99.50` |
| **Web UI** | `http://192.168.99.50:8080` |
| **SSH** | `ssh eraser-server` (or `ssh root@192.168.99.50`) |
| **Logs** | `journalctl -u eraser -f` |
| **Config** | `/var/lib/eraser/config.yaml` |
| **Database** | `/var/lib/eraser/history.db` |
| **Binary** | `/opt/eraser/eraser` |
| **Backups** | `/var/backups/eraser/` |
| **Proxmox UI** | `https://192.168.99.20:8006` |
