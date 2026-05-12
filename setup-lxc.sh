#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Auth Proxy — LXC Container Setup Script
#
# Run this inside a fresh Proxmox LXC container (Ubuntu 22.04+ / Debian 12+)
# to install dependencies and configure the auth-proxy service.
#
# Usage:
#   sudo bash setup-lxc.sh
#
# This script will:
#   1. Install system dependencies (python3, pip, git, ssh)
#   2. Install Python packages (fastapi, uvicorn, pyyaml, python-telegram-bot)
#   3. Copy the auth-proxy files to /opt/auth-proxy/
#   4. Create a systemd service for auto-start
#   5. (Optionally) prompt you to configure config.yaml
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/auth-proxy"
SERVICE_NAME="auth-proxy"

echo "=== Auth Proxy LXC Setup ==="
echo ""

# ── 1. System dependencies ──
echo "[1/5] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git openssh-client curl
echo "  ✓ Done"

# ── 2. Python virtual environment ──
echo "[2/5] Setting up Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/venv"
source "${INSTALL_DIR}/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet fastapi uvicorn[standard] pyyaml python-telegram-bot pydantic
deactivate
echo "  ✓ Done"

# ── 3. Copy files ──
echo "[3/5] Copying proxy files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/services"
cp "${SCRIPT_DIR}/auth-proxy-server.py" "${INSTALL_DIR}/"
cp -r "${SCRIPT_DIR}/services" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/config.yaml.example" "${INSTALL_DIR}/config.yaml.example"
if [ ! -f "${INSTALL_DIR}/config.yaml" ]; then
    cp "${INSTALL_DIR}/config.yaml.example" "${INSTALL_DIR}/config.yaml"
    echo "  ✓ Created default config.yaml — EDIT THIS FILE"
else
    echo "  ✓ config.yaml already exists, keeping existing"
fi
find "${INSTALL_DIR}" -name "*.py" -exec chmod +x {} \;
chown -R root:root "${INSTALL_DIR}"
echo "  ✓ Done"

# ── 4. Systemd service ──
echo "[4/5] Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'SERVICE'
[Unit]
Description=Auth Proxy — Secure credential gate with Telegram approval
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/auth-proxy/venv/bin/python /opt/auth-proxy/auth-proxy-server.py
WorkingDirectory=/opt/auth-proxy
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
echo "  ✓ Done"

# ── 5. Next steps ──
echo "[5/5] Setup complete!"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NEXT STEPS:"
echo ""
echo "  1. CONFIGURE:  nano ${INSTALL_DIR}/config.yaml"
echo "     Set your:"
echo "       - api.auth_token        (or use AUTH_PROXY_TOKEN env)"
echo "       - telegram.bot_token    (or use AUTH_PROXY_TELEGRAM env)"
echo "       - telegram.allowed_user_ids"
echo "       - services.git.ssh_key_path"
echo ""
echo "  2. ADD SSH KEY (for GitHub):"
echo "     Copy your GitHub SSH key to:"
echo "       /root/.ssh/id_ed25519"
echo "     (or the path specified in config.yaml)"
echo ""
echo "  3. START:  systemctl start auth-proxy"
echo "     STATUS: systemctl status auth-proxy"
echo "     LOGS:   journalctl -u auth-proxy -f"
echo ""
echo "  4. ADD A NEW SERVICE:"
echo "     Create a new file in ${INSTALL_DIR}/services/"
echo "     that subclasses BaseService and uses @service('name')."
echo "     See services/git.py for a working example."
echo ""
echo "═══════════════════════════════════════════════════════════════"
