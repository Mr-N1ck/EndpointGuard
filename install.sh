#!/bin/bash
###############################################################################
# EndpointGuard v4.0 — Quick Installer
# Author: Prince Gaur (Mr-N1ck)
# https://github.com/Mr-N1ck/EndpointGuard
###############################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/.epg"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="${SCRIPT_DIR}/src/endpointguard.sh"

echo -e "${CYAN}"
echo '╔══════════════════════════════════════════════════════════╗'
echo '║       EndpointGuard v4.0 — Quick Installer              ║'
echo '║       Advanced Endpoint Security for Linux               ║'
echo '╚══════════════════════════════════════════════════════════╝'
echo -e "${NC}"

# Root check
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[✗] This installer must be run as root.${NC}"
    echo -e "    Run: ${BOLD}sudo bash install.sh${NC}"
    exit 1
fi

# Check source exists
if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    echo -e "${RED}[✗] Source script not found: ${SOURCE_SCRIPT}${NC}"
    echo -e "    Make sure you're running from the repository root."
    exit 1
fi

echo -e "${GREEN}[1/6]${NC} Checking system requirements..."

# Bash version check
BASH_MAJOR="${BASH_VERSINFO[0]}"
if [[ "$BASH_MAJOR" -lt 4 ]]; then
    echo -e "${RED}[✗] Bash 4.0+ required (found: ${BASH_VERSION})${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Bash ${BASH_VERSION}"

# Check recommended tools
for tool in flock inotifywait curl ss; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool} available"
    else
        echo -e "  ${YELLOW}⚠${NC} ${tool} not found (optional but recommended)"
    fi
done

echo -e "\n${GREEN}[2/6]${NC} Creating installation directory..."
mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"
echo -e "  ${GREEN}✓${NC} ${INSTALL_DIR}"

echo -e "\n${GREEN}[3/6]${NC} Installing EndpointGuard..."
cp "$SOURCE_SCRIPT" "${INSTALL_DIR}/endpointguard.sh"
chmod 700 "${INSTALL_DIR}/endpointguard.sh"
echo -e "  ${GREEN}✓${NC} Script installed"

echo -e "\n${GREEN}[4/6]${NC} Creating symlink..."
ln -sf "${INSTALL_DIR}/endpointguard.sh" /usr/local/bin/endpointguard 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} /usr/local/bin/endpointguard"

echo -e "\n${GREEN}[5/6]${NC} Installing systemd service..."

cat > /etc/systemd/system/endpointguard.service << EOF
[Unit]
Description=EndpointGuard v4.0 — Advanced Endpoint Security Daemon
Documentation=https://github.com/Mr-N1ck/EndpointGuard
After=network.target sshd.service auditd.service
Wants=network.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/endpointguard.sh start
ExecStop=/bin/bash ${INSTALL_DIR}/endpointguard.sh stop
Restart=on-failure
RestartSec=60
KillMode=control-group
TimeoutStopSec=20
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "  ${GREEN}✓${NC} Service created"

echo -e "\n${GREEN}[6/6]${NC} Configuration reminder..."
echo ""
echo -e "  ${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
echo -e "  ${YELLOW}║  IMPORTANT: Configure before starting!           ║${NC}"
echo -e "  ${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Edit: ${BOLD}nano ${INSTALL_DIR}/endpointguard.sh${NC}"
echo ""
echo -e "  Set these values:"
echo -e "    ${CYAN}SAFETY_MODE${NC}      → \"monitor\" (recommended to start)"
echo -e "    ${CYAN}TRUSTED_USER${NC}     → your username"
echo -e "    ${CYAN}TRUSTED_IPS${NC}      → your IP addresses"
echo -e "    ${CYAN}TELEGRAM_BOT_TOKEN${NC} → your bot token (optional)"
echo -e "    ${CYAN}TELEGRAM_CHAT_ID${NC}   → your chat ID (optional)"
echo ""
echo -e "  ${GREEN}Commands:${NC}"
echo -e "    Start:   ${BOLD}sudo endpointguard start${NC}"
echo -e "    Stop:    ${BOLD}sudo endpointguard stop${NC}"
echo -e "    Status:  ${BOLD}sudo endpointguard status${NC}"
echo -e "    Service: ${BOLD}sudo systemctl enable --now endpointguard${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}Installation complete! ✅${NC}"
echo ""
