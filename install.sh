#!/bin/bash
###############################################################################
# EndpointGuard v5.0 — Installer (interactive, no arguments)
#
# Usage:  sudo bash install.sh
###############################################################################

set -o pipefail

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
cat <<'BANNER'
  ╔════════════════════════════════════════════════════════════════╗
  ║          EndpointGuard v5.0 — Linux Sentinel installer         ║
  ║   Advanced reverse-shell, C2 and persistence hunter for Linux  ║
  ╚════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[✗] Run as root: sudo bash install.sh${NC}"
    exit 1
fi
if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    echo -e "${RED}[✗] Source script not found: ${SOURCE_SCRIPT}${NC}"
    exit 1
fi

echo -e "${GREEN}[1/5]${NC} Checking system requirements..."
BASH_MAJOR="${BASH_VERSINFO[0]}"
if [[ "$BASH_MAJOR" -lt 4 ]]; then
    echo -e "${RED}[✗] Bash 4.0+ required (found ${BASH_VERSION})${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Bash ${BASH_VERSION}"
for tool in flock inotifywait curl ss conntrack; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool}"
    else
        echo -e "  ${YELLOW}⚠${NC} ${tool} not found (recommended)"
    fi
done

echo -e "\n${GREEN}[2/5]${NC} Creating ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"

echo -e "\n${GREEN}[3/5]${NC} Installing main script..."
cp "$SOURCE_SCRIPT" "${INSTALL_DIR}/endpointguard.sh"
chmod 700 "${INSTALL_DIR}/endpointguard.sh"

echo -e "\n${GREEN}[4/5]${NC} Linking to /usr/local/bin/endpointguard..."
ln -sf "${INSTALL_DIR}/endpointguard.sh" /usr/local/bin/endpointguard 2>/dev/null
echo -e "  ${GREEN}✓${NC} You can now run: ${BOLD}sudo endpointguard${NC}"

echo -e "\n${GREEN}[5/5]${NC} Optional: install as systemd service?"
read -rp "Install service so EPG starts at boot? (y/N): " INSTALL_SERVICE
if [[ "$INSTALL_SERVICE" =~ ^[Yy] ]]; then
    cat > /etc/systemd/system/endpointguard.service <<EOF
[Unit]
Description=EndpointGuard v5.0 — Linux Sentinel
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/endpointguard.sh __daemon_run
ExecStop=/bin/bash ${INSTALL_DIR}/endpointguard.sh __stop
Restart=on-failure
RestartSec=60
KillMode=control-group
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "  ${GREEN}✓${NC} Service installed: ${BOLD}endpointguard.service${NC}"
    echo -e "  ${GREEN}✓${NC} Start with: ${BOLD}sudo systemctl enable --now endpointguard${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation complete ✅${NC}"
echo ""
echo -e "  Launch the menu:  ${BOLD}sudo endpointguard${NC}"
echo -e "  First run will guide you through setup (no manual editing)."
echo ""
