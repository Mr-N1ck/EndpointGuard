#!/bin/bash
###############################################################################
# EndpointGuard v4.0 — Uninstaller
# Author: Prince Gaur (Mr-N1ck)
# https://github.com/Mr-N1ck/EndpointGuard
###############################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/.epg"

echo -e "${RED}"
echo '╔══════════════════════════════════════════════════════════╗'
echo '║       EndpointGuard v4.0 — Uninstaller                  ║'
echo '╚══════════════════════════════════════════════════════════╝'
echo -e "${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[✗] Must run as root.${NC}"
    exit 1
fi

echo -e "${YELLOW}This will completely remove EndpointGuard.${NC}"
read -rp "Are you sure? (y/N): " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo "Cancelled." && exit 0

echo -e "\n${GREEN}[1/5]${NC} Stopping daemon..."
if [[ -f "${INSTALL_DIR}/endpointguard.sh" ]]; then
    bash "${INSTALL_DIR}/endpointguard.sh" stop 2>/dev/null || true
fi

echo -e "${GREEN}[2/5]${NC} Removing systemd service..."
systemctl stop endpointguard 2>/dev/null || true
systemctl disable endpointguard 2>/dev/null || true
rm -f /etc/systemd/system/endpointguard.service
systemctl daemon-reload 2>/dev/null

echo -e "${GREEN}[3/5]${NC} Restoring configurations..."
# Restore SSH config
[[ -f /etc/ssh/sshd_config.epg_backup ]] && \
    mv /etc/ssh/sshd_config.epg_backup /etc/ssh/sshd_config 2>/dev/null

# Restore PAM configs
for svc in sshd login su; do
    if [[ -f "/etc/pam.d/${svc}.epg_backup" ]]; then
        mv "/etc/pam.d/${svc}.epg_backup" "/etc/pam.d/${svc}" 2>/dev/null
    else
        sed -i '/pam_epg_hook/d' "/etc/pam.d/${svc}" 2>/dev/null || true
    fi
done

# Restore jailed users
for uh in /home/*/; do
    if [[ -f "${uh}.bashrc.epg_bak" ]]; then
        local_user=$(basename "$uh")
        chattr -i "${uh}.bashrc" 2>/dev/null || true
        mv "${uh}.bashrc.epg_bak" "${uh}.bashrc" 2>/dev/null
        chmod 644 "${uh}.bashrc" 2>/dev/null
        passwd -u "$local_user" 2>/dev/null || true
        usermod -s /bin/bash "$local_user" 2>/dev/null || true
        chage -E -1 "$local_user" 2>/dev/null || true
    fi
done

# Remove DenyUsers entries
[[ -f /etc/ssh/sshd_config ]] && \
    sed -i '/^DenyUsers/d' /etc/ssh/sshd_config 2>/dev/null
systemctl reload sshd 2>/dev/null || true

echo -e "${GREEN}[4/5]${NC} Removing blocked IPs..."
if [[ -f "${INSTALL_DIR}/blocked.list" ]]; then
    while IFS='|' read -r ip _ _; do
        [[ -z "$ip" ]] && continue
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null || true
        sed -i "/${ip}/d" /etc/hosts.deny 2>/dev/null || true
    done < "${INSTALL_DIR}/blocked.list"
fi

echo -e "${GREEN}[5/5]${NC} Cleaning up files..."
rm -f /usr/local/bin/endpointguard 2>/dev/null
rm -f /tmp/.epg_hp.log /etc/ssh/banner 2>/dev/null
rm -rf "$INSTALL_DIR" 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}EndpointGuard has been completely removed. ✅${NC}"
echo ""
