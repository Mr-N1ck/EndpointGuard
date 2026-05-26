#!/bin/bash
###############################################################################
# EndpointGuard v5.0 — Uninstaller (interactive, no arguments)
#
# Usage:  sudo bash uninstall.sh
###############################################################################

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/.epg"
BLOCKED_FILE="${INSTALL_DIR}/blocked.list"
PAM_HOOK_SCRIPT="${INSTALL_DIR}/pam_epg_hook.sh"
PAM_FIFO="${INSTALL_DIR}/pam_alerts.fifo"
PAM_LOG="${INSTALL_DIR}/pam_events.log"
PAM_TRUSTED_IPS="${INSTALL_DIR}/trusted_ips.conf"

echo -e "${RED}"
cat <<'BANNER'
  ╔════════════════════════════════════════════════════════════════╗
  ║         EndpointGuard v5.0 — Uninstaller                       ║
  ╚════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[✗] Run as root: sudo bash uninstall.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}This will completely remove EndpointGuard and undo all its changes.${NC}"
read -rp "Type YES to confirm: " confirm
[[ "$confirm" != "YES" ]] && { echo "Cancelled."; exit 0; }

echo -e "\n${GREEN}[1/6]${NC} Stopping daemon..."
if [[ -f "${INSTALL_DIR}/endpointguard.sh" ]]; then
    bash "${INSTALL_DIR}/endpointguard.sh" __stop 2>/dev/null || true
fi

echo -e "${GREEN}[2/6]${NC} Removing systemd service..."
systemctl stop endpointguard 2>/dev/null || true
systemctl disable endpointguard 2>/dev/null || true
rm -f /etc/systemd/system/endpointguard.service
systemctl daemon-reload 2>/dev/null

echo -e "${GREEN}[3/6]${NC} Restoring SSH and PAM configurations..."
[[ -f /etc/ssh/sshd_config.epg_backup ]] && \
    mv /etc/ssh/sshd_config.epg_backup /etc/ssh/sshd_config 2>/dev/null
for svc in sshd login su; do
    if [[ -f "/etc/pam.d/${svc}.epg_backup" ]]; then
        mv "/etc/pam.d/${svc}.epg_backup" "/etc/pam.d/${svc}" 2>/dev/null
    else
        sed -i '/pam_epg_hook/d' "/etc/pam.d/${svc}" 2>/dev/null || true
    fi
done
rm -f "$PAM_HOOK_SCRIPT" "$PAM_FIFO" "$PAM_LOG" "$PAM_TRUSTED_IPS" 2>/dev/null

echo -e "${GREEN}[4/6]${NC} Restoring jailed users..."
for uh in /home/*/; do
    if [[ -f "${uh}.bashrc.epg_bak" ]]; then
        u=$(basename "$uh")
        chattr -i "${uh}.bashrc" 2>/dev/null || true
        mv "${uh}.bashrc.epg_bak" "${uh}.bashrc" 2>/dev/null
        chmod 644 "${uh}.bashrc" 2>/dev/null
        passwd -u "$u" 2>/dev/null || true
        usermod -s /bin/bash "$u" 2>/dev/null || true
        chage -E -1 "$u" 2>/dev/null || true
    fi
done
[[ -f /etc/ssh/sshd_config ]] && sed -i '/^DenyUsers/d' /etc/ssh/sshd_config 2>/dev/null
systemctl reload sshd 2>/dev/null || true

echo -e "${GREEN}[5/6]${NC} Removing blocked IP rules..."
if [[ -f "$BLOCKED_FILE" ]]; then
    while IFS='|' read -r ip _ _; do
        [[ -z "$ip" ]] && continue
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null || true
        iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null || true
        iptables -D FORWARD -d "$ip" -j DROP 2>/dev/null || true
        sed -i "/${ip}/d" /etc/hosts.deny 2>/dev/null || true
    done < "$BLOCKED_FILE"
fi

echo -e "${GREEN}[6/6]${NC} Cleaning up files..."
rm -f /usr/local/bin/endpointguard 2>/dev/null
rm -f /tmp/.epg_hp.log /etc/ssh/banner 2>/dev/null
rm -rf "$INSTALL_DIR" 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}EndpointGuard has been completely removed ✅${NC}"
echo ""
