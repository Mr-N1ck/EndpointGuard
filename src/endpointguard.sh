#!/bin/bash

###############################################################################
#
#  ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗
#  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝
#  █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║
#  ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║
#  ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║
#  ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═╝
#   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
#  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
#  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
#  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
#  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
#   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
#
#  EndpointGuard v4.0 — Advanced Endpoint Security with Instant
#  Intrusion Response
#
#  Author:   Prince Gaur
#  GitHub:   https://github.com/Mr-N1ck
#  LinkedIn: https://www.linkedin.com/in/mr-n1ck/
#
#  FEATURES:
#  1.  Atomic locking with flock (no TOCTOU race)
#  2.  Event-driven monitoring where possible (inotifywait/auditd)
#      with polling fallback + adaptive scan intervals
#  3.  Multi-format log parsing (Debian/RHEL/journalctl JSON)
#  4.  Crash-safe honeypot jail (auto-recovery on startup)
#  5.  Process group management (no orphaned processes)
#  6.  Resource-aware scanning with load throttling
#
#  NEW IN v4.0 — INSTANT INTRUSION RESPONSE:
#  7.  Rapid login detection (2-3 second response time)
#  8.  PAM hook for instant detection of ALL login methods
#  9.  Session-specific blocking (never harms your own sessions)
#  10. Trusted account compromise → honeypot redirect
#  11. Multi-method detection: SSH, console, su, VNC, RDP, tmux
#  12. Auto-detect owner IP to prevent self-lockout
#
#  SAFETY MODES:
#    "monitor"  → Alert only, NEVER takes action (DEFAULT)
#    "moderate" → Alert + auto-block brute force IPs
#    "active"   → Full auto-response
#
###############################################################################

set -o pipefail

# ========================== SAFETY MODE ==========================

SAFETY_MODE="active"

# ========================== CONFIGURATION ==========================

TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"

TRUSTED_USER="your_username"
ADDITIONAL_TRUSTED_USERS=""
TRUSTED_IPS=""
TRUSTED_NETWORKS=""

INSTALL_DIR="/opt/.epg"
LOG_FILE="${INSTALL_DIR}/epg.log"
BLOCKED_FILE="${INSTALL_DIR}/blocked.list"
SESSION_DB="${INSTALL_DIR}/sessions.db"
PID_FILE="${INSTALL_DIR}/daemon.pid"
HONEYPOT_DIR="${INSTALL_DIR}/honeypot"
ALERT_TRACKER="${INSTALL_DIR}/alerts"
LOCK_DIR="${INSTALL_DIR}/locks"
BASELINE_DIR="${INSTALL_DIR}/baselines"
JAIL_REGISTRY="${INSTALL_DIR}/jailed_users.list"

MAX_FAILED_LOGINS=10
SUSPICIOUS_CMD_THRESHOLD=8
LOCKOUT_DURATION=3600
PERMANENT_BAN_STRIKES=5

# --- Adaptive Scan Intervals ---
SCAN_INTERVAL_LIGHT=30
SCAN_INTERVAL_MEDIUM=120
SCAN_INTERVAL_HEAVY=300
SCAN_INTERVAL_VERY_HEAVY=600

# --- Rapid Login Detection (2-3 seconds) ---
REALTIME_LOGIN_INTERVAL=2

# --- Alert Cooldowns ---
ALERT_COOLDOWN_SSH=120
ALERT_COOLDOWN_CMD=60
ALERT_COOLDOWN_FILE=600
ALERT_COOLDOWN_NET=300
ALERT_COOLDOWN_PERSIST=600
ALERT_COOLDOWN_OTHER=300

# --- Whitelisted Programs (NEVER flagged) ---
WHITELISTED_PROGRAMS=(
    nmap masscan hydra john hashcat sqlmap msfconsole msfvenom
    metasploit burpsuite nikto dirb dirbuster gobuster ffuf wfuzz
    aircrack airmon airodump reaver wpscan enum4linux smbclient
    rpcclient crackmapexec impacket responder bloodhound
    linpeas linenum pspy chisel socat proxychains
    netcat nc ncat tcpdump wireshark tshark ettercap bettercap
    beef setoolkit searchsploit exploitdb
    python python3 ruby perl php gcc gdb strace ltrace objdump
    radare2 r2 ghidra volatility autopsy foremost binwalk
    steghide exiftool curl wget ssh scp rsync
    vim nano emacs tmux screen
    docker podman kubectl ansible terraform
    git pip pip3 npm cargo go make cmake
    apt dpkg yum dnf pacman snap flatpak
    systemctl journalctl service
    cat less more head tail grep awk sed find locate
    ls ll dir cp mv rm mkdir rmdir chmod chown
    ps top htop free df du mount umount
    ip ifconfig route netstat ping traceroute dig nslookup host
    tar gzip gunzip bzip2 xz zip unzip
    bash sh zsh fish dash
    sudo su passwd useradd usermod groupadd
    crontab at
    man info help which whereis type
    echo printf date cal uptime hostname uname id who w last
    ssh-keygen ssh-copy-id ssh-agent ssh-add
    openssl gpg
    iptables nft firewall-cmd ufw
    fail2ban-client
    lsof fuser
    dd fdisk parted lsblk blkid
    dmesg lspci lsusb lscpu
    reboot shutdown poweroff halt init
)

# --- Whitelisted Kernel Modules (NEVER alerted) ---
WHITELISTED_KERNEL_MODULES=(
    # Graphics / Display
    i915 amdgpu radeon nouveau nvidia nvidia_modeset nvidia_uvm nvidia_drm
    drm drm_kms_helper ttm fb_sys_fops syscopyarea sysfillrect sysimgblt
    fbdev fbcon vgastate vga16fb vboxvideo vmwgfx cirrus ast mgag200
    # Audio
    snd snd_hda_intel snd_hda_codec snd_hda_codec_realtek snd_hda_codec_generic
    snd_hda_core snd_hwdep snd_pcm snd_timer snd_seq snd_seq_midi
    snd_rawmidi snd_seq_device snd_compress snd_soc_core snd_pcm_dmaengine
    snd_intel_dspcfg snd_intel_sdw_acpi soundcore
    # Networking
    e1000 e1000e igb ixgbe r8169 realtek r8152 r8153 ath9k ath10k_pci
    ath10k_core ath11k_pci iwlwifi iwlmvm iwldvm mt76 mt7921e mt7921_common
    rtw88_pci rtw88_core rtl8xxxu brcmfmac brcmutil cfg80211 mac80211
    bluetooth btusb btintel btrtl btbcm bnep rfcomm
    tun tap veth bridge br_netfilter nf_tables nf_conntrack nf_nat
    iptable_filter iptable_nat ip_tables ip6_tables xt_conntrack xt_state
    xt_nat xt_tcpudp xt_multiport xt_comment xt_addrtype xt_mark
    nf_conntrack_netlink nfnetlink nf_defrag_ipv4 nf_defrag_ipv6
    wireguard openvpn 8021q bonding team
    # USB
    usbcore usb_common usbhid hid hid_generic xhci_hcd xhci_pci ehci_hcd
    ehci_pci ohci_hcd uhci_hcd usb_storage uas usbip_core usbip_host
    # Storage / Filesystem
    ahci libahci libata sd_mod sr_mod sg scsi_mod nvme nvme_core
    ext4 jbd2 btrfs xfs fat vfat msdos ntfs ntfs3 fuse overlay
    isofs udf crc32c_generic crc32c_intel dm_mod dm_crypt dm_mirror
    dm_snapshot dm_thin_pool dm_log dm_region_hash md_mod raid0 raid1
    raid10 raid456 loop nbd
    # Input
    evdev mousedev psmouse i2c_hid i2c_hid_acpi atkbd input_leds
    joydev hid_multitouch hid_logitech hid_logitech_dj hid_apple
    # Power / Thermal / CPU
    acpi_cpufreq intel_pstate amd_pstate cpufreq_conservative cpufreq_ondemand
    cpufreq_performance cpufreq_powersave cpufreq_userspace processor thermal
    thermal_sys fan battery ac button int3400_thermal int3403_thermal
    intel_rapl_msr intel_rapl_common intel_powerclamp coretemp k10temp
    # Virtualization
    kvm kvm_intel kvm_amd vboxdrv vboxnetflt vboxnetadp vboxpci
    vmw_vsock_vmci_transport vmw_balloon vmw_vmci vmxnet3 vmw_pvscsi
    hv_vmbus hv_storvsc hv_netvsc hv_utils hyperv_keyboard pci_hyperv
    virtio virtio_pci virtio_net virtio_blk virtio_scsi virtio_balloon
    virtio_console virtio_ring 9pnet 9pnet_virtio
    # Crypto
    aesni_intel aes_x86_64 ghash_clmulni_intel sha256_ssse3 sha512_ssse3
    sha1_ssse3 crc32_pclmul crct10dif_pclmul cryptd glue_helper
    crypto_simd af_alg algif_hash algif_skcipher
    # Platform / ACPI
    wmi wmi_bmof mxm_wmi asus_wmi asus_nb_wmi dell_wmi dell_smbios
    hp_wmi thinkpad_acpi ideapad_laptop platform_profile int3400_thermal
    int340x_thermal_zone intel_hid intel_vbtn sparse_keymap
    video backlight leds_class led_class_flash
    # Misc common
    lp ppdev parport parport_pc pcspkr serio serio_raw i2c_core i2c_piix4
    i2c_smbus i2c_algo_bit gpio_generic pinctrl_amd pinctrl_intel
    cec rc_core lirc_dev ir_common mei mei_hdcp mei_me mei_pxp
    thunderbolt typec ucsi_acpi roles
    efivarfs efi_pstore configfs
    zram zsmalloc lz4 lz4_compress lz4_decompress lzo lzo_compress
    lzo_decompress zlib_deflate zlib_inflate
    rfkill ecdh_generic ecc
    nls_utf8 nls_cp437 nls_ascii nls_iso8859_1
    sunrpc nfsd nfs nfsv4 grace lockd auth_rpcgss
    cifs smbfs_common
    af_packet llc stp psnap p8022
    ipmi_devintf ipmi_si ipmi_msghandler
    edac_mce_amd edac_core
    binfmt_misc autofs4
    # Docker / Container
    overlay br_netfilter xt_conntrack xt_MASQUERADE xt_addrtype
    vxlan ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh nf_conntrack_tftp
    nf_nat_tftp
    # AppArmor / Security
    apparmor security_apparmor integrity ima evm
)

# --- Whitelisted SUID binaries (NEVER alerted) ---
WHITELISTED_SUID_PATHS=(
    # Browser sandboxes
    "/opt/brave.com/brave/chrome-sandbox"
    "/opt/google/chrome/chrome-sandbox"
    "/usr/lib/chromium/chrome-sandbox"
    "/usr/lib/chromium-browser/chrome-sandbox"
    "/usr/lib/firefox/plugin-container"
    "/snap/chromium/"
    "/snap/firefox/"
    # Standard system SUID binaries
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    "/usr/bin/pkexec"
    "/usr/bin/crontab"
    "/usr/bin/at"
    "/usr/bin/ssh-agent"
    "/usr/bin/expiry"
    "/usr/bin/chage"
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/libexec/polkit-agent-helper-1"
    "/usr/lib/xorg/Xorg.wrap"
    "/usr/lib/eject/dmcrypt-get-device"
    "/usr/sbin/pppd"
    "/usr/sbin/unix_chkpwd"
    "/usr/sbin/mount.nfs"
    "/usr/sbin/mount.cifs"
    "/usr/sbin/userhelper"
    "/usr/bin/locate"
    "/usr/bin/mlocate"
    "/usr/bin/ping"
    "/usr/bin/traceroute"
    "/usr/bin/staprun"
    # Snap / Flatpak
    "/snap/"
    "/var/lib/flatpak/"
    "/usr/lib/snapd/"
)

# --- Truly Malicious Patterns (almost never legitimate) ---
TRULY_MALICIOUS_PATTERNS=(
    "bash -i >& /dev/tcp/"
    "bash -i >& /dev/udp/"
    "sh -i >& /dev/tcp/"
    "sh -i >& /dev/udp/"
    "bash -c.bash -i.>& /dev/"
    "rm -rf / --no-preserve-root"
    "rm -rf /"
    "dd if=/dev/zero of=/dev/sda"
    "dd if=/dev/zero of=/dev/vda"
    "dd if=/dev/null of=/dev/sda"
    "mkfs.ext4 /dev/sda"
    "mkfs.ext4 /dev/vda"
    ":(){ :|:& };:"
    "echo.|.base64 -d|.bash"
    "wget.-O-|bash"
    "wget.-O-|sh"
    "curl.|bash"
    "curl.|sh"
    "python.*-c.*import.*socket.*connect.*dup2.exec"
    "perl.-e.*socket.*INET.connect.exec"
    "ruby.-rsocket.-e.*TCPSocket.*exec"
    "export HISTSIZE=0"
    "export HISTFILESIZE=0"
    "unset HISTFILE"
    "history -c;history -w"
)

SENSITIVE_FILES=(
    "/etc/passwd" "/etc/shadow" "/etc/sudoers"
    "/etc/ssh/sshd_config" "/etc/crontab"
    "/etc/hosts.allow" "/etc/hosts.deny"
    "/etc/ld.so.preload" "/etc/pam.d/sshd"
    "/root/.ssh/authorized_keys"
)

# ========================== COLORS ==========================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ========================== GLOBAL STATE ==========================

CHILD_PIDS=()
RUNNING=true
MY_CURRENT_IPS=""          # Auto-populated at startup to prevent self-lockout
KNOWN_SESSIONS_HASH=""     # For rapid login change detection

# ========================== BANNER ==========================

show_banner() {
    clear
    echo ""
    echo -e "${CYAN}"
    cat << 'BANNER_ART'
    ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗
    ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝
    █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║
    ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║
    ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║
    ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═╝
BANNER_ART
    echo -e "${GREEN}"
    cat << 'BANNER_ART2'
     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
BANNER_ART2
    echo -e "${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${MAGENTA}${BOLD}  EndpointGuard v4.0${NC} ${DIM}— Advanced Endpoint Security Engine${NC}"
    echo -e "  ${DIM}  Instant Intrusion Response | Honeypot Traps | Auto-Recovery${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${DIM}Author:   ${NC}${WHITE}Prince Gaur${NC}"
    echo -e "  ${DIM}GitHub:   ${NC}${CYAN}https://github.com/Mr-N1ck${NC}"
    echo -e "  ${DIM}LinkedIn: ${NC}${CYAN}https://www.linkedin.com/in/mr-n1ck/${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ========================== PROCESS GROUP MANAGEMENT ==========================

cleanup() {
    RUNNING=false
    log_event "INFO" "Shutting down EndpointGuard"

    # Kill entire process group (all children + grandchildren)
    local my_pgid
    my_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')

    if [[ -n "$my_pgid" ]] && [[ "$my_pgid" != "1" ]]; then
        kill -- -"$my_pgid" 2>/dev/null
    fi

    # Also explicitly kill tracked children
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
        pkill -P "$pid" 2>/dev/null
    done

    # Wait briefly for children to die
    sleep 1

    # Clean orphaned subprocesses
    local my_pid=$$
    local orphans
    orphans=$(pgrep -P "$my_pid" 2>/dev/null || true)
    if [[ -n "$orphans" ]]; then
        echo "$orphans" | xargs kill -9 2>/dev/null
    fi

    rm -f "$PID_FILE"
    find "$LOCK_DIR" -name "*.lock" -delete 2>/dev/null

    log_event "INFO" "EndpointGuard stopped cleanly"
    exit 0
}

# Track a background job properly
track_child() {
    local pid=$1
    CHILD_PIDS+=("$pid")

    # Limit tracked children to prevent array bloat
    if [[ ${#CHILD_PIDS[@]} -gt 100 ]]; then
        local new_pids=()
        for p in "${CHILD_PIDS[@]}"; do
            if kill -0 "$p" 2>/dev/null; then
                new_pids+=("$p")
            fi
        done
        CHILD_PIDS=("${new_pids[@]}")
    fi
}

# ========================== ATOMIC LOCKING WITH FLOCK ==========================

FLOCK_AVAILABLE=false
command -v flock &>/dev/null && FLOCK_AVAILABLE=true

# Execute a command with an exclusive lock
with_lock() {
    local lockname="$1"
    shift
    local lockfile="${LOCK_DIR}/${lockname}.lock"

    if [[ "$FLOCK_AVAILABLE" == "true" ]]; then
        (
            flock -w 10 200 || { log_event "WARN" "Lock timeout: ${lockname}"; return 1; }
            "$@"
        ) 200>"$lockfile"
    else
        local max_attempts=10
        local attempt=0

        while ! mkdir "${lockfile}.d" 2>/dev/null; do
            attempt=$((attempt + 1))
            if [[ "$attempt" -ge "$max_attempts" ]]; then
                rm -rf "${lockfile}.d" 2>/dev/null
                mkdir "${lockfile}.d" 2>/dev/null || return 1
                break
            fi
            sleep 1
        done

        "$@"
        rm -rf "${lockfile}.d" 2>/dev/null
    fi
}

# ========================== UTILITY FUNCTIONS ==========================

init_directories() {
    mkdir -p "$INSTALL_DIR" "$LOCK_DIR" "$ALERT_TRACKER" "$BASELINE_DIR" "$HONEYPOT_DIR"
    touch "$LOG_FILE" "$BLOCKED_FILE" "$SESSION_DB" "$JAIL_REGISTRY"
    chmod 700 "$INSTALL_DIR"
    chmod 600 "$LOG_FILE" "$BLOCKED_FILE" "$SESSION_DB" "$JAIL_REGISTRY"
}

log_event() {
    local level="$1" local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null

    local lines
    lines=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$lines" -gt 50000 ]]; then
        with_lock "log_rotate" _rotate_log_internal
    fi
}

_rotate_log_internal() {
    tail -25000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null
    mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
}

check_alert_cooldown() {
    local alert_key="$1"
    local cooldown_seconds="$2"

    local safe_key
    safe_key=$(echo "$alert_key" | tr -c 'a-zA-Z0-9_-' '_' | head -c 80)
    local tracker_file="${ALERT_TRACKER}/${safe_key}"

    local now
    now=$(date +%s)

    if [[ -f "$tracker_file" ]]; then
        local last_sent
        last_sent=$(cat "$tracker_file" 2>/dev/null || echo "0")
        [[ ! "$last_sent" =~ ^[0-9]+$ ]] && last_sent=0

        if [[ $((now - last_sent)) -lt "$cooldown_seconds" ]]; then
            return 1
        fi
    fi

    echo "$now" > "$tracker_file" 2>/dev/null
    return 0
}

send_telegram() {
    local message="$1"
    local urgency="${2:-LOW}"

    [[ "$TELEGRAM_BOT_TOKEN" == "YOUR_BOT_TOKEN_HERE" ]] && return

    local emoji=""
    case "$urgency" in
        LOW) emoji="ℹ️" ;; MEDIUM) emoji="⚠️" ;; HIGH) emoji="🚨" ;; CRITICAL) emoji="🔴" ;; *) emoji="📌" ;;
    esac

    local mode_label="MONITOR"
    [[ "$SAFETY_MODE" == "moderate" ]] && mode_label="MODERATE"
    [[ "$SAFETY_MODE" == "active" ]] && mode_label="ACTIVE"

    local full_message="${emoji} EPG [${mode_label}]

Host: $(hostname 2>/dev/null)
Time: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
Level: ${urgency}

$(echo "$message" | head -c 2500)"

    # Run in background with timeout
    (curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${full_message}" \
        -d "disable_web_page_preview=true" \
        > /dev/null 2>&1) &
    track_child $!
}

send_smart_alert() {
    local key="$1" cooldown="$2" message="$3" urgency="${4:-LOW}"
    if check_alert_cooldown "$key" "$cooldown"; then
        send_telegram "$message" "$urgency"
        log_event "$urgency" "ALERT: ${key}"
    fi
}

# ========================== SAFETY FUNCTIONS ==========================

is_trusted_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1
    [[ "$ip" == "unknown" ]] && return 1
    [[ "$ip" == "local" || "$ip" == ":0" ]] && return 0

    for tip in $TRUSTED_IPS; do
        [[ "$ip" == "$tip" ]] && return 0
    done

    for network in $TRUSTED_NETWORKS; do
        local prefix
        prefix=$(echo "$network" | cut -d'/' -f1 | rev | cut -d'.' -f2- | rev)
        [[ -n "$prefix" ]] && echo "$ip" | grep -q "^${prefix}\." 2>/dev/null && return 0
    done

    return 1
}

is_trusted_user() {
    local user="$1"
    [[ -z "$user" ]] && return 1
    [[ "$user" == "$TRUSTED_USER" ]] && return 0
    for tu in $ADDITIONAL_TRUSTED_USERS; do
        [[ "$user" == "$tu" ]] && return 0
    done
    return 1
}

is_system_user() {
    local user="$1"
    [[ -z "$user" ]] && return 0
    local uid
    uid=$(id -u "$user" 2>/dev/null)
    [[ -z "$uid" ]] && return 0
    [[ "$uid" -lt 1000 ]] && return 0
    return 1
}

is_protected_user() {
    local user="$1"
    [[ -z "$user" ]] && return 0
    is_trusted_user "$user" && return 0
    is_system_user "$user" && return 0
    [[ "$user" == "root" ]] && return 0
    return 1
}

is_own_process() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0
    [[ "$pid" == "$$" ]] && return 0

    local ppid
    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    [[ "$ppid" == "$$" ]] && return 0

    local pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    local my_pgid
    my_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
    [[ "$pgid" == "$my_pgid" ]] && return 0

    for cpid in "${CHILD_PIDS[@]}"; do
        [[ "$pid" == "$cpid" ]] && return 0
    done

    return 1
}

is_whitelisted_program() {
    local cmd_line="$1"
    [[ -z "$cmd_line" ]] && return 0

    local binary
    binary=$(echo "$cmd_line" | awk '{print $1}' | xargs basename 2>/dev/null || echo "")

    for prog in "${WHITELISTED_PROGRAMS[@]}"; do
        [[ "$binary" == "$prog" ]] && return 0
    done

    return 1
}

# Check if a kernel module is whitelisted
is_whitelisted_kernel_module() {
    local modname="$1"
    [[ -z "$modname" ]] && return 0

    for wmod in "${WHITELISTED_KERNEL_MODULES[@]}"; do
        [[ "$modname" == "$wmod" ]] && return 0
    done

    return 1
}

# Check if a SUID binary path is whitelisted
is_whitelisted_suid() {
    local filepath="$1"
    [[ -z "$filepath" ]] && return 0

    for wpath in "${WHITELISTED_SUID_PATHS[@]}"; do
        # Support prefix matching for paths ending with /
        if [[ "$wpath" == */ ]]; then
            [[ "$filepath" == "$wpath"* ]] && return 0
        else
            [[ "$filepath" == "$wpath" ]] && return 0
        fi
    done

    return 1
}

# ========================== SELF-LOCKOUT PREVENTION ==========================

detect_my_ips() {
    local ips=""

    # Get all local interface IPs
    local iface_ips
    iface_ips=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' || \
                ifconfig 2>/dev/null | grep -oP 'inet (addr:)?\K[0-9.]+' || true)
    [[ -n "$iface_ips" ]] && ips="$iface_ips"

    # Get the IP of the current SSH session
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local ssh_ip
        ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
        [[ -n "$ssh_ip" ]] && ips="$ips $ssh_ip"
    fi
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local ssh_conn_ip
        ssh_conn_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        [[ -n "$ssh_conn_ip" ]] && ips="$ips $ssh_conn_ip"
    fi

    # Who is currently logged in as the trusted user
    local who_ips
    who_ips=$(who 2>/dev/null | grep "^${TRUSTED_USER} " | awk '{print $5}' | tr -d '()' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    [[ -n "$who_ips" ]] && ips="$ips $who_ips"

    # Always include localhost
    ips="$ips 127.0.0.1 ::1"

    # Also include TRUSTED_IPS
    ips="$ips $TRUSTED_IPS"

    # Deduplicate
    MY_CURRENT_IPS=$(echo "$ips" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    log_event "INFO" "Owner IPs detected: ${MY_CURRENT_IPS}"
}

is_my_own_ip() {
    local ip="$1"
    [[ -z "$ip" || "$ip" == "local" || "$ip" == ":0" || "$ip" == "unknown" ]] && return 0

    for my_ip in $MY_CURRENT_IPS; do
        [[ "$ip" == "$my_ip" ]] && return 0
    done

    is_trusted_ip "$ip" && return 0

    return 1
}

is_my_own_session() {
    local user="$1" ip="$2"

    is_my_own_ip "$ip" && return 0

    if is_trusted_user "$user"; then
        [[ "$ip" == "local" || "$ip" == ":0" || -z "$ip" ]] && return 0
    fi

    return 1
}

# ========================== RESOURCE-AWARE SCANNING ==========================

get_system_load() {
    local load
    load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}' | cut -d'.' -f1)
    echo "${load:-0}"
}

get_cpu_count() {
    nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1
}

get_adaptive_interval() {
    local base_interval="$1"
    local load cpus

    load=$(get_system_load)
    cpus=$(get_cpu_count)

    if [[ "$load" -gt $((cpus * 3)) ]]; then
        echo $((base_interval * 4))
    elif [[ "$load" -gt $((cpus * 2)) ]]; then
        echo $((base_interval * 2))
    else
        echo "$base_interval"
    fi
}

can_heavy_scan() {
    local load cpus
    load=$(get_system_load)
    cpus=$(get_cpu_count)
    [[ "$load" -le $((cpus * 2)) ]]
}

# ========================== MODE-GATED ACTIONS ==========================

can_take_action() { [[ "$SAFETY_MODE" == "active" ]]; }
can_block_ip() { [[ "$SAFETY_MODE" == "active" || "$SAFETY_MODE" == "moderate" ]]; }

safe_kill_process() {
    local pid="$1" user="$2" reason="$3"

    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would kill PID=${pid} user=${user} (${reason})"
        return
    fi

    is_protected_user "$user" && { log_event "WARN" "REFUSED kill on protected user=${user}"; return; }
    is_own_process "$pid" && return

    log_event "HIGH" "KILLING PID=${pid} user=${user} (${reason})"
    kill -9 "$pid" 2>/dev/null
}

safe_block_ip() {
    local ip="$1" reason="${2:-unknown}"

    if ! can_block_ip; then
        log_event "INFO" "[MONITOR] Would block IP=${ip} (${reason})"
        return
    fi

    [[ -z "$ip" ]] && return
    is_trusted_ip "$ip" && { log_event "WARN" "REFUSED block trusted IP=${ip}"; return; }
    [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && return

    with_lock "iptables" _block_ip_internal "$ip" "$reason"
}

_block_ip_internal() {
    local ip="$1" reason="$2"

    iptables -C INPUT -s "$ip" -j DROP 2>/dev/null && return

    iptables -I INPUT -s "$ip" -j DROP 2>/dev/null
    iptables -I OUTPUT -d "$ip" -j DROP 2>/dev/null

    grep -q "$ip" /etc/hosts.deny 2>/dev/null || echo "ALL: ${ip}" >> /etc/hosts.deny 2>/dev/null

    echo "${ip}|$(date +%s)|${reason}" >> "$BLOCKED_FILE" 2>/dev/null

    local strikes
    strikes=$(grep -c "^${ip}|" "$BLOCKED_FILE" 2>/dev/null || echo 0)

    log_event "HIGH" "BLOCKED: ${ip} (${reason}) strike=${strikes}/${PERMANENT_BAN_STRIKES}"

    if [[ "$strikes" -lt "$PERMANENT_BAN_STRIKES" ]]; then
        (
            sleep "$LOCKOUT_DURATION"
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
            sed -i "/${ip}/d" /etc/hosts.deny 2>/dev/null
            log_event "INFO" "Unblocked (expired): ${ip}"
        ) &
        track_child $!
    fi
}

safe_kill_sessions() {
    local user="$1"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would kill sessions: ${user}"
        return
    fi
    is_protected_user "$user" && return
    log_event "HIGH" "Killing sessions: ${user}"
    pkill -9 -u "$user" 2>/dev/null
}

safe_lock_account() {
    local user="$1"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would lock: ${user}"
        return
    fi
    is_protected_user "$user" && return
    log_event "HIGH" "Locking: ${user}"
    passwd -l "$user" 2>/dev/null
    usermod -s /sbin/nologin "$user" 2>/dev/null
    chage -E 0 "$user" 2>/dev/null

    if [[ -f /etc/ssh/sshd_config ]]; then
        with_lock "sshd_config" _add_deny_user "$user"
    fi
}

_add_deny_user() {
    local user="$1"
    if grep -q "DenyUsers" /etc/ssh/sshd_config 2>/dev/null; then
        grep -qE "DenyUsers.*\b${user}\b" /etc/ssh/sshd_config 2>/dev/null || \
            sed -i "s/^DenyUsers.*/& ${user}/" /etc/ssh/sshd_config 2>/dev/null
    else
        echo "DenyUsers ${user}" >> /etc/ssh/sshd_config 2>/dev/null
    fi
    systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null
}

# ========================== CRASH-SAFE HONEYPOT JAIL ==========================

setup_honeypot_jail() {
    log_event "INFO" "Setting up honeypot"

    mkdir -p "${HONEYPOT_DIR}"/{bin,etc,home,tmp}

    cat > "${HONEYPOT_DIR}/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF

    cat > "${HONEYPOT_DIR}/etc/shadow" << 'EOF'
root:!:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
EOF

    local fake_cmds=("ls" "cat" "id" "whoami" "uname" "wget" "curl" "sudo" "ssh" "find" "passwd" "nc" "ncat" "python" "python3")

    for cmd in "${fake_cmds[@]}"; do
        cat > "${HONEYPOT_DIR}/bin/${cmd}" << 'FAKESCRIPT'
#!/bin/bash
echo "$(date +%s) $(basename $0) $*" >> /tmp/.epg_hp.log 2>/dev/null
case "$(basename $0)" in
    ls) echo "Desktop  Documents  Downloads" ;;
    cat) echo "cat: $1: Permission denied" ;;
    id) echo "uid=1000(user) gid=1000(user) groups=1000(user)" ;;
    whoami) echo "user" ;;
    uname) echo "Linux server 5.4.0-generic #1 SMP x86_64" ;;
    wget|curl) sleep 1; echo "$(basename $0): network unreachable"; exit 1 ;;
    sudo) read -sp "[sudo] password: " x; echo; echo "not in sudoers file" ;;
    ssh) echo "ssh: Connection timed out" ;;
    find) echo "find: Permission denied" ;;
    passwd) echo "passwd: Authentication error" ;;
    nc|ncat) echo "nc: network unreachable"; exit 1 ;;
    *) echo "command not found" ;;
esac
FAKESCRIPT
        chmod +x "${HONEYPOT_DIR}/bin/${cmd}" 2>/dev/null
    done

    chmod 700 "${HONEYPOT_DIR}"
    log_event "INFO" "Honeypot ready"
}

register_jail() {
    local user="$1"
    with_lock "jail_registry" _register_jail_internal "$user"
}

_register_jail_internal() {
    local user="$1"
    grep -q "^${user}$" "$JAIL_REGISTRY" 2>/dev/null || echo "$user" >> "$JAIL_REGISTRY"
}

unregister_jail() {
    local user="$1"
    with_lock "jail_registry" _unregister_jail_internal "$user"
}

_unregister_jail_internal() {
    local user="$1"
    sed -i "/^${user}$/d" "$JAIL_REGISTRY" 2>/dev/null
}

recover_jailed_users() {
    log_event "INFO" "Checking for crash-orphaned jails"

    if [[ -f "$JAIL_REGISTRY" ]] && [[ -s "$JAIL_REGISTRY" ]]; then
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            log_event "INFO" "Recovering jailed user from crash: ${user}"
            deactivate_jail_for_user "$user"
            unregister_jail "$user"
        done < "$JAIL_REGISTRY"
    fi

    for user_home in /home/*/; do
        if [[ -f "${user_home}.bashrc.epg_bak" ]]; then
            local user
            user=$(basename "$user_home")
            if ! who 2>/dev/null | grep -q "^${user} "; then
                log_event "INFO" "Restoring orphaned jail: ${user}"
                deactivate_jail_for_user "$user"
            fi
        fi
    done
}

activate_jail_for_session() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"

    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would jail: ${target_user}"
        return
    fi

    is_protected_user "$target_user" && return

    local user_home
    user_home=$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)

    [[ -z "$user_home" || "$user_home" == "/" || ! -d "$user_home" ]] && return
    [[ "$user_home" == "$HOME" ]] && return

    log_event "HIGH" "Jailing: ${target_user} ip=${target_ip}"

    register_jail "$target_user"

    if [[ -f "${user_home}/.bashrc" ]] && [[ ! -f "${user_home}/.bashrc.epg_bak" ]]; then
        cp -p "${user_home}/.bashrc" "${user_home}/.bashrc.epg_bak" 2>/dev/null
    fi

    cat > "${user_home}/.bashrc" << JAILRC
export PATH="${HONEYPOT_DIR}/bin"
export HOME="${HONEYPOT_DIR}/home"
export PS1="\u@\h:\w\$ "
PROMPT_COMMAND='echo "\$(date +%s) \$(history 1)" >> /tmp/.epg_hp.log 2>/dev/null'
JAILRC

    chmod 444 "${user_home}/.bashrc" 2>/dev/null

    send_smart_alert "jail_${target_user}" "$ALERT_COOLDOWN_CMD" \
        "JAIL ACTIVATED

User: ${target_user}
IP: ${target_ip}" "HIGH"
}

deactivate_jail_for_user() {
    local target_user="$1"
    is_protected_user "$target_user" && return

    local user_home
    user_home=$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)
    [[ -z "$user_home" ]] && user_home=$(eval echo "~${target_user}" 2>/dev/null)

    if [[ -f "${user_home}/.bashrc.epg_bak" ]]; then
        chattr -i "${user_home}/.bashrc" 2>/dev/null
        chmod 644 "${user_home}/.bashrc" 2>/dev/null
        mv "${user_home}/.bashrc.epg_bak" "${user_home}/.bashrc" 2>/dev/null
        chmod 644 "${user_home}/.bashrc" 2>/dev/null
        unregister_jail "$target_user"
        log_event "INFO" "Jail deactivated: ${target_user}"
    fi
}

# ========================== MULTI-FORMAT LOG PARSING ==========================

find_auth_log() {
    if [[ -f /var/log/auth.log ]]; then
        echo "file:/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then
        echo "file:/var/log/secure"
    else
        echo "journalctl"
    fi
}

parse_ssh_success() {
    local line="$1"
    local user="" ip="" method=""

    if echo "$line" | grep -qiE "Accepted (password|publickey|keyboard)" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'for \K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
        method=$(echo "$line" | grep -oP 'Accepted \K\S+' 2>/dev/null | head -1)
    fi

    if [[ -z "$user" ]] && echo "$line" | grep -qiE "sshd:session.*session opened" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'for user \K\S+' 2>/dev/null | head -1)
        method="pam"
    fi

    if [[ -z "$user" ]] && echo "$line" | grep -qiE '"_COMM":"sshd".*"MESSAGE":"Accepted' 2>/dev/null; then
        user=$(echo "$line" | grep -oP '"MESSAGE":"Accepted \S+ for \K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
        method=$(echo "$line" | grep -oP 'Accepted \K\S+' 2>/dev/null | head -1)
    fi

    [[ -n "$user" ]] && echo "${user}|${ip:-unknown}|${method:-unknown}" || echo ""
}

parse_ssh_failure() {
    local line="$1"
    local user="" ip=""

    if echo "$line" | grep -qiE "Failed password" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'for (invalid user )?\K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
    fi

    if [[ -z "$user" ]] && echo "$line" | grep -qiE "authentication failure" 2>/dev/null; then
        user=$(echo "$line" | grep -oP '(user=|ruser=)\K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP '(rhost=)\K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
    fi

    if [[ -z "$user" ]] && echo "$line" | grep -qiE "Invalid user" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'Invalid user \K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
    fi

    [[ -n "$ip" ]] && echo "${user:-UNKNOWN}|${ip}" || echo ""
}

parse_ssh_close() {
    local line="$1"
    local user=""

    if echo "$line" | grep -qiE "(session closed|Disconnected from|Connection closed|pam_unix.*session closed)" 2>/dev/null; then
        user=$(echo "$line" | grep -oP '(for user |user )\K\S+' 2>/dev/null | head -1)
        [[ -z "$user" ]] && user=$(echo "$line" | grep -oP 'for \K\S+' 2>/dev/null | head -1)
    fi

    echo "${user:-}"
}

handle_compromised_trusted_account() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"

    # CRITICAL SAFETY: Never block yourself
    if is_my_own_ip "$target_ip"; then
        log_event "INFO" "Login from owner IP ${target_ip} for ${target_user} - safe"
        return
    fi

    send_smart_alert "compromised_${target_user}_${target_ip}" "$ALERT_COOLDOWN_SSH" \
        "🚨 SUSPICIOUS LOGIN TO TRUSTED ACCOUNT 🚨

User: ${target_user}
IP: ${target_ip}
PID: ${target_pid}

⚠️ This IP is NOT in trusted list!
Action: Blocking IP + redirecting to honeypot in 2 seconds" "CRITICAL"

    if can_take_action || can_block_ip; then
        (
            sleep 2
            log_event "CRITICAL" "Responding to untrusted IP ${target_ip} on trusted account ${target_user}"
            safe_block_ip "$target_ip" "compromised_trusted_account_${target_user}"
            redirect_attacker_to_honeypot "$target_user" "$target_ip" "$target_pid"
            kill_attacker_session_only "$target_user" "$target_ip" "$target_pid"
            log_event "HIGH" "Intrusion response complete: user=${target_user} ip=${target_ip}"
        ) &
        track_child $!
    else
        log_event "INFO" "[MONITOR] Would block+jail compromised session for ${target_user} from ${target_ip}"
    fi
}

redirect_attacker_to_honeypot() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"

    local attacker_pts
    attacker_pts=$(who 2>/dev/null | grep "$target_ip" | awk '{print $2}' || true)

    if [[ -n "$attacker_pts" ]]; then
        for pts in $attacker_pts; do
            if [[ -w "/dev/$pts" ]]; then
                echo "export PATH='${HONEYPOT_DIR}/bin'; export HOME='${HONEYPOT_DIR}/home'; export PS1='\u@\h:\w\$ '; PROMPT_COMMAND='echo \"\$(date +%s) \$(history 1)\" >> /tmp/.epg_hp.log 2>/dev/null'" > "/dev/$pts" 2>/dev/null || true
            fi
        done
        log_event "HIGH" "Honeypot redirect sent to attacker PTY: ${attacker_pts}"
    fi

    if ! is_trusted_user "$target_user" || [[ "$target_user" == "root" ]]; then
        register_jail "$target_user"
    fi

    send_smart_alert "honeypot_${target_user}_${target_ip}" "$ALERT_COOLDOWN_CMD" \
        "🏭 HONEYPOT ACTIVATED

Attacker redirected to fake environment
User: ${target_user} | IP: ${target_ip}
PTY: ${attacker_pts:-unknown}" "HIGH"
}

kill_attacker_session_only() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"

    if [[ "$target_pid" != "unknown" && -n "$target_pid" ]]; then
        kill -9 "$target_pid" 2>/dev/null
        pkill -9 -P "$target_pid" 2>/dev/null
        log_event "HIGH" "Killed attacker PID ${target_pid}"
    fi

    local pts_list
    pts_list=$(who 2>/dev/null | grep "$target_ip" | awk '{print $2}')
    for pts in $pts_list; do
        [[ -z "$pts" ]] && continue
        local pts_source
        pts_source=$(who 2>/dev/null | grep "$pts" | awk '{print $5}' | tr -d '()' | head -1)
        if ! is_my_own_ip "$pts_source"; then
            fuser -k -9 "/dev/$pts" 2>/dev/null
            log_event "HIGH" "Killed attacker PTY /dev/${pts}"
        fi
    done

    local sshd_pids
    sshd_pids=$(ss -tnp 2>/dev/null | grep ":22 " | grep "$target_ip" | grep -oP 'pid=\K\d+' || true)
    for spid in $sshd_pids; do
        [[ -z "$spid" ]] && continue
        kill -9 "$spid" 2>/dev/null
        pkill -9 -P "$spid" 2>/dev/null
        log_event "HIGH" "Killed attacker SSHD PID ${spid}"
    done
}

# ========================== MODULE: SSH MONITOR ==========================

monitor_ssh_logins() {
    local auth_source
    auth_source=$(find_auth_log)

    log_event "INFO" "SSH monitor started (${auth_source})"

    if [[ "$auth_source" == "journalctl" ]]; then
        journalctl -u sshd -u ssh -f --no-pager -n 0 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            process_auth_line "$line"
        done &
    else
        local logfile="${auth_source#file:}"
        tail -n 0 -F "$logfile" 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            process_auth_line "$line"
        done &
    fi

    track_child $!
}

process_auth_line() {
    local line="$1"
    [[ -z "$line" ]] && return

    # --- Success ---
    local success_data
    success_data=$(parse_ssh_success "$line")

    if [[ -n "$success_data" ]]; then
        IFS='|' read -r user ip method <<< "$success_data"

        log_event "INFO" "SSH LOGIN: user=${user} ip=${ip} method=${method}"
        echo "$(date +%s)|${user}|${ip}|${method}" >> "$SESSION_DB" 2>/dev/null

        if is_trusted_user "$user" && is_trusted_ip "$ip"; then
            send_smart_alert "login_ok" "$ALERT_COOLDOWN_SSH" \
                "Trusted Login ✅

User: ${user} | IP: ${ip}" "LOW"

        elif is_trusted_user "$user"; then
            local ssh_pid
            ssh_pid=$(pgrep -n -u "$user" sshd 2>/dev/null || echo "unknown")
            handle_compromised_trusted_account "$user" "$ip" "$ssh_pid"
        else
            send_smart_alert "login_bad_${user}" "$ALERT_COOLDOWN_SSH" \
                "UNTRUSTED LOGIN

User: ${user} | IP: ${ip}
Mode: ${SAFETY_MODE}" "CRITICAL"

            if can_take_action; then
                local ssh_pid
                ssh_pid=$(pgrep -n -u "$user" sshd 2>/dev/null || echo "")
                activate_jail_for_session "$user" "$ip" "$ssh_pid"
                monitor_untrusted_session "$user" "$ip" "$ssh_pid" &
                track_child $!
            fi
        fi
        return
    fi

    # --- Failure ---
    local fail_data
    fail_data=$(parse_ssh_failure "$line")

    if [[ -n "$fail_data" ]]; then
        IFS='|' read -r user ip <<< "$fail_data"
        [[ -z "$ip" ]] && return

        is_trusted_ip "$ip" && return

        log_event "MEDIUM" "SSH FAIL: user=${user} ip=${ip}"

        local fail_count
        fail_count=$(grep -c "SSH FAIL.*ip=${ip}" "$LOG_FILE" 2>/dev/null || echo 0)

        if [[ "$fail_count" -ge "$MAX_FAILED_LOGINS" ]]; then
            send_smart_alert "brute_${ip}" 600 \
                "BRUTE FORCE

IP: ${ip} | User: ${user} | Attempts: ${fail_count}" "CRITICAL"
            safe_block_ip "$ip" "brute_force"
        elif [[ $((fail_count % 5)) -eq 0 ]] && [[ "$fail_count" -gt 0 ]]; then
            send_smart_alert "sshfail_${ip}" "$ALERT_COOLDOWN_SSH" \
                "SSH Failures: ${fail_count}/${MAX_FAILED_LOGINS}
IP: ${ip} | User: ${user}" "MEDIUM"
        fi
        return
    fi

    # --- Close ---
    local close_user
    close_user=$(parse_ssh_close "$line")

    if [[ -n "$close_user" ]] && ! is_protected_user "$close_user"; then
        deactivate_jail_for_user "$close_user"
    fi
}

# ========================== MODULE: UNTRUSTED SESSION MONITOR ==========================

monitor_untrusted_session() {
    local user="$1" ip="$2" session_pid="${3:-}"
    local suspicious_count=0

    is_protected_user "$user" && return

    log_event "INFO" "Monitoring: ${user} from ${ip}"

    while [[ "$RUNNING" == "true" ]]; do
        if ! pgrep -u "$user" &>/dev/null; then
            deactivate_jail_for_user "$user"
            break
        fi

        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_LIGHT")

        local user_procs
        user_procs=$(ps -u "$user" -o pid=,cmd= --no-headers 2>/dev/null || true)

        while IFS= read -r proc_line; do
            [[ -z "$proc_line" ]] && continue

            local proc_pid proc_cmd
            proc_pid=$(echo "$proc_line" | awk '{print $1}')
            proc_cmd=$(echo "$proc_line" | awk '{$1=""; print $0}' | sed 's/^ //')

            is_own_process "$proc_pid" && continue
            is_whitelisted_program "$proc_cmd" && continue

            for pattern in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
                if echo "$proc_cmd" | grep -qiF "$pattern" 2>/dev/null; then
                    suspicious_count=$((suspicious_count + 1))
                    log_event "CRITICAL" "MALICIOUS: user=${user} cmd='${proc_cmd}'"

                    safe_kill_process "$proc_pid" "$user" "malicious_cmd"

                    send_smart_alert "mal_${user}_${suspicious_count}" "$ALERT_COOLDOWN_CMD" \
                        "MALICIOUS COMMAND

User: ${user} | IP: ${ip}
Cmd: $(echo "$proc_cmd" | head -c 200)
Strike: ${suspicious_count}/${SUSPICIOUS_CMD_THRESHOLD}" "CRITICAL"

                    if [[ "$suspicious_count" -ge "$SUSPICIOUS_CMD_THRESHOLD" ]]; then
                        send_telegram "THRESHOLD: ${user} fully blocked" "CRITICAL"
                        safe_block_ip "$ip" "threshold"
                        safe_kill_sessions "$user"
                        safe_lock_account "$user"
                        return
                    fi
                    break
                fi
            done
        done <<< "$user_procs"

        sleep "$interval"
    done
}

# ========================== MODULE: FILE INTEGRITY ==========================

init_file_integrity() {
    local baseline="${BASELINE_DIR}/file_integrity"
    [[ -f "$baseline" ]] && return

    log_event "INFO" "Creating file integrity baseline"
    for file in "${SENSITIVE_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            local hash
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            [[ -n "$hash" ]] && echo "${file}|${hash}" >> "$baseline"
        fi
    done
}

check_file_integrity() {
    local baseline="${BASELINE_DIR}/file_integrity"
    [[ ! -f "$baseline" ]] && return

    can_heavy_scan || return

    with_lock "file_integrity" _check_integrity_internal
}

_check_integrity_internal() {
    local baseline="${BASELINE_DIR}/file_integrity"
    local temp="${baseline}.tmp"
    rm -f "$temp" 2>/dev/null

    while IFS='|' read -r file expected_hash; do
        [[ -z "$file" || -z "$expected_hash" ]] && continue

        if [[ -f "$file" ]]; then
            local current_hash
            current_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')

            if [[ -n "$current_hash" && "$current_hash" != "$expected_hash" ]]; then
                log_event "HIGH" "FILE MODIFIED: ${file}"

                send_smart_alert "integrity_${file//\//_}" "$ALERT_COOLDOWN_FILE" \
                    "FILE MODIFIED

${file}
Users: $(who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')" "HIGH"

                echo "${file}|${current_hash}" >> "$temp"
            else
                echo "${file}|${expected_hash}" >> "$temp"
            fi
        else
            echo "${file}|${expected_hash}" >> "$temp"
        fi
    done < "$baseline"

    [[ -f "$temp" ]] && mv "$temp" "$baseline" 2>/dev/null
}

start_file_integrity_monitor() {
    if command -v inotifywait &>/dev/null; then
        log_event "INFO" "File integrity: using inotifywait (event-driven)"

        local watch_files=()
        for f in "${SENSITIVE_FILES[@]}"; do
            [[ -f "$f" ]] && watch_files+=("$f")
        done

        if [[ ${#watch_files[@]} -gt 0 ]]; then
            inotifywait -m -e modify,create,delete,move "${watch_files[@]}" 2>/dev/null | while IFS= read -r event_line; do
                [[ "$RUNNING" == "false" ]] && break

                local changed_file
                changed_file=$(echo "$event_line" | awk '{print $1}')

                log_event "HIGH" "FILE EVENT: ${event_line}"

                send_smart_alert "inotify_${changed_file//\//_}" "$ALERT_COOLDOWN_FILE" \
                    "FILE CHANGED (real-time)

${event_line}
Users: $(who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')" "HIGH"
            done &
            track_child $!
        fi
    else
        log_event "INFO" "File integrity: polling mode (install inotify-tools for real-time)"

        (
            while [[ "$RUNNING" == "true" ]]; do
                check_file_integrity
                local interval
                interval=$(get_adaptive_interval "$SCAN_INTERVAL_VERY_HEAVY")
                sleep "$interval"
            done
        ) &
        track_child $!
    fi
}

# ========================== MODULE: NETWORK MONITOR ==========================

monitor_network() {
    log_event "INFO" "Network monitor started"

    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort > "${BASELINE_DIR}/ports" 2>/dev/null

    while [[ "$RUNNING" == "true" ]]; do
        can_heavy_scan || { sleep "$SCAN_INTERVAL_HEAVY"; continue; }

        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_MEDIUM")

        local current_raw
        current_raw=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
        local current_list
        current_list=$(echo "$current_raw" | awk '{print $4}' | sort)

        if [[ -f "${BASELINE_DIR}/ports" ]]; then
            local new_ports
            new_ports=$(diff <(cat "${BASELINE_DIR}/ports") <(echo "$current_list") 2>/dev/null | grep "^>" | sed 's/^> //' || true)

            while IFS= read -r new_port; do
                [[ -z "$new_port" ]] && continue

                local detail pid port_user port_cmd
                detail=$(echo "$current_raw" | grep "$new_port" | head -1 || true)
                pid=$(echo "$detail" | grep -oP 'pid=\K\d+' 2>/dev/null | head -1)

                [[ -z "$pid" ]] && continue

                port_user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
                is_protected_user "$port_user" && continue

                port_cmd=$(ps -o cmd= -p "$pid" 2>/dev/null || true)
                is_whitelisted_program "$port_cmd" && continue

                log_event "HIGH" "New port: ${new_port} user=${port_user}"

                send_smart_alert "port_${new_port}" "$ALERT_COOLDOWN_NET" \
                    "NEW PORT

Port: ${new_port} | User: ${port_user}
Cmd: $(echo "$port_cmd" | head -c 150)" "HIGH"

                safe_kill_process "$pid" "$port_user" "suspicious_port"
            done <<< "$new_ports"
        fi

        echo "$current_list" > "${BASELINE_DIR}/ports" 2>/dev/null

        # Reverse shell detection
        local conns
        conns=$(ss -tnp 2>/dev/null | grep "ESTAB" || true)

        while IFS= read -r conn; do
            [[ -z "$conn" ]] && continue

            local cpid
            cpid=$(echo "$conn" | grep -oP 'pid=\K\d+' 2>/dev/null | head -1)
            [[ -z "$cpid" ]] && continue
            is_own_process "$cpid" && continue

            local ccmd
            ccmd=$(ps -o cmd= -p "$cpid" 2>/dev/null || true)
            [[ -z "$ccmd" ]] && continue
            is_whitelisted_program "$ccmd" && continue

            local cuser
            cuser=$(ps -o user= -p "$cpid" 2>/dev/null | tr -d ' ')
            is_protected_user "$cuser" && continue

            if echo "$ccmd" | grep -qiE "bash -i >&.*/dev/(tcp|udp)/" 2>/dev/null; then
                log_event "CRITICAL" "REVERSE SHELL: ${cuser} cmd=${ccmd}"

                local remote_ip
                remote_ip=$(echo "$conn" | awk '{print $5}' | rev | cut -d: -f2- | rev)

                send_telegram "REVERSE SHELL

User: ${cuser} | Remote: ${remote_ip}
Cmd: $(echo "$ccmd" | head -c 200)" "CRITICAL"

                safe_kill_process "$cpid" "$cuser" "reverse_shell"
                [[ -n "$remote_ip" ]] && safe_block_ip "$remote_ip" "reverse_shell"
                safe_kill_sessions "$cuser"
            fi
        done <<< "$conns"

        sleep "$interval"
    done
}

# ========================== MODULE: PROCESS MONITOR ==========================

monitor_processes() {
    log_event "INFO" "Process monitor started"

    while [[ "$RUNNING" == "true" ]]; do
        can_heavy_scan || { sleep "$SCAN_INTERVAL_HEAVY"; continue; }

        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_MEDIUM")

        local real_users
        real_users=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd 2>/dev/null || true)

        while IFS= read -r check_user; do
            [[ -z "$check_user" ]] && continue
            is_protected_user "$check_user" && continue

            local procs
            procs=$(ps -u "$check_user" -o pid=,cmd= --no-headers 2>/dev/null || true)

            while IFS= read -r pl; do
                [[ -z "$pl" ]] && continue

                local ppid pcmd
                ppid=$(echo "$pl" | awk '{print $1}')
                pcmd=$(echo "$pl" | awk '{$1=""; print $0}' | sed 's/^ //')

                is_own_process "$ppid" && continue
                is_whitelisted_program "$pcmd" && continue

                for pattern in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
                    if echo "$pcmd" | grep -qiF "$pattern" 2>/dev/null; then
                        log_event "CRITICAL" "MALICIOUS PROC: ${check_user} cmd=${pcmd}"
                        safe_kill_process "$ppid" "$check_user" "malicious"

                        send_smart_alert "proc_${check_user}_${ppid}" "$ALERT_COOLDOWN_CMD" \
                            "MALICIOUS PROCESS

User: ${check_user} | Cmd: $(echo "$pcmd" | head -c 200)" "CRITICAL"
                        break
                    fi
                done
            done <<< "$procs"
        done <<< "$real_users"

        # SUID check (temp paths only) — with whitelist filtering
        local suid
        suid=$(find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | sort || true)

        if [[ -f "${BASELINE_DIR}/suid" ]]; then
            local suid_diff
            suid_diff=$(diff <(cat "${BASELINE_DIR}/suid") <(echo "$suid") 2>/dev/null | grep "^>" | sed 's/^> //' || true)

            if [[ -n "$suid_diff" ]]; then
                # Filter out whitelisted SUID binaries
                local suspicious_suids=""
                while IFS= read -r sf; do
                    [[ -z "$sf" ]] && continue
                    if ! is_whitelisted_suid "$sf"; then
                        suspicious_suids="${suspicious_suids}${sf}"$'\n'
                    fi
                done <<< "$suid_diff"

                if [[ -n "$suspicious_suids" ]]; then
                    send_smart_alert "suid_new" "$ALERT_COOLDOWN_FILE" \
                        "NEW SUID IN TEMP

${suspicious_suids}" "CRITICAL"

                    if can_take_action; then
                        while IFS= read -r sf; do
                            [[ -z "$sf" ]] && continue
                            is_whitelisted_suid "$sf" && continue
                            chmod u-s "$sf" 2>/dev/null
                        done <<< "$suid_diff"
                    fi
                fi
            fi
        fi

        echo "$suid" > "${BASELINE_DIR}/suid" 2>/dev/null

        sleep "$interval"
    done
}

# ========================== MODULE: PERSISTENCE MONITOR ==========================

monitor_persistence() {
    log_event "INFO" "Persistence monitor started"

    while [[ "$RUNNING" == "true" ]]; do
        can_heavy_scan || { sleep "$SCAN_INTERVAL_HEAVY"; continue; }

        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_HEAVY")

        # Crontab
        local crons=""
        for cf in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/crontab /etc/cron.d/*; do
            [[ -f "$cf" ]] && crons+="$(cat "$cf" 2>/dev/null)"$'\n'
        done

        local cron_hash
        cron_hash=$(echo "$crons" | sha256sum | awk '{print $1}')

        if [[ -f "${BASELINE_DIR}/cron_hash" ]]; then
            local prev
            prev=$(cat "${BASELINE_DIR}/cron_hash" 2>/dev/null)
            [[ "$cron_hash" != "$prev" ]] && send_smart_alert "cron" "$ALERT_COOLDOWN_PERSIST" "Crontab Modified" "HIGH"
        fi
        echo "$cron_hash" > "${BASELINE_DIR}/cron_hash" 2>/dev/null

        # SSH keys
        local ak=""
        while IFS= read -r kf; do
            [[ -z "$kf" ]] && continue
            ak+="$(sha256sum "$kf" 2>/dev/null)"$'\n'
        done < <(find /home /root -name "authorized_keys" -type f 2>/dev/null)

        local ak_hash
        ak_hash=$(echo "$ak" | sha256sum | awk '{print $1}')

        if [[ -f "${BASELINE_DIR}/ak_hash" ]]; then
            local prev_ak
            prev_ak=$(cat "${BASELINE_DIR}/ak_hash" 2>/dev/null)
            [[ "$ak_hash" != "$prev_ak" ]] && send_smart_alert "authkeys" "$ALERT_COOLDOWN_PERSIST" "SSH Keys Modified" "HIGH"
        fi
        echo "$ak_hash" > "${BASELINE_DIR}/ak_hash" 2>/dev/null

        # Systemd services
        local svc_hash
        svc_hash=$(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -type f 2>/dev/null | sort | sha256sum | awk '{print $1}')

        if [[ -f "${BASELINE_DIR}/svc_hash" ]]; then
            local prev_svc
            prev_svc=$(cat "${BASELINE_DIR}/svc_hash" 2>/dev/null)
            [[ "$svc_hash" != "$prev_svc" ]] && send_smart_alert "services" "$ALERT_COOLDOWN_PERSIST" "Systemd Services Changed" "HIGH"
        fi
        echo "$svc_hash" > "${BASELINE_DIR}/svc_hash" 2>/dev/null

        # ld.so.preload rootkit
        if [[ -f /etc/ld.so.preload ]] && [[ -s /etc/ld.so.preload ]]; then
            send_smart_alert "ldpreload" 60 "LD_PRELOAD ROOTKIT: $(cat /etc/ld.so.preload 2>/dev/null)" "CRITICAL"
            can_take_action && echo "" > /etc/ld.so.preload 2>/dev/null
        fi

        sleep "$interval"
    done
}

# ========================== MODULE: ALL-LOGIN MONITOR (RAPID 2s) ==========================

monitor_all_logins() {
    log_event "INFO" "Rapid login monitor started (${REALTIME_LOGIN_INTERVAL}s interval)"

    who 2>/dev/null > "${BASELINE_DIR}/sessions" 2>/dev/null
    who 2>/dev/null | sha256sum | awk '{print $1}' > "${BASELINE_DIR}/sessions_hash" 2>/dev/null

    while [[ "$RUNNING" == "true" ]]; do
        local current
        current=$(who 2>/dev/null || true)
        local hash
        hash=$(echo "$current" | sha256sum | awk '{print $1}')

        local prev_hash=""
        [[ -f "${BASELINE_DIR}/sessions_hash" ]] && prev_hash=$(cat "${BASELINE_DIR}/sessions_hash" 2>/dev/null)

        if [[ "$hash" != "$prev_hash" ]]; then
            local prev=""
            [[ -f "${BASELINE_DIR}/sessions" ]] && prev=$(cat "${BASELINE_DIR}/sessions" 2>/dev/null)

            local new_sessions
            new_sessions=$(diff <(echo "$prev") <(echo "$current") 2>/dev/null | grep "^>" | sed 's/^> //' || true)

            while IFS= read -r sl; do
                [[ -z "$sl" ]] && continue

                local s_user s_source s_tty
                s_user=$(echo "$sl" | awk '{print $1}')
                s_tty=$(echo "$sl" | awk '{print $2}')
                s_source=$(echo "$sl" | awk '{print $5}' | tr -d '()')
                [[ -z "$s_source" ]] && s_source="local"

                log_event "INFO" "New session detected: user=${s_user} tty=${s_tty} source=${s_source}"

                # SAFETY: Skip our own sessions
                if is_my_own_session "$s_user" "$s_source"; then
                    log_event "INFO" "Owner session confirmed: ${s_user} from ${s_source}"
                    send_smart_alert "login_owner_${s_source}" "$ALERT_COOLDOWN_SSH" \
                        "✅ Owner Login Detected

User: ${s_user} | Source: ${s_source}
TTY: ${s_tty}" "LOW"
                    continue
                fi

                # THREAT: Trusted user from untrusted IP
                if is_trusted_user "$s_user"; then
                    local sp
                    sp=$(pgrep -n -u "$s_user" 2>/dev/null || echo "unknown")
                    handle_compromised_trusted_account "$s_user" "$s_source" "$sp"

                # THREAT: Untrusted user login
                elif ! is_system_user "$s_user"; then
                    send_smart_alert "login_${s_user}" "$ALERT_COOLDOWN_SSH" \
                        "🚨 UNTRUSTED USER LOGIN

User: ${s_user} | Source: ${s_source}
TTY: ${s_tty}
Action: Jail + Monitor" "CRITICAL"

                    if can_take_action; then
                        local sp
                        sp=$(pgrep -n -u "$s_user" 2>/dev/null || echo "")
                        activate_jail_for_session "$s_user" "$s_source" "$sp"
                        monitor_untrusted_session "$s_user" "$s_source" "$sp" &
                        track_child $!
                    fi
                fi
            done <<< "$new_sessions"

            # Logouts
            local gone
            gone=$(diff <(echo "$prev") <(echo "$current") 2>/dev/null | grep "^<" | sed 's/^< //' || true)

            while IFS= read -r gl; do
                [[ -z "$gl" ]] && continue
                local gu
                gu=$(echo "$gl" | awk '{print $1}')
                is_protected_user "$gu" || deactivate_jail_for_user "$gu"
            done <<< "$gone"
        fi

        echo "$hash" > "${BASELINE_DIR}/sessions_hash" 2>/dev/null
        echo "$current" > "${BASELINE_DIR}/sessions" 2>/dev/null

        sleep "$REALTIME_LOGIN_INTERVAL"
    done
}

# ========================== MODULE: RAPID LAST-LOG WATCHER ==========================

monitor_wtmp_logins() {
    log_event "INFO" "WTMP rapid watcher started"

    last -n 20 -i 2>/dev/null | head -20 > "${BASELINE_DIR}/last_logins" 2>/dev/null

    while [[ "$RUNNING" == "true" ]]; do
        local current_last
        current_last=$(last -n 20 -i 2>/dev/null | head -20 || true)

        if [[ -f "${BASELINE_DIR}/last_logins" ]]; then
            local prev_last
            prev_last=$(cat "${BASELINE_DIR}/last_logins" 2>/dev/null)

            local new_entries
            new_entries=$(diff <(echo "$prev_last") <(echo "$current_last") 2>/dev/null | grep "^>" | sed 's/^> //' || true)

            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                echo "$entry" | grep -qiE "^(reboot|wtmp begins|$)" && continue

                local l_user l_ip
                l_user=$(echo "$entry" | awk '{print $1}')
                l_ip=$(echo "$entry" | awk '{print $3}')
                [[ -z "$l_ip" || "$l_ip" == "0.0.0.0" ]] && l_ip="local"

                is_my_own_session "$l_user" "$l_ip" && continue

                if is_trusted_user "$l_user" && ! is_my_own_ip "$l_ip"; then
                    log_event "CRITICAL" "WTMP: Untrusted login to trusted account ${l_user} from ${l_ip}"
                    local sp
                    sp=$(pgrep -n -u "$l_user" 2>/dev/null || echo "unknown")
                    handle_compromised_trusted_account "$l_user" "$l_ip" "$sp"
                elif ! is_system_user "$l_user" && ! is_trusted_user "$l_user"; then
                    log_event "HIGH" "WTMP: Unknown user login ${l_user} from ${l_ip}"
                    send_smart_alert "wtmp_${l_user}" "$ALERT_COOLDOWN_SSH" \
                        "🔍 WTMP Login Detected

User: ${l_user} | IP: ${l_ip}
Source: wtmp/last" "HIGH"
                fi
            done <<< "$new_entries"
        fi

        echo "$current_last" > "${BASELINE_DIR}/last_logins" 2>/dev/null
        sleep "$REALTIME_LOGIN_INTERVAL"
    done
}

# ========================== MODULE: PAM HOOK (INSTANT DETECTION) ==========================

install_pam_hook() {
    local pam_script="${INSTALL_DIR}/pam_epg_hook.sh"
    local pam_dir="/etc/pam.d"

    cat > "$pam_script" << 'PAMHOOK'
#!/bin/bash
# EndpointGuard PAM Hook
EPG_DIR="/opt/.epg"
TRUSTED_IPS_FILE="${EPG_DIR}/trusted_ips.conf"
ALERT_FIFO="${EPG_DIR}/pam_alerts.fifo"

LOGIN_USER="${PAM_USER:-unknown}"
LOGIN_IP="${PAM_RHOST:-local}"
LOGIN_TYPE="${PAM_TYPE:-unknown}"
LOGIN_SERVICE="${PAM_SERVICE:-unknown}"
LOGIN_TTY="${PAM_TTY:-unknown}"

if [[ -p "$ALERT_FIFO" ]]; then
    echo "$(date +%s)|${LOGIN_USER}|${LOGIN_IP}|${LOGIN_TYPE}|${LOGIN_SERVICE}|${LOGIN_TTY}" > "$ALERT_FIFO" 2>/dev/null &
fi

if [[ -f "$TRUSTED_IPS_FILE" ]]; then
    if ! grep -qF "$LOGIN_IP" "$TRUSTED_IPS_FILE" 2>/dev/null; then
        echo "$(date +%s) UNTRUSTED_PAM user=${LOGIN_USER} ip=${LOGIN_IP} svc=${LOGIN_SERVICE}" >> "${EPG_DIR}/pam_events.log" 2>/dev/null
    fi
fi

exit 0
PAMHOOK
    chmod 700 "$pam_script"

    echo "$TRUSTED_IPS 127.0.0.1 ::1 $MY_CURRENT_IPS" | tr ' ' '\n' | sort -u > "${INSTALL_DIR}/trusted_ips.conf" 2>/dev/null

    local fifo="${INSTALL_DIR}/pam_alerts.fifo"
    [[ ! -p "$fifo" ]] && mkfifo "$fifo" 2>/dev/null
    chmod 622 "$fifo" 2>/dev/null

    if [[ -f "${pam_dir}/sshd" ]]; then
        if ! grep -q "pam_epg_hook" "${pam_dir}/sshd" 2>/dev/null; then
            cp "${pam_dir}/sshd" "${pam_dir}/sshd.epg_backup" 2>/dev/null
            echo "session optional pam_exec.so seteuid ${pam_script}" >> "${pam_dir}/sshd" 2>/dev/null
            log_event "INFO" "PAM hook installed for sshd"
        fi
    fi

    if [[ -f "${pam_dir}/login" ]]; then
        if ! grep -q "pam_epg_hook" "${pam_dir}/login" 2>/dev/null; then
            cp "${pam_dir}/login" "${pam_dir}/login.epg_backup" 2>/dev/null
            echo "session optional pam_exec.so seteuid ${pam_script}" >> "${pam_dir}/login" 2>/dev/null
            log_event "INFO" "PAM hook installed for console login"
        fi
    fi

    if [[ -f "${pam_dir}/su" ]]; then
        if ! grep -q "pam_epg_hook" "${pam_dir}/su" 2>/dev/null; then
            cp "${pam_dir}/su" "${pam_dir}/su.epg_backup" 2>/dev/null
            echo "session optional pam_exec.so seteuid ${pam_script}" >> "${pam_dir}/su" 2>/dev/null
            log_event "INFO" "PAM hook installed for su"
        fi
    fi

    log_event "INFO" "PAM hooks installed for instant login detection"
}

uninstall_pam_hooks() {
    local pam_dir="/etc/pam.d"

    for svc in sshd login su; do
        if [[ -f "${pam_dir}/${svc}.epg_backup" ]]; then
            mv "${pam_dir}/${svc}.epg_backup" "${pam_dir}/${svc}" 2>/dev/null
        else
            sed -i '/pam_epg_hook/d' "${pam_dir}/${svc}" 2>/dev/null
        fi
    done

    rm -f "${INSTALL_DIR}/pam_epg_hook.sh" "${INSTALL_DIR}/pam_alerts.fifo" \
          "${INSTALL_DIR}/pam_events.log" "${INSTALL_DIR}/trusted_ips.conf" 2>/dev/null
    log_event "INFO" "PAM hooks removed"
}

monitor_pam_alerts() {
    local fifo="${INSTALL_DIR}/pam_alerts.fifo"

    [[ ! -p "$fifo" ]] && return

    log_event "INFO" "PAM alert monitor started (instant detection)"

    while [[ "$RUNNING" == "true" ]]; do
        # Use timeout read to prevent blocking forever on Ctrl+C
        if read -r -t 5 alert_line < "$fifo" 2>/dev/null; then
            [[ -z "$alert_line" ]] && continue

            IFS='|' read -r timestamp pam_user pam_ip pam_type pam_service pam_tty <<< "$alert_line"

            log_event "INFO" "PAM event: user=${pam_user} ip=${pam_ip} svc=${pam_service} type=${pam_type}"

            is_my_own_session "$pam_user" "$pam_ip" && continue

            if is_trusted_user "$pam_user" && ! is_my_own_ip "$pam_ip"; then
                log_event "CRITICAL" "PAM: Untrusted access to ${pam_user} from ${pam_ip} via ${pam_service}"
                local sp
                sp=$(pgrep -n -u "$pam_user" 2>/dev/null || echo "unknown")
                handle_compromised_trusted_account "$pam_user" "$pam_ip" "$sp"

            elif ! is_system_user "$pam_user" && ! is_trusted_user "$pam_user"; then
                send_smart_alert "pam_${pam_user}_${pam_ip}" "$ALERT_COOLDOWN_SSH" \
                    "🔐 PAM LOGIN DETECTED (INSTANT)

User: ${pam_user} | IP: ${pam_ip}
Service: ${pam_service} | TTY: ${pam_tty}" "CRITICAL"

                if can_take_action; then
                    local sp
                    sp=$(pgrep -n -u "$pam_user" 2>/dev/null || echo "")
                    activate_jail_for_session "$pam_user" "$pam_ip" "$sp"
                    safe_block_ip "$pam_ip" "pam_untrusted_login"
                fi
            fi
        fi
    done
}

monitor_pam_events_log() {
    local pam_log="${INSTALL_DIR}/pam_events.log"
    [[ ! -f "$pam_log" ]] && touch "$pam_log" 2>/dev/null

    log_event "INFO" "PAM events log monitor started"

    tail -n 0 -F "$pam_log" 2>/dev/null | while IFS= read -r line; do
        [[ "$RUNNING" == "false" ]] && break
        [[ -z "$line" ]] && continue

        local pu pi
        pu=$(echo "$line" | grep -oP 'user=\K\S+' 2>/dev/null)
        pi=$(echo "$line" | grep -oP 'ip=\K\S+' 2>/dev/null)

        [[ -z "$pu" || -z "$pi" ]] && continue
        is_my_own_session "$pu" "$pi" && continue

        if is_trusted_user "$pu"; then
            local sp
            sp=$(pgrep -n -u "$pu" 2>/dev/null || echo "unknown")
            handle_compromised_trusted_account "$pu" "$pi" "$sp"
        fi
    done &
    track_child $!
}

# ========================== MODULE: SU/SUDO MONITOR ==========================

monitor_su_sudo() {
    local auth_source
    auth_source=$(find_auth_log)

    log_event "INFO" "SU/Sudo monitor started"

    _process_su_sudo() {
        local line="$1"
        [[ -z "$line" ]] && return

        # SU
        if echo "$line" | grep -qiE "(su\[|su:).*session opened" 2>/dev/null; then
            local su_user
            su_user=$(echo "$line" | grep -oP 'by \K\S+' 2>/dev/null | tr -d '()' | head -1)
            [[ -z "$su_user" ]] && return

            if ! is_protected_user "$su_user"; then
                send_smart_alert "su_${su_user}" "$ALERT_COOLDOWN_CMD" "SU by untrusted: ${su_user}" "HIGH"
                can_take_action && pkill -u "$su_user" su 2>/dev/null
            fi
        fi

        # SUDO
        if echo "$line" | grep -qiE "sudo:.*COMMAND=" 2>/dev/null; then
            local sudo_user sudo_cmd
            sudo_user=$(echo "$line" | grep -oP 'sudo:\s+\K\S+' 2>/dev/null | head -1)
            sudo_cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*' 2>/dev/null)
            [[ -z "$sudo_user" ]] && return

            if ! is_protected_user "$sudo_user"; then
                local dangerous=false
                for p in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
                    echo "$sudo_cmd" | grep -qiF "$p" 2>/dev/null && dangerous=true && break
                done

                if [[ "$dangerous" == "true" ]]; then
                    send_telegram "DANGEROUS SUDO: ${sudo_user} cmd=$(echo "$sudo_cmd" | head -c 200)" "CRITICAL"
                    safe_kill_sessions "$sudo_user"
                    safe_lock_account "$sudo_user"
                else
                    send_smart_alert "sudo_${sudo_user}" "$ALERT_COOLDOWN_CMD" \
                        "SUDO: ${sudo_user} cmd=$(echo "$sudo_cmd" | head -c 200)" "MEDIUM"
                fi
            fi
        fi

        # Failed sudo
        if echo "$line" | grep -qiE "sudo:.*authentication failure" 2>/dev/null; then
            local fu
            fu=$(echo "$line" | grep -oP '(user=)\K\S+' 2>/dev/null | head -1)
            [[ -n "$fu" ]] && ! is_protected_user "$fu" && \
                send_smart_alert "sudofail_${fu}" "$ALERT_COOLDOWN_SSH" "Sudo fail: ${fu}" "MEDIUM"
        fi
    }

    if [[ "$auth_source" == "journalctl" ]]; then
        journalctl -f --no-pager -n 0 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            _process_su_sudo "$line"
        done &
    else
        local logfile="${auth_source#file:}"
        tail -n 0 -F "$logfile" 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            _process_su_sudo "$line"
        done &
    fi

    track_child $!
}

# ========================== MODULE: KERNEL MONITOR (WITH WHITELIST) ==========================

monitor_kernel_modules() {
    log_event "INFO" "Kernel monitor started (with whitelist)"
    lsmod 2>/dev/null | sort > "${BASELINE_DIR}/kmods" 2>/dev/null

    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_VERY_HEAVY")

        local current
        current=$(lsmod 2>/dev/null | sort)

        if [[ -f "${BASELINE_DIR}/kmods" ]]; then
            local new_mods
            new_mods=$(diff <(cat "${BASELINE_DIR}/kmods") <(echo "$current") 2>/dev/null | grep "^>" | sed 's/^> //' || true)

            if [[ -n "$new_mods" ]]; then
                # Filter out whitelisted kernel modules
                local suspicious_mods=""
                while IFS= read -r mod_line; do
                    [[ -z "$mod_line" ]] && continue

                    local mod_name
                    mod_name=$(echo "$mod_line" | awk '{print $1}')
                    [[ -z "$mod_name" ]] && continue

                    if ! is_whitelisted_kernel_module "$mod_name"; then
                        suspicious_mods="${suspicious_mods}${mod_line}"$'\n'
                        log_event "HIGH" "Suspicious kernel module loaded: ${mod_name}"
                    else
                        log_event "INFO" "Whitelisted kernel module loaded: ${mod_name}"
                    fi
                done <<< "$new_mods"

                # Only alert on truly suspicious modules
                if [[ -n "$suspicious_mods" ]]; then
                    send_smart_alert "kmod" "$ALERT_COOLDOWN_OTHER" \
                        "⚠️ Suspicious Kernel Modules Loaded:

${suspicious_mods}" "HIGH"
                fi
            fi
        fi

        echo "$current" > "${BASELINE_DIR}/kmods" 2>/dev/null
        sleep "$interval"
    done
}

# ========================== MODULE: RESOURCE MONITOR ==========================

monitor_resource_abuse() {
    log_event "INFO" "Resource monitor started"

    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_MEDIUM")

        local high_cpu
        high_cpu=$(ps aux --no-headers 2>/dev/null | awk '$3 > 95.0 {print $0}' || true)

        while IFS= read -r cl; do
            [[ -z "$cl" ]] && continue

            local cu cp cc
            cu=$(echo "$cl" | awk '{print $1}')
            cp=$(echo "$cl" | awk '{print $2}')
            cc=$(echo "$cl" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i}')

            is_protected_user "$cu" && continue
            is_own_process "$cp" && continue
            is_whitelisted_program "$cc" && continue

            if echo "$cc" | grep -qiE "(xmrig|minerd|cpuminer|cryptonight|stratum\+tcp)" 2>/dev/null; then
                safe_kill_process "$cp" "$cu" "miner"
                send_smart_alert "miner_${cp}" "$ALERT_COOLDOWN_OTHER" "MINER: ${cu} cmd=$(echo "$cc" | head -c 150)" "CRITICAL"
                safe_kill_sessions "$cu"
            else
                send_smart_alert "cpu_${cu}" "$ALERT_COOLDOWN_OTHER" "High CPU: ${cu} $(echo "$cc" | head -c 100)" "MEDIUM"
            fi
        done <<< "$high_cpu"

        sleep "$interval"
    done
}

# ========================== MODULE: ANTI-TAMPERING ==========================

anti_tampering() {
    log_event "INFO" "Anti-tampering started"

    local self_path
    self_path=$(readlink -f "$0" 2>/dev/null || echo "$0")
    sha256sum "$self_path" 2>/dev/null | awk '{print $1}' > "${BASELINE_DIR}/self_hash" 2>/dev/null
    iptables -L INPUT -n 2>/dev/null | wc -l > "${BASELINE_DIR}/fw_count" 2>/dev/null

    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_HEAVY")

        # Self integrity
        if [[ -f "${BASELINE_DIR}/self_hash" ]]; then
            local ch eh
            ch=$(sha256sum "$self_path" 2>/dev/null | awk '{print $1}')
            eh=$(cat "${BASELINE_DIR}/self_hash" 2>/dev/null)
            [[ -n "$ch" && -n "$eh" && "$ch" != "$eh" ]] && \
                send_smart_alert "tamper" 300 "EPG BINARY MODIFIED!" "CRITICAL"
        fi

        # Firewall integrity
        if [[ -f "${BASELINE_DIR}/fw_count" ]] && can_block_ip; then
            local rc pc
            rc=$(iptables -L INPUT -n 2>/dev/null | wc -l)
            pc=$(cat "${BASELINE_DIR}/fw_count" 2>/dev/null || echo "0")

            if [[ "$pc" -gt 5 && "$rc" -lt "$((pc - 5))" ]]; then
                send_smart_alert "fw_flush" 600 "FIREWALL FLUSHED (${pc}→${rc})" "CRITICAL"

                [[ -f "$BLOCKED_FILE" ]] && while IFS='|' read -r ip _ _; do
                    [[ -z "$ip" ]] && continue
                    iptables -I INPUT -s "$ip" -j DROP 2>/dev/null
                    iptables -I OUTPUT -d "$ip" -j DROP 2>/dev/null
                done < "$BLOCKED_FILE"
            fi

            echo "$rc" > "${BASELINE_DIR}/fw_count" 2>/dev/null
        fi

        sleep "$interval"
    done
}

# ========================== SSH HARDENING ==========================

apply_ssh_hardening() {
    local conf="/etc/ssh/sshd_config"
    [[ ! -f "$conf" ]] && return

    if [[ "$SAFETY_MODE" == "monitor" ]]; then
        log_event "INFO" "SSH hardening skipped (monitor mode)"
        return
    fi

    log_event "INFO" "Applying SSH hardening"
    [[ ! -f "${conf}.epg_backup" ]] && cp "$conf" "${conf}.epg_backup" 2>/dev/null

    _set() {
        local k="$1" v="$2"
        if grep -qE "^${k}\s" "$conf" 2>/dev/null; then
            sed -i "s/^${k}\s.*/${k} ${v}/" "$conf" 2>/dev/null
        elif grep -qE "^#\s*${k}\s" "$conf" 2>/dev/null; then
            sed -i "s/^#\s*${k}\s.*/${k} ${v}/" "$conf" 2>/dev/null
        else
            echo "${k} ${v}" >> "$conf"
        fi
    }

    _set "MaxAuthTries" "5"
    _set "LoginGraceTime" "60"
    _set "PermitEmptyPasswords" "no"
    _set "ClientAliveInterval" "300"
    _set "ClientAliveCountMax" "3"
    _set "MaxSessions" "10"
    _set "LogLevel" "VERBOSE"

    cat > /etc/ssh/banner << 'BANNER'
================================================================
       AUTHORIZED ACCESS ONLY — All connections monitored.
================================================================
BANNER
    _set "Banner" "/etc/ssh/banner"

    systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null
}

# ========================== DAILY REPORT ==========================

generate_daily_report() {
    log_event "INFO" "Daily report started"
    local last_day=""

    while [[ "$RUNNING" == "true" ]]; do
        local hour day
        hour=$(date +%H)
        day=$(date +%Y-%m-%d)

        if [[ "$hour" == "00" && "$day" != "$last_day" ]]; then
            last_day="$day"

            local total=0 crit=0 high=0 blocked=0

            [[ -f "$LOG_FILE" ]] && {
                total=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
                crit=$(grep -c "CRITICAL" "$LOG_FILE" 2>/dev/null || echo 0)
                high=$(grep -c "HIGH" "$LOG_FILE" 2>/dev/null || echo 0)
            }
            [[ -f "$BLOCKED_FILE" ]] && blocked=$(wc -l < "$BLOCKED_FILE" 2>/dev/null || echo 0)

            send_telegram "DAILY REPORT 📊

Mode: ${SAFETY_MODE} | Events: ${total}
Critical: ${crit} | High: ${high} | Blocked: ${blocked}" "LOW"

            find "$ALERT_TRACKER" -type f -mtime +7 -delete 2>/dev/null

            local sz
            sz=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
            if [[ "$sz" -gt 52428800 ]]; then
                mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d)" 2>/dev/null
                gzip "${LOG_FILE}.$(date +%Y%m%d)" 2>/dev/null &
                touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
                ls -t "${LOG_FILE}".*.gz 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null
            fi
        fi

        sleep 3600
    done
}

# ========================== DAEMON CONTROL ==========================

start_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local ep
        ep=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$ep" ]] && kill -0 "$ep" 2>/dev/null; then
            echo -e "${YELLOW}Already running (PID: ${ep})${NC}"
            return 1
        fi
    fi

    [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Must run as root${NC}" && exit 1

    show_banner

    echo -e "  ${WHITE}${BOLD}⚙  CONFIGURATION${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    case "$SAFETY_MODE" in
        monitor)  echo -e "  ${GREEN}●${NC}  Mode:    ${BOLD}${GREEN}MONITOR${NC} ${DIM}(Alert only — ZERO risk)${NC}" ;;
        moderate) echo -e "  ${YELLOW}●${NC}  Mode:    ${BOLD}${YELLOW}MODERATE${NC} ${DIM}(Alert + block brute force)${NC}" ;;
        active)   echo -e "  ${RED}●${NC}  Mode:    ${BOLD}${RED}ACTIVE${NC} ${DIM}(Full auto-response)${NC}" ;;
    esac

    echo -e "  ${CYAN}●${NC}  User:    ${BOLD}${TRUSTED_USER}${NC}"

    [[ "$TELEGRAM_BOT_TOKEN" == "YOUR_BOT_TOKEN_HERE" ]] && \
        echo -e "  ${YELLOW}●${NC}  Telegram: ${YELLOW}Not configured${NC}" || \
        echo -e "  ${GREEN}●${NC}  Telegram: ${GREEN}Configured${NC}"

    command -v flock &>/dev/null && \
        echo -e "  ${GREEN}●${NC}  Locking:  ${GREEN}flock (atomic)${NC}" || \
        echo -e "  ${YELLOW}●${NC}  Locking:  ${YELLOW}mkdir (fallback)${NC}"

    command -v inotifywait &>/dev/null && \
        echo -e "  ${GREEN}●${NC}  FileWatch: ${GREEN}inotifywait (event-driven)${NC}" || \
        echo -e "  ${YELLOW}●${NC}  FileWatch: ${YELLOW}polling mode${NC}"

    echo ""
    echo -e "  ${WHITE}${BOLD}🔌 STARTING MODULES${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    log_event "INFO" "===== EPG v4.0 Starting (mode=${SAFETY_MODE}) ====="

    # Set up signal handling BEFORE launching anything
    trap cleanup SIGTERM SIGINT SIGHUP

    init_directories
    detect_my_ips
    setup_honeypot_jail
    init_file_integrity
    apply_ssh_hardening
    install_pam_hook

    # Recover any jailed users from previous crash
    recover_jailed_users

    # Baselines
    find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | sort > "${BASELINE_DIR}/suid" 2>/dev/null
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort > "${BASELINE_DIR}/ports" 2>/dev/null
    lsmod 2>/dev/null | sort > "${BASELINE_DIR}/kmods" 2>/dev/null

    local ic=""
    for cf in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/crontab /etc/cron.d/*; do
        [[ -f "$cf" ]] && ic+="$(cat "$cf" 2>/dev/null)"$'\n'
    done
    echo "$ic" | sha256sum | awk '{print $1}' > "${BASELINE_DIR}/cron_hash" 2>/dev/null

    local iak=""
    while IFS= read -r kf; do
        [[ -z "$kf" ]] && continue
        iak+="$(sha256sum "$kf" 2>/dev/null)"$'\n'
    done < <(find /home /root -name "authorized_keys" -type f 2>/dev/null)
    echo "$iak" | sha256sum | awk '{print $1}' > "${BASELINE_DIR}/ak_hash" 2>/dev/null

    find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -type f 2>/dev/null | \
        sort | sha256sum | awk '{print $1}' > "${BASELINE_DIR}/svc_hash" 2>/dev/null

    # Launch modules
    monitor_ssh_logins
    echo -e "  ${GREEN}  [✓]${NC} SSH Monitor"

    monitor_all_logins &             track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Rapid Login Monitor (${REALTIME_LOGIN_INTERVAL}s)"

    monitor_wtmp_logins &            track_child $!
    echo -e "  ${GREEN}  [✓]${NC} WTMP Rapid Watcher"

    monitor_su_sudo
    echo -e "  ${GREEN}  [✓]${NC} SU/Sudo Monitor"

    monitor_network &                track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Network Monitor"

    monitor_processes &              track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Process Monitor"

    monitor_persistence &            track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Persistence Monitor"

    monitor_kernel_modules &         track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Kernel Monitor ${DIM}(with whitelist)${NC}"

    monitor_resource_abuse &         track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Resource Monitor"

    anti_tampering &                 track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Anti-Tampering"

    generate_daily_report &          track_child $!
    echo -e "  ${GREEN}  [✓]${NC} Daily Report"

    start_file_integrity_monitor
    echo -e "  ${GREEN}  [✓]${NC} File Integrity ${DIM}($(command -v inotifywait &>/dev/null && echo 'event-driven' || echo 'polling'))${NC}"

    monitor_pam_alerts &             track_child $!
    echo -e "  ${GREEN}  [✓]${NC} PAM Instant Detection"

    monitor_pam_events_log
    echo -e "  ${GREEN}  [✓]${NC} PAM Events Log"

    echo $$ > "$PID_FILE"

    echo ""
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}${BOLD}  ✅ All 14 modules active! (2-3 sec response time)${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${DIM}Owner IPs:${NC}  ${CYAN}${MY_CURRENT_IPS}${NC}"
    echo -e "  ${DIM}PID:${NC}        ${WHITE}$$${NC}"
    echo -e "  ${DIM}Mode:${NC}       ${BOLD}${SAFETY_MODE^^}${NC}"
    echo -e "  ${DIM}Log:${NC}        ${CYAN}${LOG_FILE}${NC}"
    echo ""
    echo -e "  ${DIM}Press Ctrl+C to stop${NC}"
    echo ""

    send_telegram "🛡️ EPG v4.0 STARTED

Mode: ${SAFETY_MODE^^} | Modules: 14
Response Time: ${REALTIME_LOGIN_INTERVAL}s
Owner IPs: ${MY_CURRENT_IPS}
Lock: $(command -v flock &>/dev/null && echo 'flock' || echo 'mkdir')
FileWatch: $(command -v inotifywait &>/dev/null && echo 'inotifywait' || echo 'poll')
PAM Hooks: Active
Trusted: ${TRUSTED_USER}" "LOW"

    # Wait for children — use a loop so signals can interrupt
    while [[ "$RUNNING" == "true" ]]; do
        # Wait with timeout so Ctrl+C works
        wait -n 2>/dev/null || true
        # Check if we still have living children
        local alive=0
        for cpid in "${CHILD_PIDS[@]}"; do
            kill -0 "$cpid" 2>/dev/null && alive=$((alive + 1))
        done
        if [[ "$alive" -eq 0 ]]; then
            log_event "WARN" "All child processes died, restarting in 5s..."
            sleep 5
            break
        fi
    done
}

stop_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local dp
        dp=$(cat "$PID_FILE" 2>/dev/null)

        if [[ -n "$dp" ]]; then
            local pgid
            pgid=$(ps -o pgid= -p "$dp" 2>/dev/null | tr -d ' ')

            if [[ -n "$pgid" && "$pgid" != "1" ]]; then
                kill -- -"$pgid" 2>/dev/null
                sleep 2
                kill -9 -- -"$pgid" 2>/dev/null
            else
                pkill -P "$dp" 2>/dev/null
                sleep 1
                pkill -9 -P "$dp" 2>/dev/null
                kill "$dp" 2>/dev/null
                kill -9 "$dp" 2>/dev/null
            fi
        fi

        rm -f "$PID_FILE"
        find "$LOCK_DIR" -name "*.lock" -delete 2>/dev/null
        find "$LOCK_DIR" -name "*.lock.d" -type d -exec rm -rf {} + 2>/dev/null

        log_event "INFO" "Daemon stopped"
        send_telegram "EPG STOPPED" "HIGH"
        echo -e "${YELLOW}EndpointGuard stopped.${NC}"
    else
        echo -e "${RED}No running daemon found.${NC}"
    fi
}

show_status() {
    echo ""
    echo -e "  ${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${CYAN}${BOLD}  EndpointGuard v4.0 — Status${NC}"
    echo -e "  ${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "  Mode:    ${BOLD}${SAFETY_MODE^^}${NC}"
    echo -e "  Lock:    $(command -v flock &>/dev/null && echo "${GREEN}flock${NC}" || echo "${YELLOW}mkdir${NC}")"
    echo -e "  inotify: $(command -v inotifywait &>/dev/null && echo "${GREEN}yes${NC}" || echo "${YELLOW}no (polling)${NC}")"

    if [[ -f "$PID_FILE" ]]; then
        local p
        p=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
            local ch
            ch=$(pgrep -P "$p" 2>/dev/null | wc -l)
            echo -e "  Status:  ${GREEN}RUNNING${NC} (PID: ${p}, children: ${ch})"
            echo -e "  Load:    $(cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}')"
        else
            echo -e "  Status:  ${RED}STOPPED${NC} (stale PID)"
        fi
    else
        echo -e "  Status:  ${RED}STOPPED${NC}"
    fi

    echo -e "  User:    ${CYAN}${TRUSTED_USER}${NC}"

    if [[ -f "$BLOCKED_FILE" ]] && [[ -s "$BLOCKED_FILE" ]]; then
        local bc
        bc=$(wc -l < "$BLOCKED_FILE")
        echo -e "  Blocked: ${RED}${bc}${NC}"
        while IFS='|' read -r ip ts reason; do
            [[ -z "$ip" ]] && continue
            echo -e "    ${RED}✗${NC} ${ip} (${reason})"
        done < "$BLOCKED_FILE"
    else
        echo -e "  Blocked: ${GREEN}0${NC}"
    fi

    if [[ -f "$JAIL_REGISTRY" ]] && [[ -s "$JAIL_REGISTRY" ]]; then
        echo -e "  Jailed:  ${RED}$(wc -l < "$JAIL_REGISTRY")${NC}"
    fi

    if [[ -f "$LOG_FILE" ]]; then
        echo -e "  Events:  $(wc -l < "$LOG_FILE") (${RED}$(grep -c CRITICAL "$LOG_FILE" 2>/dev/null || echo 0) crit${NC})"
    fi
    echo ""
}

view_logs() {
    local f="${1:-recent}"
    [[ ! -f "$LOG_FILE" ]] && echo -e "${RED}No logs.${NC}" && return

    echo -e "\n${CYAN}=== Logs ===${NC}\n"
    case "$f" in
        critical) grep "CRITICAL" "$LOG_FILE" 2>/dev/null | tail -50 ;;
        high)     grep -E "(CRITICAL|HIGH)" "$LOG_FILE" 2>/dev/null | tail -50 ;;
        logins)   grep -iE "(LOGIN|session|Accepted|Failed)" "$LOG_FILE" 2>/dev/null | tail -50 ;;
        blocked)  [[ -f "$BLOCKED_FILE" ]] && cat "$BLOCKED_FILE" || echo "None" ;;
        all)      tail -100 "$LOG_FILE" ;;
        *)        tail -50 "$LOG_FILE" ;;
    esac
    echo ""
}

manual_block() {
    local ip="$1"
    [[ -z "$ip" ]] && echo -e "${RED}Usage: $0 block <IP>${NC}" && return
    safe_block_ip "$ip" "manual"
    echo -e "${GREEN}Block requested: ${ip} (mode: ${SAFETY_MODE})${NC}"
}

manual_unblock() {
    local ip="$1"
    [[ -z "$ip" ]] && echo -e "${RED}Usage: $0 unblock <IP>${NC}" && return
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
    sed -i "/${ip}/d" /etc/hosts.deny 2>/dev/null
    sed -i "/${ip}/d" "$BLOCKED_FILE" 2>/dev/null
    echo -e "${GREEN}Unblocked: ${ip}${NC}"
}

test_telegram() {
    [[ "$TELEGRAM_BOT_TOKEN" == "YOUR_BOT_TOKEN_HERE" ]] && \
        echo -e "${RED}Set TELEGRAM_BOT_TOKEN first!${NC}" && return 1

    local r
    r=$(curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=EPG Test ✅ $(date '+%H:%M:%S') $(hostname)" 2>&1)

    echo "$r" | grep -q '"ok":true' && echo -e "${GREEN}Success!${NC}" || \
        { echo -e "${RED}Failed: ${r}${NC}"; return 1; }
}

install_service() {
    [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required.${NC}" && exit 1

    local sp
    sp=$(readlink -f "$0" 2>/dev/null || echo "$0")

    mkdir -p "$INSTALL_DIR"
    cp "$sp" "${INSTALL_DIR}/endpointguard.sh"
    chmod 700 "${INSTALL_DIR}/endpointguard.sh"

    cat > /etc/systemd/system/endpointguard.service << EOF
[Unit]
Description=EndpointGuard Security Daemon
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/endpointguard.sh start
ExecStop=/bin/bash ${INSTALL_DIR}/endpointguard.sh stop
Restart=on-failure
RestartSec=60
KillMode=control-group
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable endpointguard 2>/dev/null
    systemctl start endpointguard 2>/dev/null
    echo -e "${GREEN}Installed! Use: systemctl {start|stop|status} endpointguard${NC}"
}

uninstall_tool() {
    stop_daemon

    [[ -f /etc/ssh/sshd_config.epg_backup ]] && \
        mv /etc/ssh/sshd_config.epg_backup /etc/ssh/sshd_config 2>/dev/null

    systemctl stop endpointguard 2>/dev/null
    systemctl disable endpointguard 2>/dev/null
    rm -f /etc/systemd/system/endpointguard.service 2>/dev/null
    systemctl daemon-reload 2>/dev/null

    [[ -f "$BLOCKED_FILE" ]] && while IFS='|' read -r ip _ _; do
        [[ -z "$ip" ]] && continue
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
        iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
        sed -i "/${ip}/d" /etc/hosts.deny 2>/dev/null
    done < "$BLOCKED_FILE"

    for uh in /home/*/; do
        [[ -f "${uh}.bashrc.epg_bak" ]] && {
            local u; u=$(basename "$uh")
            chattr -i "${uh}.bashrc" 2>/dev/null
            mv "${uh}.bashrc.epg_bak" "${uh}.bashrc" 2>/dev/null
            chmod 644 "${uh}.bashrc" 2>/dev/null
            passwd -u "$u" 2>/dev/null
            usermod -s /bin/bash "$u" 2>/dev/null
            chage -E -1 "$u" 2>/dev/null
        }
    done

    [[ -f /etc/ssh/sshd_config ]] && sed -i '/^DenyUsers/d' /etc/ssh/sshd_config 2>/dev/null
    systemctl reload sshd 2>/dev/null

    rm -f /tmp/.epg_hp.log /etc/ssh/banner 2>/dev/null

    uninstall_pam_hooks

    rm -rf "$INSTALL_DIR" 2>/dev/null

    echo -e "${GREEN}Uninstalled.${NC}"
}

print_help() {
    show_banner
    echo -e "  ${WHITE}${BOLD}USAGE${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "    ${CYAN}$0${NC} ${WHITE}<command>${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}COMMANDS${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "    ${GREEN}start${NC}         Start the daemon"
    echo -e "    ${GREEN}stop${NC}          Stop the daemon"
    echo -e "    ${GREEN}restart${NC}       Restart the daemon"
    echo -e "    ${GREEN}status${NC}        Show current status"
    echo -e "    ${GREEN}test${NC}          Test Telegram connection"
    echo -e "    ${GREEN}logs${NC} ${DIM}[filter]${NC}  View logs ${DIM}(critical/high/logins/blocked/all)${NC}"
    echo -e "    ${GREEN}block${NC} ${DIM}<IP>${NC}    Block an IP address"
    echo -e "    ${GREEN}unblock${NC} ${DIM}<IP>${NC}  Unblock an IP address"
    echo -e "    ${GREEN}install${NC}       Install as systemd service"
    echo -e "    ${GREEN}uninstall${NC}     Remove completely"
    echo ""
    echo -e "  ${DIM}Current mode: ${NC}${BOLD}${SAFETY_MODE^^}${NC} ${DIM}(edit SAFETY_MODE in script)${NC}"
    echo ""
}

main() {
    local cmd="${1:-help}"

    case "$cmd" in
        start)    [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; start_daemon ;;
        stop)     [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; stop_daemon ;;
        restart)  [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; stop_daemon; sleep 3; start_daemon ;;
        status)   show_status ;;
        test)     test_telegram ;;
        logs)     view_logs "$2" ;;
        block)    [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; manual_block "$2" ;;
        unblock)  [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; manual_unblock "$2" ;;
        install)  [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; install_service ;;
        uninstall) [[ "$(id -u)" -ne 0 ]] && echo -e "${RED}Root required${NC}" && exit 1; uninstall_tool ;;
        help|--help|-h) print_help ;;
        *)        echo -e "${RED}Unknown: ${cmd}${NC}"; print_help; exit 1 ;;
    esac
}

main "$@"
