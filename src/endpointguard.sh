#!/bin/bash
###############################################################################
#
#  ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗
#  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝
#  █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║
#  ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║
#  ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║
#  ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝
#
#   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
#  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
#  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
#  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
#  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
#   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
#
#  EndpointGuard v5.0 — Linux Sentinel
#  Menu-driven, zero-argument, advanced reverse-shell & C2 hunter
#
#  Author:    Prince Gaur (Mr-N1ck)
#  GitHub:    https://github.com/Mr-N1ck/EndpointGuard
#  License:   MIT
#
#  WHAT'S NEW IN v5.0
#    • Pure interactive TUI — no command-line arguments needed
#    • First-run setup wizard — no manual config editing
#    • /proc/<pid>/fd socket-walk reverse-shell hunter
#        Detects bash, sh, dash, zsh, busybox, python, perl, ruby, php, lua,
#        node, awk, socat, ncat, openssl s_client reverse shells regardless
#        of how they were invoked
#    • C2 channel detector
#        Discord webhooks, Telegram bots, IRC, ngrok, serveo, pastebin
#        clones, anonfile, transfer.sh, 0x0.st, paste.ee, dpaste, etc.
#    • Beaconing pattern detector — catches periodic call-home traffic
#    • Kernel-level socket kill (ss -K) + conntrack flush
#        Severs the TCP/UDP session at the kernel — attacker drops instantly
#    • Quarantine system — malicious files moved, locked, hashed
#    • Deep persistence sweep — cron, systemd, .bashrc, .profile,
#        /etc/profile.d, authorized_keys, rc.local, at, anacron, ld.so.preload
#    • Watchdog — auto-restarts crashed modules
#    • Self-healing PAM hook — reinstalls if attacker removes
#    • Audit hook (optional) for kernel-level execve visibility
#    • All v4 features retained (PAM, honeypot, file integrity, etc.)
#
###############################################################################

set -o pipefail
umask 077

# ========================== VERSION ==========================
EPG_VERSION="5.0.0"

# ========================== INSTALL PATHS ==========================
INSTALL_DIR="/opt/.epg"
CONFIG_FILE="${INSTALL_DIR}/config.conf"
LOG_FILE="${INSTALL_DIR}/epg.log"
ALERT_LOG="${INSTALL_DIR}/alerts.log"
BLOCKED_FILE="${INSTALL_DIR}/blocked.list"
SESSION_DB="${INSTALL_DIR}/sessions.db"
PID_FILE="${INSTALL_DIR}/daemon.pid"
HONEYPOT_DIR="${INSTALL_DIR}/honeypot"
QUARANTINE_DIR="${INSTALL_DIR}/quarantine"
ALERT_TRACKER="${INSTALL_DIR}/alerts"
LOCK_DIR="${INSTALL_DIR}/locks"
BASELINE_DIR="${INSTALL_DIR}/baselines"
JAIL_REGISTRY="${INSTALL_DIR}/jailed_users.list"
BEACON_DB="${INSTALL_DIR}/beacons.db"
KILLED_CONNS="${INSTALL_DIR}/killed_conns.log"

# ========================== DEFAULT CONFIG ==========================
# (overridden by ${CONFIG_FILE} if it exists)
SAFETY_MODE="active"
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
TRUSTED_USER=""
ADDITIONAL_TRUSTED_USERS=""
TRUSTED_IPS=""
TRUSTED_NETWORKS=""
ENABLE_AUDITD_HOOK="auto"   # auto | yes | no
ENABLE_OUTBOUND_BLOCK="yes" # block known-bad C2 destinations

# ========================== TUNABLES ==========================
MAX_FAILED_LOGINS=10
SUSPICIOUS_CMD_THRESHOLD=8
LOCKOUT_DURATION=3600
PERMANENT_BAN_STRIKES=5

SCAN_INTERVAL_LIGHT=15
SCAN_INTERVAL_MEDIUM=60
SCAN_INTERVAL_HEAVY=180
SCAN_INTERVAL_VERY_HEAVY=600

REALTIME_LOGIN_INTERVAL=2
REVSHELL_SCAN_INTERVAL=3       # /proc fd hunter — fast
C2_SCAN_INTERVAL=10
BEACON_WINDOW=900              # seconds — analyse beaconing within this window
BEACON_MIN_HITS=4              # number of similar connections to flag

# Connection auditor (v5.1)
CONN_AUDIT_INTERVAL=5          # seconds between full netstat sweeps
CONN_RISK_THRESHOLD=60         # 0–100, flag at this score
CONN_AUDIT_USE_NETSTAT=true    # also cross-check with netstat if available

ALERT_COOLDOWN_SSH=120
ALERT_COOLDOWN_CMD=30
ALERT_COOLDOWN_FILE=600
ALERT_COOLDOWN_NET=30
ALERT_COOLDOWN_PERSIST=600
ALERT_COOLDOWN_OTHER=300

# ========================== COLORS ==========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ========================== GLOBAL STATE ==========================
CHILD_PIDS=()
RUNNING=true
MY_CURRENT_IPS=""
DAEMON_MODE=false   # true only when running as the daemon

# ========================== KNOWN C2 / EXFIL INDICATORS ==========================
# These are domains/hosts commonly abused by malware for C2 and exfiltration.
# Legitimate uses exist — that's why we alert and require active mode to block.
C2_DOMAINS=(
    "discord.com/api/webhooks"
    "discordapp.com/api/webhooks"
    "ptb.discord.com/api/webhooks"
    "canary.discord.com/api/webhooks"
    "api.telegram.org/bot"
    "t.me"
    "telegra.ph"
    "ngrok.io"
    "ngrok-free.app"
    "ngrok.app"
    "serveo.net"
    "localtunnel.me"
    "loca.lt"
    "trycloudflare.com"
    "pastebin.com/raw"
    "paste.ee/r/"
    "hastebin.com/raw"
    "dpaste.com/raw"
    "rentry.co"
    "rentry.org"
    "transfer.sh"
    "0x0.st"
    "anonfiles.com"
    "bashupload.com"
    "termbin.com"
    "ix.io"
    "envs.sh"
    "filebin.net"
    "file.io"
    "gofile.io"
    "anonfile.la"
    "bin.disroot.org"
    "free.beeceptor.com"
    "webhook.site"
    "requestcatcher.com"
    "pipedream.net"
    "interact.sh"
    "oast.fun"
    "burpcollaborator.net"
    "canarytokens.com"
)

# Suspicious shell-style payload patterns — deeper than v4
TRULY_MALICIOUS_PATTERNS=(
    "bash -i >& /dev/tcp/"
    "bash -i >& /dev/udp/"
    "sh -i >& /dev/tcp/"
    "sh -i >& /dev/udp/"
    "/dev/tcp/"
    "/dev/udp/"
    "0<&196;exec 196<>/dev/tcp"
    "exec 5<>/dev/tcp"
    "rm -rf / --no-preserve-root"
    "rm -rf /*"
    "dd if=/dev/zero of=/dev/sd"
    "dd if=/dev/null of=/dev/sd"
    "mkfs.ext4 /dev/sd"
    ":(){ :|:& };:"
    "echo .* | base64 -d | bash"
    "echo .* | base64 -d | sh"
    "wget -O- .* | bash"
    "wget -O- .* | sh"
    "curl .* | bash"
    "curl .* | sh"
    "curl -fsSL .* | bash"
    "curl -fsSL .* | sh"
    "python -c .*socket.*connect.*dup2"
    "python3 -c .*socket.*connect.*dup2"
    "python -c .*pty.spawn"
    "python3 -c .*pty.spawn"
    "perl -e .*socket.*connect.*exec"
    "ruby -rsocket -e .*TCPSocket.*exec"
    "php -r .*fsockopen"
    "lua -e .*socket.connect"
    "node -e .*net.connect"
    "ncat -e /bin/"
    "ncat -e /usr/bin/"
    "nc -e /bin/"
    "nc -e /usr/bin/"
    "socat .* EXEC:"
    "socat .* TCP:"
    "openssl s_client -connect .* -quiet"
    "export HISTSIZE=0"
    "export HISTFILESIZE=0"
    "unset HISTFILE"
    "history -c"
    "history -w"
    "chattr +i /etc/passwd"
    "chattr +i /etc/shadow"
    "echo .* >> ~/.ssh/authorized_keys"
    "echo .* >> /root/.ssh/authorized_keys"
)

# Programs that legitimately spawn shells with sockets (allow-list — they
# never read interactive shells back from the network).
SHELL_SOCKET_ALLOWLIST=(
    sshd ssh chrome chromium firefox brave thunderbird
    code code-oss codium electron docker dockerd containerd
    redis-server postgres mysqld mariadbd mongod
    apache2 httpd nginx haproxy
    systemd-resolved systemd-networkd systemd-timesyncd
    NetworkManager wpa_supplicant dhclient avahi-daemon
    snapd dbus-daemon polkitd accounts-daemon
)

WHITELISTED_PROGRAMS=(
    nmap masscan hydra john hashcat sqlmap msfconsole msfvenom
    metasploit burpsuite nikto dirb dirbuster gobuster ffuf wfuzz
    aircrack airmon airodump reaver wpscan enum4linux smbclient
    rpcclient crackmapexec impacket responder bloodhound
    linpeas linenum pspy chisel proxychains
    tcpdump wireshark tshark ettercap bettercap
    beef setoolkit searchsploit exploitdb
    python python3 ruby perl php gcc gdb strace ltrace objdump
    radare2 r2 ghidra volatility autopsy foremost binwalk
    steghide exiftool ssh scp rsync
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
    fdisk parted lsblk blkid
    dmesg lspci lsusb lscpu
    reboot shutdown poweroff halt init
)

WHITELISTED_KMODS=(
    i915 xe drm drm_kms_helper drm_exec drm_gpuvm drm_suballoc_helper
    drm_display_helper drm_buddy drm_ttm_helper drm_client_lib ttm gpu_sched
    nvidia nvidia_modeset nvidia_uvm nvidia_drm
    amdgpu radeon nouveau
    i2c_hid i2c_hid_acpi i2c_algo_bit
    video backlight
    snd snd_hda_intel snd_hda_codec snd_hda_codec_generic snd_hda_codec_realtek
    snd_hda_codec_realtek_lib snd_hda_codec_alc269 snd_hda_codec_hdmi
    snd_hda_core snd_hwdep snd_pcm snd_pcm_dmaengine snd_timer
    snd_seq snd_seq_device snd_seq_midi snd_seq_midi_event snd_rawmidi
    snd_soc_core snd_soc_avs snd_soc_sdca snd_compress
    snd_sof snd_sof_utils snd_sof_intel_hda_common snd_sof_intel_hda_generic
    snd_sof_intel_hda snd_sof_pci snd_sof_pci_intel_tgl
    snd_sof_pci_intel_mtl snd_sof_pci_intel_lnl
    soundwire_intel soundwire_generic_allocation soundwire_cadence
    soundwire_bus soundwire_intel_init
    snd_soc_hda_codec snd_soc_hdac_hda snd_soc_acpi snd_soc_acpi_intel_match
    aesni_intel aes_x86_64 crypto_simd cryptd ghash_clmulni_intel
    polyval_clmulni polyval_generic ccm gcm cbc cmac
    algif_hash algif_skcipher af_alg
    pkcs8_key_parser pkcs7_message x509_cert_parser
    evdev hid hid_generic hid_multitouch hid_asus hid_logitech
    hid_logitech_dj hid_logitech_hidpp hid_apple hid_cherry
    hid_microsoft hid_lenovo hid_magicmouse
    usbhid usbcore usb_common xhci_hcd xhci_pci ehci_hcd ehci_pci
    ohci_hcd ohci_pci uhci_hcd usb_storage uas
    btusb btrtl btintel btbcm btmtk bluetooth bnep rfcomm
    iwlwifi iwlmvm iwl7000 iwl8000 iwlax iwl_drv
    rtw89_core rtw89_pci rtw89_8852ae rtw89_8852be rtw89_8852ce
    rtw88_core rtw88_pci rtw88_8822be rtw88_8822ce
    ath11k ath11k_pci ath10k_core ath10k_pci ath9k
    mt76_core mt7921_common mt7921e mt7921s
    cfg80211 mac80211 rfkill lib80211
    r8169 r8152 e1000 e1000e igb igc ixgbe i40e ice
    realtek atlantic
    nf_tables nfnetlink nf_conntrack nf_nat nf_defrag_ipv4 nf_defrag_ipv6
    nft_chain_nat nft_compat nft_counter nft_ct nft_fib
    nft_fib_inet nft_fib_ipv4 nft_fib_ipv6
    nft_limit nft_log nft_masq nft_nat nft_objref nft_quota
    nft_redir nft_reject nft_reject_inet nft_reject_ipv4 nft_reject_ipv6
    ip_tables ip6_tables iptable_filter iptable_nat iptable_mangle
    ip6table_filter ip6table_nat
    x_tables xt_conntrack xt_nat xt_tcpudp xt_addrtype xt_comment
    xt_multiport xt_state xt_mark xt_MASQUERADE xt_LOG xt_limit
    xt_connmark xt_set xt_recent
    br_netfilter bridge veth macvlan ipvlan tun tap
    bonding team 8021q
    fuse overlay overlayfs squashfs isofs udf
    nfs nfsd nfsv3 nfsv4 lockd sunrpc grace
    ext4 mbcache jbd2 btrfs xfs fat vfat msdos ntfs ntfs3
    dm_mod dm_crypt dm_thin_pool dm_cache dm_mirror dm_snapshot
    raid0 raid1 raid456 raid10 md_mod
    ahci libahci libata sd_mod sr_mod sg scsi_mod
    nvme nvme_core nvme_common
    kvm kvm_intel kvm_amd
    vboxdrv vboxnetflt vboxnetadp vboxpci
    vmw_vmci vmw_balloon vmxnet3 vmw_pvscsi
    virtio virtio_pci virtio_net virtio_blk virtio_scsi virtio_ring
    vhost vhost_net vhost_scsi
    nbd loop
    acpi_cpufreq intel_rapl_msr intel_rapl_common intel_powerclamp
    intel_cstate intel_uncore processor_thermal_device
    processor_thermal_mbox processor_thermal_rfim
    int340x_thermal_zone int3400_thermal int3403_thermal
    intel_pch_thermal intel_soc_dts_iosf
    acpi_pad acpi_tad acpi_thermal_rel
    thinkpad_acpi asus_wmi asus_nb_wmi platform_profile
    wmi wmi_bmof mxm_wmi dell_wmi dell_smbios
    battery ac thermal thermal_sys
    binfmt_misc efi_pstore configfs
    crc32_pclmul crc32c_intel crct10dif_pclmul
    lpc_ich i2c_i801 i2c_smbus i2c_piix4
    pinctrl_icelake pinctrl_tigerlake pinctrl_alderlake
    pinctrl_meteorlake pinctrl_lunarlake
    mei mei_me mei_hdcp mei_pxp
    idma64 pwm_lpss pwm_lpss_platform
    intel_lpss intel_lpss_pci
    tpm tpm_tis tpm_tis_core tpm_crb tpm_tis_spi
    thunderbolt typec ucsi ucsi_acpi
    serio atkbd libps2 psmouse
    leds_asus ledtrig_audio
    parport parport_pc ppdev lp
    pcspkr snd_pcsp
    zstd zstd_compress zstd_decompress lz4 lz4_compress lzo lzo_rle
    cec drm_privacy_screen
    integrity ima evm
    apparmor security_apparmor tomoyo selinux landlock yama
)

SENSITIVE_FILES=(
    "/etc/passwd" "/etc/shadow" "/etc/sudoers"
    "/etc/ssh/sshd_config" "/etc/crontab"
    "/etc/hosts.allow" "/etc/hosts.deny"
    "/etc/ld.so.preload" "/etc/pam.d/sshd"
    "/etc/pam.d/login" "/etc/pam.d/su"
    "/etc/profile" "/etc/bash.bashrc"
    "/root/.ssh/authorized_keys"
    "/root/.bashrc" "/root/.profile"
)


# ========================== UTILS ==========================

epg_die() { echo -e "${RED}$*${NC}" >&2; exit 1; }
epg_info() { echo -e "${CYAN}$*${NC}"; }
epg_ok()   { echo -e "${GREEN}$*${NC}"; }
epg_warn() { echo -e "${YELLOW}$*${NC}"; }
epg_err()  { echo -e "${RED}$*${NC}"; }

require_root() {
    [[ "$(id -u)" -ne 0 ]] && epg_die "This action requires root. Use: sudo bash $0"
}

# Atomic init of state directories — never logs unless asked
init_directories_silent() {
    mkdir -p "$INSTALL_DIR" "$LOCK_DIR" "$ALERT_TRACKER" \
             "$BASELINE_DIR" "$HONEYPOT_DIR" "$QUARANTINE_DIR" 2>/dev/null
    touch "$LOG_FILE" "$ALERT_LOG" "$BLOCKED_FILE" "$SESSION_DB" \
          "$JAIL_REGISTRY" "$BEACON_DB" "$KILLED_CONNS" 2>/dev/null
    chmod 700 "$INSTALL_DIR" "$QUARANTINE_DIR" 2>/dev/null
    chmod 600 "$LOG_FILE" "$ALERT_LOG" "$BLOCKED_FILE" "$SESSION_DB" \
              "$JAIL_REGISTRY" "$BEACON_DB" "$KILLED_CONNS" 2>/dev/null
}

# Write to log only when daemon is running. CLI invocations stay silent.
log_event() {
    [[ "$DAEMON_MODE" != "true" ]] && return 0
    local level="$1" message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
    case "$level" in
        CRITICAL|HIGH)
            echo "[$timestamp] [$level] $message" >> "$ALERT_LOG" 2>/dev/null ;;
    esac
    local lines
    lines=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "${lines:-0}" -gt 50000 ]]; then
        with_lock "log_rotate" _rotate_log_internal
    fi
}
_rotate_log_internal() {
    tail -25000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null
    mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
}

# ----- Locking (flock if available, mkdir fallback) -----
FLOCK_AVAILABLE=false
command -v flock &>/dev/null && FLOCK_AVAILABLE=true

with_lock() {
    local lockname="$1"; shift
    local lockfile="${LOCK_DIR}/${lockname}.lock"
    if [[ "$FLOCK_AVAILABLE" == "true" ]]; then
        ( flock -w 10 200 || { log_event "WARN" "Lock timeout: ${lockname}"; return 1; }
          "$@" ) 200>"$lockfile"
    else
        local attempt=0
        while ! mkdir "${lockfile}.d" 2>/dev/null; do
            attempt=$((attempt + 1))
            if [[ "$attempt" -ge 10 ]]; then
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

# ----- Config -----
load_config() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
# EndpointGuard v${EPG_VERSION} — Configuration
# Auto-generated by setup wizard. Edit at your own risk.
SAFETY_MODE="${SAFETY_MODE}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"
TRUSTED_USER="${TRUSTED_USER}"
ADDITIONAL_TRUSTED_USERS="${ADDITIONAL_TRUSTED_USERS}"
TRUSTED_IPS="${TRUSTED_IPS}"
TRUSTED_NETWORKS="${TRUSTED_NETWORKS}"
ENABLE_AUDITD_HOOK="${ENABLE_AUDITD_HOOK}"
ENABLE_OUTBOUND_BLOCK="${ENABLE_OUTBOUND_BLOCK}"
EOF
    chmod 600 "$CONFIG_FILE"
}

# ----- Process tracking & cleanup -----
track_child() {
    local pid=$1
    CHILD_PIDS+=("$pid")
    if [[ ${#CHILD_PIDS[@]} -gt 200 ]]; then
        local new_pids=()
        for p in "${CHILD_PIDS[@]}"; do
            kill -0 "$p" 2>/dev/null && new_pids+=("$p")
        done
        CHILD_PIDS=("${new_pids[@]}")
    fi
}

daemon_cleanup() {
    [[ "$DAEMON_MODE" != "true" ]] && exit 0
    RUNNING=false
    log_event "INFO" "Shutting down EndpointGuard"
    local my_pgid
    my_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
    if [[ -n "$my_pgid" && "$my_pgid" != "1" ]]; then
        kill -- -"$my_pgid" 2>/dev/null
    fi
    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
        pkill -P "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    local orphans
    orphans=$(pgrep -P "$$" 2>/dev/null || true)
    [[ -n "$orphans" ]] && echo "$orphans" | xargs kill -9 2>/dev/null
    rm -f "$PID_FILE"
    find "$LOCK_DIR" -name "*.lock" -delete 2>/dev/null
    log_event "INFO" "EndpointGuard stopped cleanly"
    exit 0
}

# ----- Telegram -----
send_telegram() {
    local message="$1" urgency="${2:-LOW}"
    [[ -z "$TELEGRAM_BOT_TOKEN" || "$TELEGRAM_BOT_TOKEN" == "YOUR_BOT_TOKEN" ]] && return
    local emoji
    case "$urgency" in
        LOW) emoji="ℹ️" ;; MEDIUM) emoji="⚠️" ;;
        HIGH) emoji="🚨" ;; CRITICAL) emoji="🔴" ;;
        *) emoji="📌" ;;
    esac
    local mode_label
    mode_label="${SAFETY_MODE^^}"
    local full_message="${emoji} EPG v${EPG_VERSION} [${mode_label}]

Host: $(hostname 2>/dev/null)
Time: $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
Level: ${urgency}

$(echo "$message" | head -c 2500)"
    (curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${full_message}" \
        -d "disable_web_page_preview=true" \
        > /dev/null 2>&1) &
    track_child $!
}

check_alert_cooldown() {
    local alert_key="$1" cooldown_seconds="$2"
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

send_smart_alert() {
    local key="$1" cooldown="$2" message="$3" urgency="${4:-LOW}"
    if check_alert_cooldown "$key" "$cooldown"; then
        send_telegram "$message" "$urgency"
        log_event "$urgency" "ALERT: ${key}"
    fi
}

# ========================== TRUST / SAFETY ==========================
is_trusted_ip() {
    local ip="$1"
    [[ -z "$ip" || "$ip" == "unknown" ]] && return 1
    [[ "$ip" == "local" || "$ip" == ":0" || "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && return 0
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
    # "Account-level protection" — don't lock the account, don't kill ALL of
    # the user's sessions. Used by safe_lock_account / safe_kill_sessions.
    local user="$1"
    [[ -z "$user" ]] && return 0
    is_trusted_user "$user" && return 0
    is_system_user "$user" && return 0
    [[ "$user" == "root" ]] && return 0
    return 1
}

# Process-level protection — much narrower than account protection.
# Used by safe_kill_process. We DO kill malicious processes even when they
# run as root, because attackers commonly land as root via SUID payloads,
# kernel exploits, or compromised services. The trusted_user is still
# protected because killing their bash would lock them out.
is_process_protected_user() {
    local user="$1"
    [[ -z "$user" ]] && return 0
    is_trusted_user "$user" && return 0
    return 1
}
is_own_process() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0
    [[ "$pid" == "$$" ]] && return 0
    local ppid
    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    [[ "$ppid" == "$$" ]] && return 0
    local pgid my_pgid
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
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
is_whitelisted_kmod() {
    local mod_name="$1"
    [[ -z "$mod_name" ]] && return 0
    for wk in "${WHITELISTED_KMODS[@]}"; do
        [[ "$mod_name" == "$wk" ]] && return 0
    done
    return 1
}
is_shell_socket_allowed() {
    local exe="$1"
    [[ -z "$exe" ]] && return 1
    local base
    base=$(basename "$exe")
    for ok in "${SHELL_SOCKET_ALLOWLIST[@]}"; do
        [[ "$base" == "$ok" ]] && return 0
    done
    return 1
}

detect_my_ips() {
    local ips=""
    local iface_ips
    iface_ips=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' || \
                ifconfig 2>/dev/null | grep -oP 'inet (addr:)?\K[0-9.]+' || true)
    [[ -n "$iface_ips" ]] && ips="$iface_ips"
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        ips="$ips $(echo "$SSH_CLIENT" | awk '{print $1}')"
    fi
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        ips="$ips $(echo "$SSH_CONNECTION" | awk '{print $1}')"
    fi
    local who_ips
    who_ips=$(who 2>/dev/null | grep "^${TRUSTED_USER} " | awk '{print $5}' | \
              tr -d '()' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    [[ -n "$who_ips" ]] && ips="$ips $who_ips"
    ips="$ips 127.0.0.1 ::1 $TRUSTED_IPS"
    MY_CURRENT_IPS=$(echo "$ips" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    log_event "INFO" "Owner IPs detected: ${MY_CURRENT_IPS}"
}
is_my_own_ip() {
    # Strict check: ONLY local interface IPs and explicitly-configured
    # TRUSTED_IPS qualify as "my own". TRUSTED_NETWORKS is intentionally
    # NOT consulted here — a reverse shell connecting from an attacker on
    # the same LAN must still be detected. Network-level trust is only
    # used at login time (where SSH/PAM logs need to know the source).
    local ip="$1"
    [[ -z "$ip" || "$ip" == "local" || "$ip" == ":0" || "$ip" == "unknown" ]] && return 0
    [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && return 0
    for my_ip in $MY_CURRENT_IPS; do
        [[ "$ip" == "$my_ip" ]] && return 0
    done
    for tip in $TRUSTED_IPS; do
        [[ "$ip" == "$tip" ]] && return 0
    done
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

# ========================== ADAPTIVE SCANNING ==========================
get_system_load() {
    local load
    load=$(awk '{print int($1)}' /proc/loadavg 2>/dev/null || echo 0)
    echo "${load:-0}"
}
get_cpu_count() {
    nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1
}
get_adaptive_interval() {
    local base_interval="$1" load cpus
    load=$(get_system_load)
    cpus=$(get_cpu_count)
    if [[ "$load" -gt $((cpus * 3)) ]]; then echo $((base_interval * 4))
    elif [[ "$load" -gt $((cpus * 2)) ]]; then echo $((base_interval * 2))
    else echo "$base_interval"; fi
}
can_heavy_scan() {
    local load cpus
    load=$(get_system_load)
    cpus=$(get_cpu_count)
    [[ "$load" -le $((cpus * 2)) ]]
}

# ========================== MODE GATES ==========================
can_take_action() { [[ "$SAFETY_MODE" == "active" ]]; }
can_block_ip()    { [[ "$SAFETY_MODE" == "active" || "$SAFETY_MODE" == "moderate" ]]; }


# ========================== KILL / BLOCK / QUARANTINE ==========================

# Kernel-level connection severing — uses ss -K to drop sockets and conntrack
# to flush the connection-tracking entry. Fixes the case where killing the
# user-space process leaves the TCP session in CLOSE_WAIT/ESTABLISHED.
kernel_kill_conn() {
    local remote_ip="$1" remote_port="${2:-}"
    [[ -z "$remote_ip" ]] && return
    is_my_own_ip "$remote_ip" && return

    if command -v ss &>/dev/null; then
        if [[ -n "$remote_port" ]]; then
            ss -K dst "$remote_ip" dport = ":${remote_port}" 2>/dev/null
        fi
        ss -K dst "$remote_ip" 2>/dev/null
    fi
    if command -v conntrack &>/dev/null; then
        conntrack -D -d "$remote_ip" 2>/dev/null
        conntrack -D -s "$remote_ip" 2>/dev/null
    fi
    echo "$(date +%s) ${remote_ip}:${remote_port:-?}" >> "$KILLED_CONNS" 2>/dev/null
}

safe_kill_process() {
    local pid="$1" user="$2" reason="$3"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would kill PID=${pid} user=${user} (${reason})"
        return
    fi
    is_process_protected_user "$user" && { log_event "WARN" "REFUSED kill on trusted user=${user}"; return; }
    is_own_process "$pid" && return
    log_event "HIGH" "KILLING PID=${pid} user=${user} (${reason})"
    # Kill child processes first then the target — handles forked reverse shells
    pkill -9 -P "$pid" 2>/dev/null
    kill -9 "$pid" 2>/dev/null
}

quarantine_file() {
    local src="$1" reason="${2:-malicious}"
    [[ -z "$src" || ! -f "$src" ]] && return
    # Refuse to quarantine system binaries
    case "$src" in
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*|/usr/lib/*) return ;;
    esac
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would quarantine ${src} (${reason})"
        return
    fi
    local hash ts dest
    hash=$(sha256sum "$src" 2>/dev/null | awk '{print $1}')
    ts=$(date +%Y%m%d-%H%M%S)
    dest="${QUARANTINE_DIR}/${ts}_$(basename "$src")_${hash:0:12}"
    chattr -i "$src" 2>/dev/null
    mv -f "$src" "$dest" 2>/dev/null && {
        chmod 000 "$dest" 2>/dev/null
        echo "$(date +%s)|${src}|${dest}|${hash}|${reason}" \
            >> "${QUARANTINE_DIR}/quarantine.log" 2>/dev/null
        log_event "HIGH" "QUARANTINED: ${src} → ${dest} (${reason})"
    }
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
    iptables -I FORWARD -s "$ip" -j DROP 2>/dev/null
    iptables -I FORWARD -d "$ip" -j DROP 2>/dev/null
    grep -q "^ALL: ${ip}$" /etc/hosts.deny 2>/dev/null || \
        echo "ALL: ${ip}" >> /etc/hosts.deny 2>/dev/null
    echo "${ip}|$(date +%s)|${reason}" >> "$BLOCKED_FILE" 2>/dev/null
    # Sever any live sockets to/from this IP
    kernel_kill_conn "$ip"
    local strikes
    strikes=$(grep -c "^${ip}|" "$BLOCKED_FILE" 2>/dev/null || echo 0)
    log_event "HIGH" "BLOCKED: ${ip} (${reason}) strike=${strikes}/${PERMANENT_BAN_STRIKES}"
    if [[ "$strikes" -lt "$PERMANENT_BAN_STRIKES" ]]; then
        ( sleep "$LOCKOUT_DURATION"
          iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
          iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
          iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null
          iptables -D FORWARD -d "$ip" -j DROP 2>/dev/null
          sed -i "/^ALL: ${ip}$/d" /etc/hosts.deny 2>/dev/null
          log_event "INFO" "Unblocked (expired): ${ip}" ) &
        track_child $!
    fi
}

safe_kill_sessions() {
    local user="$1"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would kill sessions: ${user}"; return
    fi
    is_protected_user "$user" && return
    log_event "HIGH" "Killing sessions: ${user}"
    pkill -9 -u "$user" 2>/dev/null
}

safe_lock_account() {
    local user="$1"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would lock: ${user}"; return
    fi
    is_protected_user "$user" && return
    log_event "HIGH" "Locking: ${user}"
    passwd -l "$user" 2>/dev/null
    usermod -s /sbin/nologin "$user" 2>/dev/null
    chage -E 0 "$user" 2>/dev/null
    [[ -f /etc/ssh/sshd_config ]] && with_lock "sshd_config" _add_deny_user "$user"
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

# ========================== HONEYPOT ==========================
setup_honeypot_jail() {
    log_event "INFO" "Setting up honeypot"
    mkdir -p "${HONEYPOT_DIR}"/{bin,etc,home,tmp}
    cat > "${HONEYPOT_DIR}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF
    cat > "${HONEYPOT_DIR}/etc/shadow" <<'EOF'
root:!:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
EOF
    local fake_cmds=(ls cat id whoami uname wget curl sudo ssh find passwd
                     nc ncat python python3 perl bash sh)
    for cmd in "${fake_cmds[@]}"; do
        cat > "${HONEYPOT_DIR}/bin/${cmd}" <<'FAKESCRIPT'
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

register_jail()       { with_lock "jail_registry" _register_jail_internal "$1"; }
unregister_jail()     { with_lock "jail_registry" _unregister_jail_internal "$1"; }
_register_jail_internal()   { grep -q "^${1}$" "$JAIL_REGISTRY" 2>/dev/null || echo "$1" >> "$JAIL_REGISTRY"; }
_unregister_jail_internal() { sed -i "/^${1}$/d" "$JAIL_REGISTRY" 2>/dev/null; }

recover_jailed_users() {
    log_event "INFO" "Checking for crash-orphaned jails"
    if [[ -s "$JAIL_REGISTRY" ]]; then
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
            who 2>/dev/null | grep -q "^${user} " || {
                log_event "INFO" "Restoring orphaned jail: ${user}"
                deactivate_jail_for_user "$user"
            }
        fi
    done
}

activate_jail_for_session() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"
    if ! can_take_action; then
        log_event "INFO" "[MONITOR] Would jail: ${target_user}"; return
    fi
    is_protected_user "$target_user" && return
    local user_home
    user_home=$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)
    [[ -z "$user_home" || "$user_home" == "/" || ! -d "$user_home" ]] && return
    [[ "$user_home" == "$HOME" ]] && return
    log_event "HIGH" "Jailing: ${target_user} ip=${target_ip}"
    register_jail "$target_user"
    if [[ -f "${user_home}/.bashrc" && ! -f "${user_home}/.bashrc.epg_bak" ]]; then
        cp -p "${user_home}/.bashrc" "${user_home}/.bashrc.epg_bak" 2>/dev/null
    fi
    cat > "${user_home}/.bashrc" <<JAILRC
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


###############################################################################
# ============== ADVANCED REVERSE-SHELL HUNTER (v5 NEW) =====================
###############################################################################
# Uses /proc/<pid>/fd inspection. This is the canonical way to detect any
# language's reverse shell:
#   - bash -i >& /dev/tcp/IP/PORT 0>&1
#   - python -c "...socket.connect()...dup2()...exec(/bin/sh)..."
#   - perl -e "...socket...exec..."
#   - ruby/php/lua/node/awk variations
#   - socat/ncat/nc -e
#
# A reverse shell is ANY shell process whose stdin/stdout/stderr are connected
# to a network socket. We don't need to know the language. We just look at fd
# 0/1/2 → if any of them is a socket and the process binary is a shell, it's
# a reverse shell. End of story.
###############################################################################

# Map a socket inode to a remote endpoint via /proc/net/tcp{,6}
inode_to_remote() {
    local inode="$1"
    [[ -z "$inode" ]] && return
    local line
    # Search both IPv4 and IPv6 tcp + udp tables
    for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
        [[ -f "$f" ]] || continue
        line=$(awk -v ino="$inode" '$10 == ino {print; exit}' "$f" 2>/dev/null)
        [[ -n "$line" ]] && break
    done
    [[ -z "$line" ]] && return
    # rem_address is field 3 (hex IP:hex PORT)
    local rem
    rem=$(echo "$line" | awk '{print $3}')
    [[ -z "$rem" ]] && return
    local hex_ip="${rem%:*}"
    local hex_port="${rem#*:}"
    local port=$((16#$hex_port))
    local ip=""
    # IPv4 (length 8) — bytes are reversed
    if [[ ${#hex_ip} -eq 8 ]]; then
        ip=$(printf "%d.%d.%d.%d" \
             "$((16#${hex_ip:6:2}))" "$((16#${hex_ip:4:2}))" \
             "$((16#${hex_ip:2:2}))" "$((16#${hex_ip:0:2}))")
    elif [[ ${#hex_ip} -eq 32 ]]; then
        # IPv6 — collapse to short form (best effort)
        local groups=""
        for ((i=0; i<32; i+=4)); do
            groups+="${hex_ip:i:4}:"
        done
        ip="${groups%:}"
    fi
    echo "${ip}:${port}"
}

# Returns true if file descriptor target is a network socket
fd_is_socket() {
    local fd_path="$1"
    local target
    target=$(readlink "$fd_path" 2>/dev/null)
    [[ "$target" == socket:* ]]
}

# Extract socket inode from a /proc/<pid>/fd/<n> link target like socket:[12345]
fd_socket_inode() {
    local fd_path="$1"
    local target
    target=$(readlink "$fd_path" 2>/dev/null)
    [[ "$target" == socket:* ]] || return
    echo "${target#socket:[}" | tr -d ']'
}

# True if the process is a shell interpreter we care about
proc_is_shell() {
    local exe="$1" comm="$2"
    [[ -z "$exe" && -z "$comm" ]] && return 1
    local base
    base=$(basename "${exe:-$comm}" 2>/dev/null)
    case "$base" in
        bash|sh|dash|zsh|ksh|ash|busybox|tcsh|csh) return 0 ;;
        python|python2|python3|python3.*|python2.*) return 0 ;;
        perl|perl5*) return 0 ;;
        ruby|ruby2*|ruby3*) return 0 ;;
        php|php-cli|php7*|php8*) return 0 ;;
        lua|luajit|lua5*) return 0 ;;
        node|nodejs) return 0 ;;
        awk|gawk|mawk|nawk) return 0 ;;
        socat|ncat|nc|netcat|nc.openbsd|nc.traditional) return 0 ;;
        openssl) return 0 ;;
    esac
    return 1
}

# Check if a given pid looks like an interactive reverse shell
# Returns "PID|USER|EXE|REMOTE" if it's a reverse shell, empty otherwise
inspect_pid_for_revshell() {
    local pid="$1"
    [[ -z "$pid" || ! -d "/proc/$pid" ]] && return
    is_own_process "$pid" && return

    local exe comm user cmdline
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    user=$(stat -c %U "/proc/$pid" 2>/dev/null)
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 400)

    # Skip kernel threads
    [[ -z "$exe" ]] && return

    # Skip allowlisted long-running daemons
    is_shell_socket_allowed "$exe" && return

    # Only inspect shells/interpreters
    proc_is_shell "$exe" "$comm" || return

    # Walk fds 0..255 looking for a socket attached to stdin/stdout/stderr or
    # any duplicate of them
    local fd_dir="/proc/$pid/fd"
    [[ -d "$fd_dir" ]] || return

    local socket_inode=""
    local found_socket_on_stdio=false

    # Check stdio FDs first — most reverse shells dup2 the socket onto 0/1/2
    for fd in 0 1 2; do
        if fd_is_socket "${fd_dir}/${fd}"; then
            socket_inode=$(fd_socket_inode "${fd_dir}/${fd}")
            found_socket_on_stdio=true
            break
        fi
    done

    if [[ "$found_socket_on_stdio" != "true" ]]; then
        # Some payloads (e.g., socat, openssl s_client) keep socket on a higher fd
        # Look for any TCP socket open by a shell process
        for fd_link in "$fd_dir"/*; do
            [[ -L "$fd_link" ]] || continue
            if fd_is_socket "$fd_link"; then
                local fd_num
                fd_num=$(basename "$fd_link")
                # Skip stdio (already handled)
                [[ "$fd_num" =~ ^[0-2]$ ]] && continue
                socket_inode=$(fd_socket_inode "$fd_link")
                # Heuristic: shell with non-stdio socket + interactive flag => suspicious
                if echo "$cmdline" | grep -qE -- '-i\b|--interactive|EXEC:|exec:'; then
                    found_socket_on_stdio=true
                    break
                fi
            fi
        done
    fi

    [[ "$found_socket_on_stdio" != "true" ]] && return
    [[ -z "$socket_inode" ]] && return

    local remote
    remote=$(inode_to_remote "$socket_inode")
    [[ -z "$remote" || "$remote" == ":0" ]] && return
    local rip="${remote%:*}"
    local rport="${remote##*:}"

    # Skip loopback (legitimate inter-process)
    [[ "$rip" == "127.0.0.1" || "$rip" == "0.0.0.0" || -z "$rip" ]] && return

    # Skip our own outbound connections (Telegram API etc)
    is_my_own_ip "$rip" && return

    echo "${pid}|${user}|${exe}|${remote}|${cmdline}"
}

monitor_revshell_proc() {
    log_event "INFO" "Reverse-shell hunter started (/proc/<pid>/fd inspection)"
    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$REVSHELL_SCAN_INTERVAL")
        # Iterate ALL pids — fast: just stat /proc and read a few links
        local pid
        for pid in /proc/[0-9]*; do
            pid=$(basename "$pid")
            local result
            result=$(inspect_pid_for_revshell "$pid")
            [[ -z "$result" ]] && continue

            IFS='|' read -r rs_pid rs_user rs_exe rs_remote rs_cmd <<< "$result"
            local rs_ip="${rs_remote%:*}"
            local rs_port="${rs_remote##*:}"

            log_event "CRITICAL" "REVERSE SHELL DETECTED pid=${rs_pid} user=${rs_user} exe=${rs_exe} remote=${rs_remote}"

            send_smart_alert "revshell_${rs_ip}_${rs_port}" "$ALERT_COOLDOWN_NET" \
                "🔴 REVERSE SHELL DETECTED

PID: ${rs_pid}
User: ${rs_user}
Binary: ${rs_exe}
Remote: ${rs_remote}
Cmd: $(echo "$rs_cmd" | head -c 200)

Action: Killing process + severing connection + blocking IP" "CRITICAL"

            # 1. Kill the process AND its parent chain — payloads often look
            #    like:  bash → bash bash.sh → bash -i (the actual revshell)
            #    Killing only the deepest bash leaves the wrapper alive which
            #    can respawn. Walk up the parent chain.
            local kill_pid="$rs_pid" depth=0
            local seen_pids=""
            while [[ -n "$kill_pid" && "$kill_pid" != "0" && "$kill_pid" != "1" && "$depth" -lt 5 ]]; do
                case " $seen_pids " in *" $kill_pid "*) break ;; esac
                seen_pids="$seen_pids $kill_pid"
                local parent_pid parent_user parent_cmd
                parent_pid=$(ps -o ppid= -p "$kill_pid" 2>/dev/null | tr -d ' ')
                parent_user=$(stat -c %U "/proc/$kill_pid" 2>/dev/null)
                parent_cmd=$(tr '\0' ' ' < "/proc/$kill_pid/cmdline" 2>/dev/null)
                is_own_process "$kill_pid" && break
                case "$parent_cmd" in
                    *systemd*|*init*|*sshd*|*login*|/usr/lib/systemd*) break ;;
                esac
                safe_kill_process "$kill_pid" "$parent_user" "reverse_shell_chain"
                kill_pid="$parent_pid"
                depth=$((depth + 1))
            done

            # 2. Sever the kernel-level connection
            kernel_kill_conn "$rs_ip" "$rs_port"

            # 3. Block the remote IP
            safe_block_ip "$rs_ip" "reverse_shell"

            # 4. Quarantine any payload script the shell was running.
            #    Look at the cmdline AND fuser-list for the rs_pid.
            local script_path
            script_path=$(echo "$rs_cmd" | awk '{for(i=1;i<=NF;i++){if($i ~ /^\//){print $i; exit}}}')
            if [[ -n "$script_path" && -f "$script_path" ]]; then
                case "$script_path" in
                    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib*) ;;
                    *) quarantine_file "$script_path" "revshell_payload" ;;
                esac
            fi
            # Also: any script the rs_pid had open (mmap-ed scripts)
            if [[ -d "/proc/$rs_pid/fd" ]]; then
                for fd_link in /proc/"$rs_pid"/fd/*; do
                    local target
                    target=$(readlink "$fd_link" 2>/dev/null)
                    [[ "$target" == /tmp/* || "$target" == /var/tmp/* || "$target" == /dev/shm/* ]] && \
                        [[ -f "$target" ]] && quarantine_file "$target" "revshell_open_fd"
                done 2>/dev/null
            fi

            # 5. Don't kill ALL sessions of the user — that would lock out a
            #    legit root session. The chain-kill above handles the active
            #    revshell. Trust the threshold/score and avoid collateral.
        done
        sleep "$interval"
    done
}

###############################################################################
# ============== C2 / EXFIL CHANNEL DETECTOR (v5 NEW) =======================
###############################################################################

# Scan command lines + recently modified files for C2 indicators
monitor_c2_channels() {
    log_event "INFO" "C2 channel detector started"
    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$C2_SCAN_INTERVAL")

        # ------ Process-args scan ------
        # Look at every running process's cmdline for C2 indicators
        local pid
        for pid in /proc/[0-9]*; do
            pid=$(basename "$pid")
            [[ ! -f "/proc/$pid/cmdline" ]] && continue
            is_own_process "$pid" && continue

            local cmdline
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
            [[ -z "$cmdline" ]] && continue

            local user exe
            user=$(stat -c %U "/proc/$pid" 2>/dev/null)
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            is_protected_user "$user" && continue
            is_shell_socket_allowed "$exe" && continue
            is_whitelisted_program "$cmdline" && continue

            local indicator=""
            for ind in "${C2_DOMAINS[@]}"; do
                if echo "$cmdline" | grep -qiF "$ind" 2>/dev/null; then
                    indicator="$ind"; break
                fi
            done

            if [[ -n "$indicator" ]]; then
                log_event "CRITICAL" "C2 INDICATOR pid=${pid} user=${user} indicator=${indicator}"
                send_smart_alert "c2_${pid}_${indicator//\//_}" "$ALERT_COOLDOWN_NET" \
                    "🔴 C2 / EXFIL CHANNEL DETECTED

PID: ${pid}
User: ${user}
Binary: ${exe}
Indicator: ${indicator}
Cmd: $(echo "$cmdline" | head -c 250)

Common abuse: Discord webhooks, Telegram bots, ngrok tunnels, paste sites." "CRITICAL"
                safe_kill_process "$pid" "$user" "c2_channel"
                # If cmdline references a script, quarantine it
                local script_path
                script_path=$(echo "$cmdline" | awk '{for(i=1;i<=NF;i++){if($i ~ /^\//){print $i; exit}}}')
                if [[ -n "$script_path" && -f "$script_path" ]]; then
                    case "$script_path" in
                        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) ;;
                        *) quarantine_file "$script_path" "c2_payload" ;;
                    esac
                fi
            fi

            # Also flag any process executing TRULY_MALICIOUS_PATTERNS
            for pattern in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
                if echo "$cmdline" | grep -qiE "$pattern" 2>/dev/null; then
                    log_event "CRITICAL" "MALICIOUS PATTERN pid=${pid} user=${user} pattern=${pattern}"
                    send_smart_alert "mal_${pid}" "$ALERT_COOLDOWN_CMD" \
                        "🔴 MALICIOUS COMMAND PATTERN

PID: ${pid}
User: ${user}
Pattern: ${pattern}
Cmd: $(echo "$cmdline" | head -c 250)" "CRITICAL"
                    safe_kill_process "$pid" "$user" "malicious_pattern"
                    break
                fi
            done
        done

        # ------ Recently-modified file scan (catches dropped scripts) ------
        # Anything written to /tmp, /var/tmp, /dev/shm in the last interval
        # that contains C2 indicators or revshell strings.
        # NOTE: We deliberately exclude /home and /root from this real-time
        # scanner because users keep legitimate scripts there (including the
        # EndpointGuard source!). Persistence-sweep handles user homes.
        if can_heavy_scan; then
            local recent
            recent=$(find /tmp /var/tmp /dev/shm \
                     -maxdepth 4 -type f \
                     -mmin -1 \
                     2>/dev/null | head -100)
            local f
            while IFS= read -r f; do
                [[ -z "$f" || ! -f "$f" ]] && continue
                # Hard-skip our own files and any common safe paths
                case "$f" in
                    "$INSTALL_DIR"/*|"$QUARANTINE_DIR"/*|"$LOG_FILE"*) continue ;;
                    */EndpointGuard/*|*/endpointguard*) continue ;;
                    *.epg_*|*.epg_pre_clean.*) continue ;;
                    /tmp/.X*|/tmp/.ICE-*|/tmp/.font-*|/tmp/dbus-*) continue ;;
                    /tmp/systemd-*|/tmp/snap-*|/tmp/.com.*) continue ;;
                esac
                # Skip files larger than 1 MB (likely not a dropper, and we
                # only sample the first 4 KB anyway).
                local sz
                sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
                [[ "${sz:-0}" -gt 1048576 ]] && continue

                local content
                content=$(head -c 4096 "$f" 2>/dev/null)
                [[ -z "$content" ]] && continue

                # CRITICAL: don't false-positive on detection tools. If the
                # file mentions MULTIPLE C2 indicator strings literally, it's
                # almost certainly a security tool (like EPG itself). A real
                # malicious dropper uses ONE C2 channel.
                local indicator_count=0
                for ind in "${C2_DOMAINS[@]}"; do
                    if echo "$content" | grep -qiF "$ind" 2>/dev/null; then
                        indicator_count=$((indicator_count + 1))
                        [[ "$indicator_count" -ge 5 ]] && break
                    fi
                done
                if [[ "$indicator_count" -ge 5 ]]; then
                    continue   # detection-tool source code
                fi

                local hit=""
                for ind in "${C2_DOMAINS[@]}"; do
                    if echo "$content" | grep -qiF "$ind" 2>/dev/null; then
                        hit="$ind"; break
                    fi
                done
                if [[ -z "$hit" ]]; then
                    # Match the actual revshell SYNTAX, not just substrings.
                    # We require the file to look like an executable script
                    # (shebang or .sh/.py/.pl extension) AND contain one of
                    # the strict patterns below.
                    local is_script=false
                    head -1 "$f" 2>/dev/null | grep -qE '^#!' && is_script=true
                    case "$f" in *.sh|*.py|*.pl|*.rb|*.php) is_script=true ;; esac
                    if [[ "$is_script" == "true" ]]; then
                        # Strict revshell syntax patterns
                        if echo "$content" | grep -qE '/dev/(tcp|udp)/[0-9.]+/' 2>/dev/null; then
                            hit="payload:/dev/tcp"
                        elif echo "$content" | grep -qE 'nc -e |ncat -e |bash -e ' 2>/dev/null; then
                            hit="payload:nc_exec"
                        elif echo "$content" | grep -qE 'socat .* EXEC:' 2>/dev/null; then
                            hit="payload:socat_exec"
                        elif echo "$content" | grep -qE 'python3?[[:space:]]*-c[[:space:]]+["'\'']\s*import (socket|os).*connect.*dup2' 2>/dev/null; then
                            hit="payload:python_revshell"
                        elif echo "$content" | grep -qE 'pty\.spawn\(["'\''/]\w*sh' 2>/dev/null; then
                            hit="payload:pty_spawn"
                        fi
                    fi
                fi
                if [[ -n "$hit" ]]; then
                    log_event "HIGH" "MALICIOUS FILE: ${f} indicator=${hit}"
                    send_smart_alert "file_${f//\//_}" "$ALERT_COOLDOWN_FILE" \
                        "🚨 MALICIOUS FILE DROPPED

Path: ${f}
Indicator: ${hit}
Owner: $(stat -c %U "$f" 2>/dev/null)

Action: Quarantining + killing any process holding it open" "HIGH"

                    # CRITICAL FIX: kill any process that has this file open
                    # OR is running as the file's content (the actual reverse
                    # shell). fuser tells us who's reading the script.
                    if can_take_action; then
                        local holders
                        holders=$(fuser "$f" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$')
                        for hpid in $holders; do
                            local huser
                            huser=$(stat -c %U "/proc/$hpid" 2>/dev/null)
                            log_event "HIGH" "Killing PID $hpid (user=$huser) holding malicious file"
                            safe_kill_process "$hpid" "$huser" "holds_malicious_file"
                        done
                        # Also: any bash/sh/python/etc child processes spawned
                        # from this script — kill them via parent-PID match.
                        # Find every recently-spawned shell whose cmdline mentions
                        # this exact path.
                        local fbase
                        fbase=$(basename "$f")
                        for pid in /proc/[0-9]*; do
                            pid=$(basename "$pid")
                            [[ ! -f "/proc/$pid/cmdline" ]] && continue
                            is_own_process "$pid" && continue
                            local pcmd puser
                            pcmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
                            if echo "$pcmd" | grep -qF "$f" || echo "$pcmd" | grep -qF "$fbase"; then
                                puser=$(stat -c %U "/proc/$pid" 2>/dev/null)
                                log_event "HIGH" "Killing PID $pid running malicious script"
                                safe_kill_process "$pid" "$puser" "running_malicious_file"
                            fi
                        done
                    fi
                    quarantine_file "$f" "dropped_c2_payload"
                fi
            done <<< "$recent"
        fi

        sleep "$interval"
    done
}

###############################################################################
# ============== BEACONING DETECTOR (v5 NEW) ================================
###############################################################################
# Catches malware that calls home periodically (e.g., every 60s).
# Records ESTABLISHED outbound connections and looks for repeated hits to the
# same remote within ${BEACON_WINDOW} seconds.
monitor_beaconing() {
    log_event "INFO" "Beaconing detector started"
    while [[ "$RUNNING" == "true" ]]; do
        sleep 30
        # Snapshot current outbound connections
        local now
        now=$(date +%s)
        local conns
        conns=$(ss -tnp state established 2>/dev/null | tail -n +2 || true)
        local line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local remote pid_field pid
            remote=$(echo "$line" | awk '{print $5}')
            pid_field=$(echo "$line" | grep -oP 'pid=\K\d+' | head -1)
            [[ -z "$remote" || -z "$pid_field" ]] && continue
            pid="$pid_field"
            is_own_process "$pid" && continue
            local rip="${remote%:*}"
            is_my_own_ip "$rip" && continue
            # Ignore well-known public services
            case "$rip" in
                127.*|10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2[0-9].*|172.3[01].*) continue ;;
            esac
            local user exe
            user=$(stat -c %U "/proc/$pid" 2>/dev/null)
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            is_protected_user "$user" && continue
            is_shell_socket_allowed "$exe" && continue
            echo "${now}|${rip}|${pid}|${user}|${exe}" >> "$BEACON_DB"
        done <<< "$conns"

        # Trim DB — keep only entries within window
        if [[ -s "$BEACON_DB" ]]; then
            local cutoff=$((now - BEACON_WINDOW))
            awk -F'|' -v c="$cutoff" '$1 >= c' "$BEACON_DB" > "${BEACON_DB}.tmp" 2>/dev/null
            mv "${BEACON_DB}.tmp" "$BEACON_DB" 2>/dev/null
        fi

        # Analyse: any (rip,exe) pair with >= BEACON_MIN_HITS over the window
        if [[ -s "$BEACON_DB" ]]; then
            awk -F'|' '{print $2"|"$5}' "$BEACON_DB" | sort | uniq -c | \
            while read -r count entry; do
                [[ "$count" -ge "$BEACON_MIN_HITS" ]] || continue
                local b_ip b_exe
                b_ip="${entry%|*}"
                b_exe="${entry#*|}"
                # Compute interval consistency
                local intervals
                intervals=$(awk -F'|' -v ip="$b_ip" -v exe="$b_exe" \
                    '$2 == ip && $5 == exe {print $1}' "$BEACON_DB" | \
                    awk 'NR>1{print $1-prev} {prev=$1}' | sort -n)
                local stddev_ish
                stddev_ish=$(echo "$intervals" | awk '{a[NR]=$1; s+=$1} END {if(NR<2)exit; m=s/NR; for(i=1;i<=NR;i++)v+=(a[i]-m)*(a[i]-m); print int(sqrt(v/NR))}')
                # Low variance = beacon
                if [[ -n "$stddev_ish" && "$stddev_ish" -lt 30 ]]; then
                    send_smart_alert "beacon_${b_ip}" 1800 \
                        "📡 BEACONING DETECTED

Remote: ${b_ip}
Process: ${b_exe}
Hits: ${count} in last ${BEACON_WINDOW}s
Interval variance: ${stddev_ish}s

Action: Blocking remote endpoint" "HIGH"
                    safe_block_ip "$b_ip" "beaconing"
                fi
            done
        fi
    done
}


###############################################################################
# ============== DEEP PERSISTENCE SWEEP (v5 NEW) ============================
###############################################################################
# Scans for trojans hiding in startup paths and removes them when found.

PERSISTENCE_PATHS=(
    "/etc/crontab"
    "/etc/cron.d"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
    "/etc/rc.local"
    "/etc/profile"
    "/etc/profile.d"
    "/etc/bash.bashrc"
    "/etc/zsh/zshrc"
    "/etc/bashrc"
    "/etc/ld.so.preload"
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
    "/etc/systemd/user"
    "/etc/init.d"
    "/etc/xdg/autostart"
    "/etc/at.allow"
    "/etc/at.deny"
)

scan_persistence_for_payloads() {
    local hits=0
    # Build a list of files to scan
    local search_files=()
    for p in "${PERSISTENCE_PATHS[@]}"; do
        if [[ -d "$p" ]]; then
            while IFS= read -r f; do
                [[ -f "$f" ]] && search_files+=("$f")
            done < <(find "$p" -maxdepth 3 -type f 2>/dev/null)
        elif [[ -f "$p" ]]; then
            search_files+=("$p")
        fi
    done
    # Scan user shell rcs
    for home in /root /home/*; do
        [[ -d "$home" ]] || continue
        for rc in .bashrc .bash_profile .profile .zshrc .bash_login \
                  .bash_logout .config/autostart .ssh/rc; do
            local target="${home}/${rc}"
            [[ -f "$target" ]] && search_files+=("$target")
            if [[ -d "$target" ]]; then
                while IFS= read -r f; do
                    [[ -f "$f" ]] && search_files+=("$f")
                done < <(find "$target" -maxdepth 2 -type f 2>/dev/null)
            fi
        done
        local ak="${home}/.ssh/authorized_keys"
        [[ -f "$ak" ]] && search_files+=("$ak")
    done

    local f
    for f in "${search_files[@]}"; do
        [[ ! -f "$f" ]] && continue
        case "$f" in
            "$INSTALL_DIR"/*|"$QUARANTINE_DIR"/*) continue ;;
            */EndpointGuard/*|*/endpointguard*) continue ;;
            *.epg_*|*.epg_pre_clean.*) continue ;;
        esac

        local content
        content=$(head -c 16384 "$f" 2>/dev/null)
        [[ -z "$content" ]] && continue

        # Multi-indicator filter — if the file contains 5+ different C2
        # indicator strings, it's almost certainly a security tool, not malware.
        local indicator_count=0
        for ind in "${C2_DOMAINS[@]}"; do
            if echo "$content" | grep -qiF "$ind" 2>/dev/null; then
                indicator_count=$((indicator_count + 1))
                [[ "$indicator_count" -ge 5 ]] && break
            fi
        done
        [[ "$indicator_count" -ge 5 ]] && continue

        local hit=""
        # For shell-rc files (.bashrc etc) we ONLY flag strict revshell
        # syntax — not any mention of "bash -i" or a domain string. This
        # prevents corrupting user prompts and aliases.
        local strict_only=false
        case "$f" in
            */.bashrc|*/.bash_profile|*/.profile|*/.zshrc|*/.bash_login|*/.bash_logout)
                strict_only=true
                ;;
            */.config/autostart/*|*/profile|*/bash.bashrc|*/bashrc|*/zshrc)
                strict_only=true
                ;;
        esac

        if [[ "$strict_only" == "true" ]]; then
            # Only strict reverse-shell syntax
            if echo "$content" | grep -qE '/dev/(tcp|udp)/[0-9.]+/' 2>/dev/null; then
                hit="strict:/dev/tcp"
            elif echo "$content" | grep -qE '(^|;|&&| )(nc|ncat|netcat) -e' 2>/dev/null; then
                hit="strict:nc_exec"
            elif echo "$content" | grep -qE 'socat .* EXEC:' 2>/dev/null; then
                hit="strict:socat_exec"
            elif echo "$content" | grep -qE 'python3?[[:space:]]+-c[[:space:]]+["'\'']\s*import\s+(socket|os|pty)' 2>/dev/null && \
                 echo "$content" | grep -qE 'connect|dup2|pty\.spawn' 2>/dev/null; then
                hit="strict:python_revshell"
            fi
        else
            # Other persistence locations — broader check
            for ind in "${C2_DOMAINS[@]}"; do
                if echo "$content" | grep -qiF "$ind" 2>/dev/null; then
                    hit="$ind"; break
                fi
            done
            if [[ -z "$hit" ]]; then
                if echo "$content" | grep -qE '/dev/(tcp|udp)/[0-9.]+/' 2>/dev/null; then
                    hit="payload:/dev/tcp"
                elif echo "$content" | grep -qE '(^|;|&&| )(nc|ncat|netcat) -e' 2>/dev/null; then
                    hit="payload:nc_exec"
                elif echo "$content" | grep -qE 'socat .* EXEC:' 2>/dev/null; then
                    hit="payload:socat_exec"
                fi
            fi
        fi

        if [[ -n "$hit" ]]; then
            hits=$((hits + 1))
            log_event "CRITICAL" "PERSISTENCE PAYLOAD: ${f} indicator=${hit}"
            send_smart_alert "persist_${f//\//_}" "$ALERT_COOLDOWN_PERSIST" \
                "🚨 PERSISTENCE TROJAN DETECTED

Path: ${f}
Indicator: ${hit}

Action: Removing malicious lines / quarantining" "CRITICAL"
            case "$f" in
                */authorized_keys)
                    if can_take_action; then
                        local tmp="${f}.epg_clean"
                        cp "$f" "${f}.epg_pre_clean.$(date +%s)" 2>/dev/null
                        # Only strip lines that contain explicit C2 webhook URLs
                        local pat
                        pat=$(printf '%s\n' "${C2_DOMAINS[@]}" | tr '\n' '|' | sed 's/|$//')
                        grep -viE "(${pat})" "$f" > "$tmp" 2>/dev/null
                        mv "$tmp" "$f" 2>/dev/null
                    fi
                    ;;
                /etc/ld.so.preload)
                    can_take_action && : > /etc/ld.so.preload 2>/dev/null
                    ;;
                */.bashrc|*/.bash_profile|*/.profile|*/.zshrc|*/.bash_login|*/.bash_logout|*/profile|*/bashrc|*/zshrc|*/bash.bashrc)
                    # For shell-rc files use SURGICAL line removal — only
                    # delete lines containing the strict revshell syntax
                    if can_take_action; then
                        cp "$f" "${f}.epg_pre_clean.$(date +%s)" 2>/dev/null
                        local tmp="${f}.epg_clean"
                        grep -vE '/dev/(tcp|udp)/[0-9.]+/|(^|;|&&| )(nc|ncat|netcat) -e|socat .* EXEC:' "$f" > "$tmp" 2>/dev/null
                        # Sanity check — never let the file become empty
                        if [[ -s "$tmp" ]]; then
                            mv "$tmp" "$f" 2>/dev/null
                        else
                            rm -f "$tmp" 2>/dev/null
                        fi
                    fi
                    ;;
                /etc/crontab|*/cron.*|/var/spool/cron/*|*/profile.d/*|*/rc.local)
                    if can_take_action; then
                        cp "$f" "${f}.epg_pre_clean.$(date +%s)" 2>/dev/null
                        local tmp="${f}.epg_clean"
                        local pat
                        pat=$(printf '%s\n' "${C2_DOMAINS[@]}" | tr '\n' '|' | sed 's/|$//')
                        grep -vE "(${pat}|/dev/tcp/|/dev/udp/|(^|;|&&| )(nc|ncat|netcat) -e|socat .* EXEC:)" "$f" > "$tmp" 2>/dev/null
                        if [[ -s "$tmp" ]]; then
                            mv "$tmp" "$f" 2>/dev/null
                        else
                            rm -f "$tmp" 2>/dev/null
                        fi
                    fi
                    ;;
                *.service)
                    can_take_action && {
                        systemctl stop "$(basename "$f")" 2>/dev/null
                        systemctl disable "$(basename "$f")" 2>/dev/null
                        quarantine_file "$f" "persistence_service"
                    }
                    ;;
                *)
                    quarantine_file "$f" "persistence_payload"
                    ;;
            esac
        fi
    done
    echo "$hits"
}

monitor_persistence_loop() {
    log_event "INFO" "Persistence monitor started"
    while [[ "$RUNNING" == "true" ]]; do
        can_heavy_scan && scan_persistence_for_payloads >/dev/null
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_HEAVY")
        sleep "$interval"
    done
}

###############################################################################
# ============== CONNECTION AUDITOR (v5.1 NEW) =============================
###############################################################################
# Continuously sweeps every TCP/UDP connection using ss (and netstat as a
# secondary check), scores each one on multiple risk factors, and on threshold
# breach: kills the process, severs the kernel socket, blocks the remote IP
# in iptables INPUT/OUTPUT/FORWARD, flushes conntrack, and quarantines the
# originating script if any.
#
# Risk factors (additive score 0–100):
#   +25  Remote port is a known reverse-shell port (4444, 4445, 1337, 31337,
#        9001, 9002, 8080, 5555, 6666, 6667, 6697, 1234, 12345, 54321, 443
#        when the binary is a shell, etc.)
#   +30  Remote IP resolves to a known C2 domain (Discord webhook, Telegram
#        bot, ngrok, serveo, paste sites, webhook.site, interact.sh, …)
#   +25  Remote IP is a Tor exit node (lightweight check via known cidrs)
#   +40  Process binary is a shell/interpreter holding the socket on stdio
#   +20  Process binary lives in /tmp, /var/tmp, /dev/shm, or /home/*/.cache
#   +20  Process is consuming >70% CPU (htop/top equivalent via /proc)
#   +10  Connection has been established for <5 seconds AND a new login
#        happened in the same window (correlation)
#   +15  Connection is to a non-RFC1918 IP using a high ephemeral port and
#        the binary is unsigned (no apt/dpkg owner)
#
# Default threshold = 60/100. Score >= threshold => auto-respond.

# --- Reverse-shell ports commonly used by Metasploit, msfvenom defaults,
#     popular pentest frameworks, and public payload generators.
SUSPICIOUS_PORTS=(
    4444 4445 4446 4447 4448 4449
    1337 31337 1234 12345 54321
    9001 9002 9003
    5555 6666 6667 6697 7777 8888
    8080 8181 8443 9999 10000 10001
    1080 1180 2222 3333 4321
    443  # only flagged when paired with shell-on-stdio
    80   # same — only with shell-on-stdio
)

is_suspicious_port() {
    local port="$1"
    [[ -z "$port" ]] && return 1
    for sp in "${SUSPICIOUS_PORTS[@]}"; do
        [[ "$port" == "$sp" ]] && return 0
    done
    return 1
}

# Cheap reverse-DNS check using getent (no extra deps).
# Returns the matching C2 domain name or empty.
ip_resolves_to_c2() {
    local ip="$1"
    [[ -z "$ip" ]] && return
    # Skip private ranges
    case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|127.*|169.254.*) return ;;
    esac
    local host
    host=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -1)
    [[ -z "$host" ]] && {
        # Fallback to dig if installed
        if command -v dig &>/dev/null; then
            host=$(dig -x "$ip" +short +time=2 +tries=1 2>/dev/null | head -1 | sed 's/\.$//')
        fi
    }
    [[ -z "$host" ]] && return
    for ind in "${C2_DOMAINS[@]}"; do
        local dom="${ind%%/*}"
        if echo "$host" | grep -qiF "$dom" 2>/dev/null; then
            echo "$ind"
            return
        fi
    done
}

# CPU% for a pid via /proc/stat (htop/top equivalent).
# We compute over a 200ms window for each pid we care about.
proc_cpu_percent() {
    local pid="$1"
    [[ -z "$pid" || ! -f "/proc/$pid/stat" ]] && { echo 0; return; }
    local stat1 stat2 utime1 stime1 utime2 stime2 total1 total2 sysjiffies1 sysjiffies2
    stat1=$(cat "/proc/$pid/stat" 2>/dev/null) || { echo 0; return; }
    sysjiffies1=$(awk '/^cpu /{u=$2+$3+$4+$5+$6+$7+$8+$9; print u}' /proc/stat)
    sleep 0.2
    stat2=$(cat "/proc/$pid/stat" 2>/dev/null) || { echo 0; return; }
    sysjiffies2=$(awk '/^cpu /{u=$2+$3+$4+$5+$6+$7+$8+$9; print u}' /proc/stat)
    utime1=$(echo "$stat1" | awk '{print $14}')
    stime1=$(echo "$stat1" | awk '{print $15}')
    utime2=$(echo "$stat2" | awk '{print $14}')
    stime2=$(echo "$stat2" | awk '{print $15}')
    total1=$((utime1 + stime1))
    total2=$((utime2 + stime2))
    local proc_diff=$((total2 - total1))
    local sys_diff=$((sysjiffies2 - sysjiffies1))
    [[ "$sys_diff" -le 0 ]] && { echo 0; return; }
    local cpus
    cpus=$(get_cpu_count)
    echo $(( (proc_diff * 100 * cpus) / sys_diff ))
}

# Returns true if the binary path looks like a dropper location
is_dropper_path() {
    local path="$1"
    [[ -z "$path" ]] && return 1
    case "$path" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*/.cache/*|/home/*/Downloads/*) return 0 ;;
    esac
    return 1
}

# Score a single connection.
# Args: pid user exe rip rport state cmdline
# Echoes: SCORE|REASONS_CSV
score_connection() {
    local pid="$1" user="$2" exe="$3" rip="$4" rport="$5" state="$6" cmdline="$7"
    local score=0 reasons=""

    # Skip own/trusted/allowlisted/private — score stays 0.
    # NOTE: We use is_process_protected_user (which only spares the
    # configured TRUSTED_USER), not is_protected_user. A reverse shell
    # running as root MUST score and be killed — it's the most common case.
    is_own_process "$pid" && { echo "0|own"; return; }
    is_process_protected_user "$user" && { echo "0|trusted_user"; return; }
    is_shell_socket_allowed "$exe" && { echo "0|allowlisted_daemon"; return; }
    is_my_own_ip "$rip" && { echo "0|own_ip"; return; }
    case "$rip" in
        127.*|0.0.0.0|::1|fe80:*|::) echo "0|loopback"; return ;;
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) echo "0|private_lan"; return ;;
        fc[0-9a-f]:*|fd[0-9a-f]:*) echo "0|private_lan6"; return ;;
    esac

    # 1) Suspicious port
    if is_suspicious_port "$rport"; then
        score=$((score + 25)); reasons="${reasons}${reasons:+,}susp_port:${rport}"
    fi

    # 2) Reverse-DNS to C2 domain
    local c2_hit
    c2_hit=$(ip_resolves_to_c2 "$rip")
    if [[ -n "$c2_hit" ]]; then
        score=$((score + 30)); reasons="${reasons}${reasons:+,}c2_domain:${c2_hit}"
    fi

    # 3) Shell process holding socket on stdio (the smoking gun — bumped to 50
    #    because it alone is near-certain evidence of a reverse shell).
    if proc_is_shell "$exe" "$(basename "$exe")"; then
        local fd_dir="/proc/$pid/fd"
        if [[ -d "$fd_dir" ]]; then
            for fd in 0 1 2; do
                if fd_is_socket "${fd_dir}/${fd}"; then
                    score=$((score + 50)); reasons="${reasons}${reasons:+,}shell_socket_stdio:fd${fd}"
                    break
                fi
            done
        fi
    fi

    # 4) Dropper path
    if is_dropper_path "$exe"; then
        score=$((score + 20)); reasons="${reasons}${reasons:+,}dropper_path:${exe}"
    fi

    # 5) High CPU
    local cpu
    cpu=$(proc_cpu_percent "$pid")
    if [[ "${cpu:-0}" -ge 70 ]]; then
        score=$((score + 20)); reasons="${reasons}${reasons:+,}high_cpu:${cpu}%"
    fi

    # 6) High ephemeral port + unsigned binary
    if [[ "$rport" -gt 49000 ]] && [[ -n "$exe" && -f "$exe" ]]; then
        local pkg_owns=false
        if command -v dpkg &>/dev/null; then
            dpkg -S "$exe" >/dev/null 2>&1 && pkg_owns=true
        fi
        if ! $pkg_owns && command -v rpm &>/dev/null; then
            rpm -qf "$exe" >/dev/null 2>&1 && pkg_owns=true
        fi
        if ! $pkg_owns; then
            score=$((score + 15)); reasons="${reasons}${reasons:+,}unsigned_high_port:${rport}"
        fi
    fi

    # 7) Cmdline contains C2 indicator
    for ind in "${C2_DOMAINS[@]}"; do
        if echo "$cmdline" | grep -qiF "$ind" 2>/dev/null; then
            score=$((score + 30)); reasons="${reasons}${reasons:+,}cmdline_c2:${ind}"
            break
        fi
    done

    # 8) Cmdline contains shell-revshell pattern
    for pat in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
        if echo "$cmdline" | grep -qiE "$pat" 2>/dev/null; then
            score=$((score + 25)); reasons="${reasons}${reasons:+,}cmdline_pattern"
            break
        fi
    done

    echo "${score}|${reasons}"
}

# Single sweep through current connections — also called by the on-demand scan.
audit_connections_once() {
    local report_only="${1:-no}"
    local hits=0
    local raw conns_tcp conns_udp

    if command -v ss &>/dev/null; then
        # Capture ALL states (not just established) — catches reverse shells
        # in SYN_SENT (just connected) and CLOSE_WAIT (lingering after kill).
        conns_tcp=$(ss -tnp 2>/dev/null | tail -n +2)
        conns_udp=$(ss -unp 2>/dev/null | tail -n +2)
    elif command -v netstat &>/dev/null; then
        conns_tcp=$(netstat -tnp 2>/dev/null | awk 'NR>2 && $6=="ESTABLISHED"')
        conns_udp=""
    else
        log_event "WARN" "Connection auditor: neither ss nor netstat available"
        echo 0; return
    fi
    raw="${conns_tcp}
${conns_udp}"

    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Skip header
        echo "$line" | grep -qE "^(Recv-Q|Netid|Active|State)" && continue

        # Extract pid from users:(("name",pid=NN,fd=NN)) anywhere in the line
        local pid
        pid=$(echo "$line" | grep -oP 'pid=\K\d+' | head -1)
        if [[ -z "$pid" ]]; then
            # netstat formats it differently: "12345/bash"
            pid=$(echo "$line" | awk '{print $7}' | cut -d/ -f1)
        fi
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue

        # Extract remote endpoint. ss layout:
        #   Recv-Q Send-Q LOCAL_ADDR:PORT  PEER_ADDR:PORT  users:((...))
        # We want field 4 (peer) when using ss; netstat puts foreign addr at $5.
        local remote
        if echo "$line" | grep -q 'users:(('; then
            # ss: peer is the field immediately before "users:"
            remote=$(echo "$line" | awk '{
                for (i=1;i<=NF;i++) {
                    if ($i ~ /^users:\(\(/) {print $(i-1); exit}
                }
            }')
        elif command -v netstat &>/dev/null; then
            # netstat tcp:  Proto Recv-Q Send-Q Local Foreign State PID/Program
            remote=$(echo "$line" | awk '{print $5}')
        else
            remote=$(echo "$line" | awk '{print $5}')
        fi

        # Strip surrounding [ ] from IPv6
        remote=$(echo "$remote" | sed 's/^\[//;s/\]:/:/')

        # IPv6 addresses contain : already — split at the LAST colon for port
        local rip rport
        rport="${remote##*:}"
        rip="${remote%:*}"

        [[ -z "$rip" || -z "$rport" || "$rip" == "0.0.0.0" || "$rip" == "*" || "$rip" == "::" ]] && continue
        # Validate port is numeric
        [[ ! "$rport" =~ ^[0-9]+$ ]] && continue

        local user exe cmdline
        user=$(stat -c %U "/proc/$pid" 2>/dev/null)
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 400)

        local result
        result=$(score_connection "$pid" "$user" "$exe" "$rip" "$rport" "ESTABLISHED" "$cmdline")
        local score reasons
        score="${result%%|*}"
        reasons="${result#*|}"

        # If only reporting (on-demand scan), echo all non-zero scores
        if [[ "$report_only" == "yes" ]]; then
            if [[ "$score" -gt 0 && "$reasons" != "own" && "$reasons" != "protected_user" && \
                  "$reasons" != "allowlisted_daemon" && "$reasons" != "loopback" && \
                  "$reasons" != "private_lan" && "$reasons" != "own_ip" ]]; then
                echo "${score}|${pid}|${user}|${exe}|${rip}:${rport}|${reasons}"
            fi
            continue
        fi

        # Below threshold => move on
        [[ "$score" -lt "$CONN_RISK_THRESHOLD" ]] && continue

        hits=$((hits + 1))
        log_event "CRITICAL" "CONN AUDITOR HIT score=${score} pid=${pid} user=${user} exe=${exe} remote=${rip}:${rport} reasons=${reasons}"
        send_smart_alert "conn_audit_${rip}_${rport}" "$ALERT_COOLDOWN_NET" \
            "🔴 SUSPICIOUS CONNECTION

Score: ${score}/100
PID: ${pid}
User: ${user}
Binary: ${exe}
Remote: ${rip}:${rport}
Reasons: ${reasons}
Cmd: $(echo "$cmdline" | head -c 200)

Action: Killing process + severing socket + blocking IP" "CRITICAL"

        # Respond — kill the process AND its parent chain. A reverse shell
        # like `bash bash.sh` has parent=bash (the wrapper). Kill both.
        local kill_pid="$pid" depth=0
        local seen_pids=""
        while [[ -n "$kill_pid" && "$kill_pid" != "0" && "$kill_pid" != "1" && "$depth" -lt 5 ]]; do
            # Cycle / re-visit guard
            case " $seen_pids " in *" $kill_pid "*) break ;; esac
            seen_pids="$seen_pids $kill_pid"
            local parent_pid parent_user parent_cmd
            parent_pid=$(ps -o ppid= -p "$kill_pid" 2>/dev/null | tr -d ' ')
            parent_user=$(stat -c %U "/proc/$kill_pid" 2>/dev/null)
            parent_cmd=$(tr '\0' ' ' < "/proc/$kill_pid/cmdline" 2>/dev/null)
            is_own_process "$kill_pid" && break
            case "$parent_cmd" in
                *systemd*|*init*|*sshd*|*login*|/usr/lib/systemd*) break ;;
            esac
            safe_kill_process "$kill_pid" "$parent_user" "conn_audit:${reasons}"
            kill_pid="$parent_pid"
            depth=$((depth + 1))
        done
        kernel_kill_conn "$rip" "$rport"
        safe_block_ip "$rip" "conn_audit:${reasons}"
        if is_dropper_path "$exe" && [[ -f "$exe" ]]; then
            quarantine_file "$exe" "conn_audit_dropper"
        fi
    done <<< "$raw"

    [[ "$report_only" == "yes" ]] && return
    echo "$hits"
}

monitor_connection_audit() {
    log_event "INFO" "Connection auditor started (interval=${CONN_AUDIT_INTERVAL}s, threshold=${CONN_RISK_THRESHOLD}/100)"
    while [[ "$RUNNING" == "true" ]]; do
        audit_connections_once "no" >/dev/null
        sleep "$CONN_AUDIT_INTERVAL"
    done
}

###############################################################################
# ============== WATCHDOG (v5 NEW) ==========================================
###############################################################################
# Restarts crashed monitor functions automatically.
WATCHDOG_FUNCS=()
WATCHDOG_PIDS=()

watchdog_start() {
    local fname="$1"
    "$fname" &
    local p=$!
    track_child $p
    WATCHDOG_FUNCS+=("$fname")
    WATCHDOG_PIDS+=("$p")
    log_event "INFO" "Watchdog: started ${fname} pid=${p}"
}

watchdog_loop() {
    log_event "INFO" "Watchdog loop started"
    while [[ "$RUNNING" == "true" ]]; do
        sleep 30
        local i
        for i in "${!WATCHDOG_FUNCS[@]}"; do
            local fname="${WATCHDOG_FUNCS[$i]}"
            local pid="${WATCHDOG_PIDS[$i]}"
            if ! kill -0 "$pid" 2>/dev/null; then
                log_event "WARN" "Watchdog: ${fname} (pid=${pid}) died — restarting"
                "$fname" &
                local newp=$!
                track_child $newp
                WATCHDOG_PIDS[$i]=$newp
                send_smart_alert "watchdog_${fname}" 600 \
                    "Module restarted: ${fname} (was pid=${pid}, now pid=${newp})" "MEDIUM"
            fi
        done
    done
}


###############################################################################
# ============== SSH / LOGIN MONITORS (carried + tightened) =================
###############################################################################

find_auth_log() {
    if [[ -f /var/log/auth.log ]]; then echo "file:/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then echo "file:/var/log/secure"
    else echo "journalctl"; fi
}

parse_ssh_success() {
    local line="$1" user="" ip="" method=""
    if echo "$line" | grep -qiE "Accepted (password|publickey|keyboard)" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'for \K\S+' 2>/dev/null | head -1)
        ip=$(echo "$line" | grep -oP 'from \K[0-9a-fA-F.:]+' 2>/dev/null | head -1)
        method=$(echo "$line" | grep -oP 'Accepted \K\S+' 2>/dev/null | head -1)
    fi
    if [[ -z "$user" ]] && echo "$line" | grep -qiE "sshd:session.*session opened" 2>/dev/null; then
        user=$(echo "$line" | grep -oP 'for user \K\S+' 2>/dev/null | head -1)
        method="pam"
    fi
    [[ -n "$user" ]] && echo "${user}|${ip:-unknown}|${method:-unknown}" || echo ""
}
parse_ssh_failure() {
    local line="$1" user="" ip=""
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
    local line="$1" user=""
    if echo "$line" | grep -qiE "(session closed|Disconnected from|Connection closed|pam_unix.*session closed)" 2>/dev/null; then
        user=$(echo "$line" | grep -oP '(for user |user )\K\S+' 2>/dev/null | head -1)
        [[ -z "$user" ]] && user=$(echo "$line" | grep -oP 'for \K\S+' 2>/dev/null | head -1)
    fi
    echo "${user:-}"
}

handle_compromised_trusted_account() {
    local target_user="$1" target_ip="$2" target_pid="${3:-unknown}"
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
        ( sleep 2
          log_event "CRITICAL" "Responding to untrusted IP ${target_ip} on trusted account ${target_user}"
          safe_block_ip "$target_ip" "compromised_trusted_account_${target_user}"
          redirect_attacker_to_honeypot "$target_user" "$target_ip" "$target_pid"
          kill_attacker_session_only "$target_user" "$target_ip" "$target_pid"
          log_event "HIGH" "Intrusion response complete: user=${target_user} ip=${target_ip}" ) &
        track_child $!
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
    # Sever any kernel sockets to/from this IP
    kernel_kill_conn "$target_ip"
}

monitor_ssh_logins() {
    local auth_source
    auth_source=$(find_auth_log)
    log_event "INFO" "SSH monitor started (${auth_source})"
    if [[ "$auth_source" == "journalctl" ]]; then
        journalctl -u sshd -u ssh -f --no-pager -n 0 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            process_auth_line "$line"
        done
    else
        local logfile="${auth_source#file:}"
        tail -n 0 -F "$logfile" 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            process_auth_line "$line"
        done
    fi
}
process_auth_line() {
    local line="$1"
    [[ -z "$line" ]] && return
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
    local fail_data
    fail_data=$(parse_ssh_failure "$line")
    if [[ -n "$fail_data" ]]; then
        IFS='|' read -r user ip <<< "$fail_data"
        [[ -z "$ip" ]] && return
        is_trusted_ip "$ip" && return
        log_event "MEDIUM" "SSH FAIL: user=${user} ip=${ip}"
        local fail_count
        fail_count=$(grep -c "SSH FAIL.*ip=${ip}" "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "${fail_count:-0}" -ge "$MAX_FAILED_LOGINS" ]]; then
            send_smart_alert "brute_${ip}" 600 \
                "BRUTE FORCE
IP: ${ip} | User: ${user} | Attempts: ${fail_count}" "CRITICAL"
            safe_block_ip "$ip" "brute_force"
        elif [[ $((fail_count % 5)) -eq 0 ]] && [[ "${fail_count:-0}" -gt 0 ]]; then
            send_smart_alert "sshfail_${ip}" "$ALERT_COOLDOWN_SSH" \
                "SSH Failures: ${fail_count}/${MAX_FAILED_LOGINS}
IP: ${ip} | User: ${user}" "MEDIUM"
        fi
        return
    fi
    local close_user
    close_user=$(parse_ssh_close "$line")
    if [[ -n "$close_user" ]] && ! is_protected_user "$close_user"; then
        deactivate_jail_for_user "$close_user"
    fi
}

monitor_untrusted_session() {
    local user="$1" ip="$2" session_pid="${3:-}"
    local suspicious_count=0
    is_protected_user "$user" && return
    log_event "INFO" "Monitoring: ${user} from ${ip}"
    while [[ "$RUNNING" == "true" ]]; do
        if ! pgrep -u "$user" &>/dev/null; then
            deactivate_jail_for_user "$user"; break
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
                if echo "$proc_cmd" | grep -qiE "$pattern" 2>/dev/null; then
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
                log_event "INFO" "New session: user=${s_user} tty=${s_tty} source=${s_source}"
                if is_my_own_session "$s_user" "$s_source"; then
                    send_smart_alert "login_owner_${s_source}" "$ALERT_COOLDOWN_SSH" \
                        "✅ Owner Login Detected
User: ${s_user} | Source: ${s_source}
TTY: ${s_tty}" "LOW"
                    continue
                fi
                if is_trusted_user "$s_user"; then
                    local sp; sp=$(pgrep -n -u "$s_user" 2>/dev/null || echo "unknown")
                    handle_compromised_trusted_account "$s_user" "$s_source" "$sp"
                elif ! is_system_user "$s_user"; then
                    send_smart_alert "login_${s_user}" "$ALERT_COOLDOWN_SSH" \
                        "🚨 UNTRUSTED USER LOGIN
User: ${s_user} | Source: ${s_source}
TTY: ${s_tty}" "CRITICAL"
                    if can_take_action; then
                        local sp; sp=$(pgrep -n -u "$s_user" 2>/dev/null || echo "")
                        activate_jail_for_session "$s_user" "$s_source" "$sp"
                        monitor_untrusted_session "$s_user" "$s_source" "$sp" &
                        track_child $!
                    fi
                fi
            done <<< "$new_sessions"
            local gone
            gone=$(diff <(echo "$prev") <(echo "$current") 2>/dev/null | grep "^<" | sed 's/^< //' || true)
            while IFS= read -r gl; do
                [[ -z "$gl" ]] && continue
                local gu; gu=$(echo "$gl" | awk '{print $1}')
                is_protected_user "$gu" || deactivate_jail_for_user "$gu"
            done <<< "$gone"
        fi
        echo "$hash" > "${BASELINE_DIR}/sessions_hash" 2>/dev/null
        echo "$current" > "${BASELINE_DIR}/sessions" 2>/dev/null
        sleep "$REALTIME_LOGIN_INTERVAL"
    done
}

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
                    local sp; sp=$(pgrep -n -u "$l_user" 2>/dev/null || echo "unknown")
                    handle_compromised_trusted_account "$l_user" "$l_ip" "$sp"
                elif ! is_system_user "$l_user" && ! is_trusted_user "$l_user"; then
                    log_event "HIGH" "WTMP: Unknown user login ${l_user} from ${l_ip}"
                    send_smart_alert "wtmp_${l_user}" "$ALERT_COOLDOWN_SSH" \
                        "🔍 WTMP Login Detected
User: ${l_user} | IP: ${l_ip}" "HIGH"
                fi
            done <<< "$new_entries"
        fi
        echo "$current_last" > "${BASELINE_DIR}/last_logins" 2>/dev/null
        sleep "$REALTIME_LOGIN_INTERVAL"
    done
}


###############################################################################
# ============== PAM HOOKS (instant detection + self-healing) ===============
###############################################################################

PAM_HOOK_SCRIPT="${INSTALL_DIR}/pam_epg_hook.sh"
PAM_FIFO="${INSTALL_DIR}/pam_alerts.fifo"
PAM_LOG="${INSTALL_DIR}/pam_events.log"
PAM_TRUSTED_IPS="${INSTALL_DIR}/trusted_ips.conf"

write_pam_hook_script() {
    cat > "$PAM_HOOK_SCRIPT" <<'PAMHOOK'
#!/bin/bash
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
if [[ -f "$TRUSTED_IPS_FILE" ]] && ! grep -qF "$LOGIN_IP" "$TRUSTED_IPS_FILE" 2>/dev/null; then
    echo "$(date +%s) UNTRUSTED_PAM user=${LOGIN_USER} ip=${LOGIN_IP} svc=${LOGIN_SERVICE}" >> "${EPG_DIR}/pam_events.log" 2>/dev/null
fi
exit 0
PAMHOOK
    chmod 700 "$PAM_HOOK_SCRIPT"
}

install_pam_hook() {
    local pam_dir="/etc/pam.d"
    write_pam_hook_script
    echo "$TRUSTED_IPS 127.0.0.1 ::1 $MY_CURRENT_IPS" | tr ' ' '\n' | sort -u > "$PAM_TRUSTED_IPS" 2>/dev/null
    [[ ! -p "$PAM_FIFO" ]] && mkfifo "$PAM_FIFO" 2>/dev/null
    chmod 622 "$PAM_FIFO" 2>/dev/null
    for svc in sshd login su; do
        [[ -f "${pam_dir}/${svc}" ]] || continue
        if ! grep -q "pam_epg_hook" "${pam_dir}/${svc}" 2>/dev/null; then
            cp "${pam_dir}/${svc}" "${pam_dir}/${svc}.epg_backup" 2>/dev/null
            echo "session optional pam_exec.so seteuid ${PAM_HOOK_SCRIPT}" >> "${pam_dir}/${svc}" 2>/dev/null
            log_event "INFO" "PAM hook installed for ${svc}"
        fi
    done
}

# Self-healing — re-install if attacker removed or tampered
pam_self_heal_loop() {
    log_event "INFO" "PAM self-heal loop started"
    while [[ "$RUNNING" == "true" ]]; do
        sleep 60
        local need_reinstall=false
        for svc in sshd login su; do
            [[ -f "/etc/pam.d/${svc}" ]] || continue
            if ! grep -q "pam_epg_hook" "/etc/pam.d/${svc}" 2>/dev/null; then
                need_reinstall=true; break
            fi
        done
        [[ ! -x "$PAM_HOOK_SCRIPT" ]] && need_reinstall=true
        [[ ! -p "$PAM_FIFO" ]] && need_reinstall=true
        if [[ "$need_reinstall" == "true" ]]; then
            log_event "HIGH" "PAM hook tampered with — reinstalling"
            send_smart_alert "pam_tamper" 600 \
                "PAM HOOK TAMPERED — reinstalling" "HIGH"
            install_pam_hook
        fi
    done
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
    rm -f "$PAM_HOOK_SCRIPT" "$PAM_FIFO" "$PAM_LOG" "$PAM_TRUSTED_IPS" 2>/dev/null
}

monitor_pam_alerts() {
    [[ ! -p "$PAM_FIFO" ]] && return
    log_event "INFO" "PAM alert monitor started"
    while [[ "$RUNNING" == "true" ]]; do
        if read -r alert_line < "$PAM_FIFO" 2>/dev/null; then
            [[ -z "$alert_line" ]] && continue
            IFS='|' read -r ts pam_user pam_ip pam_type pam_service pam_tty <<< "$alert_line"
            log_event "INFO" "PAM event: user=${pam_user} ip=${pam_ip} svc=${pam_service}"
            is_my_own_session "$pam_user" "$pam_ip" && continue
            if is_trusted_user "$pam_user" && ! is_my_own_ip "$pam_ip"; then
                local sp; sp=$(pgrep -n -u "$pam_user" 2>/dev/null || echo "unknown")
                handle_compromised_trusted_account "$pam_user" "$pam_ip" "$sp"
            elif ! is_system_user "$pam_user" && ! is_trusted_user "$pam_user"; then
                send_smart_alert "pam_${pam_user}_${pam_ip}" "$ALERT_COOLDOWN_SSH" \
                    "🔐 PAM LOGIN DETECTED (INSTANT)
User: ${pam_user} | IP: ${pam_ip}
Service: ${pam_service} | TTY: ${pam_tty}" "CRITICAL"
                if can_take_action; then
                    local sp; sp=$(pgrep -n -u "$pam_user" 2>/dev/null || echo "")
                    activate_jail_for_session "$pam_user" "$pam_ip" "$sp"
                    safe_block_ip "$pam_ip" "pam_untrusted_login"
                fi
            fi
        fi
    done
}

###############################################################################
# ============== SU/SUDO MONITOR ============================================
###############################################################################
monitor_su_sudo() {
    local auth_source
    auth_source=$(find_auth_log)
    log_event "INFO" "SU/Sudo monitor started"
    _process_susudo() {
        local line="$1"
        [[ -z "$line" ]] && return
        if echo "$line" | grep -qiE "(su\[|su:).*session opened" 2>/dev/null; then
            local su_user
            su_user=$(echo "$line" | grep -oP 'by \K\S+' 2>/dev/null | tr -d '()' | head -1)
            [[ -z "$su_user" ]] && return
            if ! is_protected_user "$su_user"; then
                send_smart_alert "su_${su_user}" "$ALERT_COOLDOWN_CMD" "SU by untrusted: ${su_user}" "HIGH"
                can_take_action && pkill -u "$su_user" su 2>/dev/null
            fi
        fi
        if echo "$line" | grep -qiE "sudo:.*COMMAND=" 2>/dev/null; then
            local sudo_user sudo_cmd
            sudo_user=$(echo "$line" | grep -oP 'sudo:\s+\K\S+' 2>/dev/null | head -1)
            sudo_cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*' 2>/dev/null)
            [[ -z "$sudo_user" ]] && return
            if ! is_protected_user "$sudo_user"; then
                local dangerous=false
                for p in "${TRULY_MALICIOUS_PATTERNS[@]}"; do
                    echo "$sudo_cmd" | grep -qiE "$p" 2>/dev/null && { dangerous=true; break; }
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
    }
    if [[ "$auth_source" == "journalctl" ]]; then
        journalctl -f --no-pager -n 0 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            _process_susudo "$line"
        done
    else
        local logfile="${auth_source#file:}"
        tail -n 0 -F "$logfile" 2>/dev/null | while IFS= read -r line; do
            [[ "$RUNNING" == "false" ]] && break
            _process_susudo "$line"
        done
    fi
}

###############################################################################
# ============== FILE INTEGRITY =============================================
###############################################################################
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
${file}" "HIGH"
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
        log_event "INFO" "File integrity: using inotifywait"
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
${event_line}" "HIGH"
            done
        fi
    else
        while [[ "$RUNNING" == "true" ]]; do
            check_file_integrity
            local interval
            interval=$(get_adaptive_interval "$SCAN_INTERVAL_VERY_HEAVY")
            sleep "$interval"
        done
    fi
}

###############################################################################
# ============== NETWORK MONITOR (ports + reverse-shell verification) =======
###############################################################################
monitor_network() {
    log_event "INFO" "Network monitor started"
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort > "${BASELINE_DIR}/ports" 2>/dev/null
    while [[ "$RUNNING" == "true" ]]; do
        can_heavy_scan || { sleep "$SCAN_INTERVAL_HEAVY"; continue; }
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_MEDIUM")
        local current_raw current_list
        current_raw=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
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
        sleep "$interval"
    done
}

###############################################################################
# ============== KERNEL MODULE MONITOR ======================================
###############################################################################
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
                local suspicious_mods="" suspicious_count=0
                while IFS= read -r mod_line; do
                    [[ -z "$mod_line" ]] && continue
                    local mod_name; mod_name=$(echo "$mod_line" | awk '{print $1}')
                    [[ -z "$mod_name" || "$mod_name" == "Module" ]] && continue
                    if ! is_whitelisted_kmod "$mod_name"; then
                        suspicious_mods+="${mod_line}"$'\n'
                        suspicious_count=$((suspicious_count + 1))
                        log_event "HIGH" "Unknown kernel module loaded: ${mod_name}"
                    fi
                done <<< "$new_mods"
                if [[ "$suspicious_count" -gt 0 ]]; then
                    send_smart_alert "kmod" "$ALERT_COOLDOWN_OTHER" \
                        "⚠️ Unknown Kernel Modules (${suspicious_count}):
${suspicious_mods}" "HIGH"
                fi
            fi
        fi
        echo "$current" > "${BASELINE_DIR}/kmods" 2>/dev/null
        sleep "$interval"
    done
}

###############################################################################
# ============== RESOURCE / MINER MONITOR ===================================
###############################################################################
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
            if echo "$cc" | grep -qiE "(xmrig|minerd|cpuminer|cryptonight|stratum\+tcp|monero)" 2>/dev/null; then
                safe_kill_process "$cp" "$cu" "miner"
                send_smart_alert "miner_${cp}" "$ALERT_COOLDOWN_OTHER" \
                    "MINER: ${cu} cmd=$(echo "$cc" | head -c 150)" "CRITICAL"
                safe_kill_sessions "$cu"
            else
                send_smart_alert "cpu_${cu}" "$ALERT_COOLDOWN_OTHER" \
                    "High CPU: ${cu} $(echo "$cc" | head -c 100)" "MEDIUM"
            fi
        done <<< "$high_cpu"
        sleep "$interval"
    done
}

###############################################################################
# ============== ANTI-TAMPERING =============================================
###############################################################################
anti_tampering() {
    log_event "INFO" "Anti-tampering started"
    local self_path
    self_path=$(readlink -f "$0" 2>/dev/null || echo "$0")
    sha256sum "$self_path" 2>/dev/null | awk '{print $1}' > "${BASELINE_DIR}/self_hash" 2>/dev/null
    iptables -L INPUT -n 2>/dev/null | wc -l > "${BASELINE_DIR}/fw_count" 2>/dev/null
    while [[ "$RUNNING" == "true" ]]; do
        local interval
        interval=$(get_adaptive_interval "$SCAN_INTERVAL_HEAVY")
        if [[ -f "${BASELINE_DIR}/self_hash" ]]; then
            local ch eh
            ch=$(sha256sum "$self_path" 2>/dev/null | awk '{print $1}')
            eh=$(cat "${BASELINE_DIR}/self_hash" 2>/dev/null)
            [[ -n "$ch" && -n "$eh" && "$ch" != "$eh" ]] && \
                send_smart_alert "tamper" 300 "EPG BINARY MODIFIED!" "CRITICAL"
        fi
        if [[ -f "${BASELINE_DIR}/fw_count" ]] && can_block_ip; then
            local rc pc
            rc=$(iptables -L INPUT -n 2>/dev/null | wc -l)
            pc=$(cat "${BASELINE_DIR}/fw_count" 2>/dev/null || echo "0")
            if [[ "${pc:-0}" -gt 5 && "${rc:-0}" -lt "$((pc - 5))" ]]; then
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


###############################################################################
# ============== SSH HARDENING ==============================================
###############################################################################
apply_ssh_hardening() {
    local conf="/etc/ssh/sshd_config"
    [[ ! -f "$conf" ]] && return
    [[ "$SAFETY_MODE" == "monitor" ]] && { log_event "INFO" "SSH hardening skipped (monitor)"; return; }
    log_event "INFO" "Applying SSH hardening"
    [[ ! -f "${conf}.epg_backup" ]] && cp "$conf" "${conf}.epg_backup" 2>/dev/null
    _setk() {
        local k="$1" v="$2"
        if grep -qE "^${k}\s" "$conf" 2>/dev/null; then
            sed -i "s/^${k}\s.*/${k} ${v}/" "$conf" 2>/dev/null
        elif grep -qE "^#\s*${k}\s" "$conf" 2>/dev/null; then
            sed -i "s/^#\s*${k}\s.*/${k} ${v}/" "$conf" 2>/dev/null
        else
            echo "${k} ${v}" >> "$conf"
        fi
    }
    _setk "MaxAuthTries" "5"
    _setk "LoginGraceTime" "60"
    _setk "PermitEmptyPasswords" "no"
    _setk "ClientAliveInterval" "300"
    _setk "ClientAliveCountMax" "3"
    _setk "MaxSessions" "10"
    _setk "LogLevel" "VERBOSE"
    cat > /etc/ssh/banner <<'BANNER'
================================================================
  AUTHORIZED ACCESS ONLY — All connections monitored.
================================================================
BANNER
    _setk "Banner" "/etc/ssh/banner"
    systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null
}

###############################################################################
# ============== DAILY REPORT ===============================================
###############################################################################
generate_daily_report() {
    log_event "INFO" "Daily report started"
    local last_day=""
    while [[ "$RUNNING" == "true" ]]; do
        local hour day
        hour=$(date +%H); day=$(date +%Y-%m-%d)
        if [[ "$hour" == "00" && "$day" != "$last_day" ]]; then
            last_day="$day"
            local total=0 crit=0 high=0 blocked=0 quarantined=0
            [[ -f "$LOG_FILE" ]] && {
                total=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
                crit=$(grep -c "CRITICAL" "$LOG_FILE" 2>/dev/null || echo 0)
                high=$(grep -c "HIGH" "$LOG_FILE" 2>/dev/null || echo 0)
            }
            [[ -f "$BLOCKED_FILE" ]] && blocked=$(wc -l < "$BLOCKED_FILE" 2>/dev/null || echo 0)
            [[ -f "${QUARANTINE_DIR}/quarantine.log" ]] && \
                quarantined=$(wc -l < "${QUARANTINE_DIR}/quarantine.log" 2>/dev/null || echo 0)
            send_telegram "DAILY REPORT 📊
Mode: ${SAFETY_MODE} | Events: ${total}
Critical: ${crit} | High: ${high}
Blocked IPs: ${blocked} | Quarantined files: ${quarantined}" "LOW"
            find "$ALERT_TRACKER" -type f -mtime +7 -delete 2>/dev/null
            local sz; sz=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
            if [[ "${sz:-0}" -gt 52428800 ]]; then
                mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d)" 2>/dev/null
                gzip "${LOG_FILE}.$(date +%Y%m%d)" 2>/dev/null &
                touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
                ls -t "${LOG_FILE}".*.gz 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null
            fi
        fi
        sleep 3600
    done
}

###############################################################################
# ============== DAEMON CONTROL =============================================
###############################################################################

start_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local ep; ep=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$ep" ]] && kill -0 "$ep" 2>/dev/null; then
            epg_warn "Already running (PID: ${ep})"; return 1
        fi
    fi
    require_root
    DAEMON_MODE=true
    init_directories_silent

    echo -e "${GREEN}"
    echo '╔═══════════════════════════════════════════════════════════╗'
    echo '║  EndpointGuard v5.0 — Linux Sentinel started              ║'
    echo '╚═══════════════════════════════════════════════════════════╝'
    echo -e "${NC}"
    epg_info "  Mode: ${BOLD}${SAFETY_MODE^^}${NC}"
    case "$SAFETY_MODE" in
        monitor)  epg_ok "  → Alert only — ZERO risk" ;;
        moderate) epg_warn "  → Alert + block brute force" ;;
        active)   epg_err "  → Full auto-response (kill + block + quarantine)" ;;
    esac
    [[ -z "$TELEGRAM_BOT_TOKEN" ]] && epg_warn "  ⚠ Telegram not configured (optional)"

    log_event "INFO" "===== EPG v${EPG_VERSION} starting (mode=${SAFETY_MODE}) ====="
    trap daemon_cleanup SIGTERM SIGINT SIGHUP EXIT

    detect_my_ips
    setup_honeypot_jail
    init_file_integrity
    apply_ssh_hardening
    install_pam_hook
    recover_jailed_users

    # Initial baselines
    find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | sort > "${BASELINE_DIR}/suid" 2>/dev/null
    ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sort > "${BASELINE_DIR}/ports" 2>/dev/null
    lsmod 2>/dev/null | sort > "${BASELINE_DIR}/kmods" 2>/dev/null

    echo $$ > "$PID_FILE"

    # Launch modules under watchdog
    watchdog_start monitor_ssh_logins;        echo -e "  ${GREEN}[✓]${NC} SSH log monitor"
    watchdog_start monitor_all_logins;        echo -e "  ${GREEN}[✓]${NC} Rapid login monitor"
    watchdog_start monitor_wtmp_logins;       echo -e "  ${GREEN}[✓]${NC} WTMP rapid watcher"
    watchdog_start monitor_su_sudo;           echo -e "  ${GREEN}[✓]${NC} SU/Sudo monitor"
    watchdog_start monitor_revshell_proc;     echo -e "  ${GREEN}[✓]${NC} ${BOLD}Reverse-shell hunter (/proc/fd)${NC}"
    watchdog_start monitor_connection_audit;  echo -e "  ${GREEN}[✓]${NC} ${BOLD}Connection auditor (ss/netstat sweep)${NC}"
    watchdog_start monitor_c2_channels;       echo -e "  ${GREEN}[✓]${NC} ${BOLD}C2/exfil channel detector${NC}"
    watchdog_start monitor_beaconing;         echo -e "  ${GREEN}[✓]${NC} Beaconing detector"
    watchdog_start monitor_network;           echo -e "  ${GREEN}[✓]${NC} Network/port monitor"
    watchdog_start monitor_persistence_loop;  echo -e "  ${GREEN}[✓]${NC} Persistence sweep"
    watchdog_start monitor_kernel_modules;    echo -e "  ${GREEN}[✓]${NC} Kernel module monitor"
    watchdog_start monitor_resource_abuse;    echo -e "  ${GREEN}[✓]${NC} Miner / resource abuse monitor"
    watchdog_start anti_tampering;            echo -e "  ${GREEN}[✓]${NC} Anti-tampering"
    watchdog_start generate_daily_report;     echo -e "  ${GREEN}[✓]${NC} Daily report"
    watchdog_start start_file_integrity_monitor; echo -e "  ${GREEN}[✓]${NC} File integrity"
    watchdog_start monitor_pam_alerts;        echo -e "  ${GREEN}[✓]${NC} PAM instant detection"
    watchdog_start pam_self_heal_loop;        echo -e "  ${GREEN}[✓]${NC} PAM self-healer"
    watchdog_loop &
    track_child $!

    echo ""
    epg_ok "  All modules active. PID: $$ | Mode: ${SAFETY_MODE} | Log: ${LOG_FILE}"
    epg_ok "  Owner IPs: ${MY_CURRENT_IPS}"
    echo ""

    send_telegram "🛡️ EPG v${EPG_VERSION} STARTED

Mode: ${SAFETY_MODE^^}
Modules: 16 with watchdog
Reverse-shell hunter: /proc/<pid>/fd inspection
C2 detector: ${#C2_DOMAINS[@]} indicators
Trusted user: ${TRUSTED_USER}" "LOW"

    wait
}

stop_daemon() {
    require_root
    if [[ -f "$PID_FILE" ]]; then
        local dp; dp=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$dp" ]]; then
            local pgid
            pgid=$(ps -o pgid= -p "$dp" 2>/dev/null | tr -d ' ')
            if [[ -n "$pgid" && "$pgid" != "1" ]]; then
                kill -- -"$pgid" 2>/dev/null
                sleep 2
                kill -9 -- -"$pgid" 2>/dev/null
            else
                pkill -P "$dp" 2>/dev/null; sleep 1
                pkill -9 -P "$dp" 2>/dev/null
                kill "$dp" 2>/dev/null; kill -9 "$dp" 2>/dev/null
            fi
        fi
        rm -f "$PID_FILE"
        find "$LOCK_DIR" -name "*.lock" -delete 2>/dev/null
        find "$LOCK_DIR" -name "*.lock.d" -type d -exec rm -rf {} + 2>/dev/null
        # Note: we DON'T call log_event here because DAEMON_MODE=false
        send_telegram "EPG STOPPED" "HIGH"
        epg_warn "EndpointGuard stopped."
    else
        epg_err "No running daemon found."
    fi
}

is_daemon_running() {
    [[ -f "$PID_FILE" ]] || return 1
    local p; p=$(cat "$PID_FILE" 2>/dev/null)
    [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null
}

###############################################################################
# ============== TUI MENU (NO COMMAND ARGUMENTS) ============================
###############################################################################

clear_screen() { printf '\033[H\033[2J'; }

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'BANNER'
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  ███████╗███╗   ██╗██████╗ ██████╗  ██████╗ ██╗███╗   ██╗████████╗ ║
  ║  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝ ║
  ║  █████╗  ██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║██╔██╗ ██║   ██║    ║
  ║  ██╔══╝  ██║╚██╗██║██║  ██║██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║    ║
  ║  ███████╗██║ ╚████║██████╔╝██║     ╚██████╔╝██║██║ ╚████║   ██║    ║
  ║  ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    ║
  ║                                                                   ║
BANNER
    printf "  ║              %sLinux Sentinel  v%s%s                          ║\n" "$BOLD" "$EPG_VERSION" "$NC$CYAN$BOLD"
    echo -e "  ╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status_bar() {
    local status_str
    if is_daemon_running; then
        status_str="${GREEN}● RUNNING${NC}"
    else
        status_str="${RED}○ STOPPED${NC}"
    fi
    echo -e "  Status: ${status_str}    Mode: ${BOLD}${SAFETY_MODE^^}${NC}    User: ${CYAN}${TRUSTED_USER:-<not set>}${NC}"
    echo ""
}

prompt() {
    local msg="$1" default="${2:-}"
    local reply
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${CYAN}${msg}${NC} [${default}]: ")" reply
        echo "${reply:-$default}"
    else
        read -rp "$(echo -e "${CYAN}${msg}${NC}: ")" reply
        echo "$reply"
    fi
}

press_enter() {
    echo ""
    read -rp "$(echo -e "${DIM}Press Enter to continue...${NC}")" _
}

###############################################################################
# ============== SETUP WIZARD ===============================================
###############################################################################

setup_wizard() {
    require_root
    init_directories_silent
    clear_screen
    print_banner
    echo -e "${BOLD}${MAGENTA}First-time setup wizard${NC}\n"
    epg_info "EndpointGuard works without configuration, but a few details help"
    epg_info "prevent self-lockout and enable Telegram alerts."
    echo ""

    # ----- Detect sensible defaults -----
    local default_user="${SUDO_USER:-${USER:-$(logname 2>/dev/null)}}"
    [[ "$default_user" == "root" || -z "$default_user" ]] && \
        default_user=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1; exit}' /etc/passwd 2>/dev/null)

    local detected_ips
    detected_ips=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '^127\.' | tr '\n' ' ')
    local ssh_ip=""
    [[ -n "${SSH_CLIENT:-}" ]] && ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    [[ -n "$ssh_ip" ]] && detected_ips="$detected_ips $ssh_ip"
    detected_ips=$(echo "$detected_ips" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')

    # Detect primary subnet
    local default_net=""
    local first_ip
    first_ip=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '^127\.' | head -1)
    if [[ -n "$first_ip" ]]; then
        default_net=$(echo "$first_ip" | cut -d. -f1-3).0/24
    fi

    # ----- Trusted user -----
    epg_info "1) Your user account (so EPG never locks you out)"
    TRUSTED_USER=$(prompt "   Trusted username" "${TRUSTED_USER:-$default_user}")

    # ----- Trusted IPs -----
    echo ""
    epg_info "2) Trusted IP addresses (your current IPs are pre-filled)"
    TRUSTED_IPS=$(prompt "   Trusted IPs (space-separated)" "${TRUSTED_IPS:-$detected_ips}")

    # ----- Trusted networks -----
    echo ""
    epg_info "3) Trusted networks (e.g. your LAN — auto-detected)"
    TRUSTED_NETWORKS=$(prompt "   Trusted networks (CIDR, space-sep)" "${TRUSTED_NETWORKS:-$default_net}")

    # ----- Safety mode -----
    echo ""
    epg_info "4) Safety mode"
    echo -e "    ${GREEN}1) monitor${NC}  — alert only (zero risk; recommended first run)"
    echo -e "    ${YELLOW}2) moderate${NC} — alert + auto-block brute-force IPs"
    echo -e "    ${RED}3) active${NC}   — full auto-response (kill + block + quarantine)"
    local mode_choice
    mode_choice=$(prompt "   Choose 1/2/3" "3")
    case "$mode_choice" in
        1) SAFETY_MODE="monitor" ;;
        2) SAFETY_MODE="moderate" ;;
        *) SAFETY_MODE="active" ;;
    esac

    # ----- Telegram (optional) -----
    echo ""
    epg_info "5) Telegram alerts (optional — press Enter to skip)"
    local want_tg
    want_tg=$(prompt "   Configure Telegram? (y/N)" "n")
    if [[ "$want_tg" =~ ^[Yy] ]]; then
        TELEGRAM_BOT_TOKEN=$(prompt "   Bot token" "$TELEGRAM_BOT_TOKEN")
        TELEGRAM_CHAT_ID=$(prompt "   Chat ID" "$TELEGRAM_CHAT_ID")
    fi

    save_config
    echo ""
    epg_ok "✓ Configuration saved to: ${CONFIG_FILE}"
    epg_ok "✓ Trusted user:     ${TRUSTED_USER}"
    epg_ok "✓ Trusted IPs:      ${TRUSTED_IPS}"
    epg_ok "✓ Trusted networks: ${TRUSTED_NETWORKS}"
    epg_ok "✓ Safety mode:      ${SAFETY_MODE}"
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]]; then
        epg_ok "✓ Telegram:         configured"
    fi
    press_enter
}

###############################################################################
# ============== MENU ACTIONS ===============================================
###############################################################################

action_start() {
    clear_screen; print_banner
    if is_daemon_running; then
        epg_warn "EndpointGuard is already running."
        press_enter; return
    fi
    if [[ -z "$TRUSTED_USER" ]]; then
        epg_warn "First-time setup needed."
        setup_wizard
    fi
    epg_info "Starting EndpointGuard daemon..."
    setsid bash "$0" __daemon_run </dev/null >/dev/null 2>&1 &
    disown
    sleep 2
    if is_daemon_running; then
        epg_ok "✓ Daemon started (PID: $(cat "$PID_FILE" 2>/dev/null))"
    else
        epg_err "✗ Daemon failed to start. Check: ${LOG_FILE}"
    fi
    press_enter
}

action_stop() {
    clear_screen; print_banner
    if ! is_daemon_running; then
        epg_warn "EndpointGuard is not running."
        press_enter; return
    fi
    epg_info "Stopping daemon..."
    stop_daemon
    press_enter
}

action_restart() {
    clear_screen; print_banner
    epg_info "Restarting daemon..."
    if is_daemon_running; then
        stop_daemon
        sleep 2
    fi
    setsid bash "$0" __daemon_run </dev/null >/dev/null 2>&1 &
    disown
    sleep 2
    if is_daemon_running; then
        epg_ok "✓ Daemon restarted (PID: $(cat "$PID_FILE" 2>/dev/null))"
    else
        epg_err "✗ Restart failed."
    fi
    press_enter
}

action_status() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}Status${NC}\n"
    echo -e "  Version:   ${BOLD}${EPG_VERSION}${NC}"
    echo -e "  Mode:      ${BOLD}${SAFETY_MODE^^}${NC}"
    echo -e "  Lock:      $(command -v flock &>/dev/null && echo "${GREEN}flock${NC}" || echo "${YELLOW}mkdir${NC}")"
    echo -e "  inotify:   $(command -v inotifywait &>/dev/null && echo "${GREEN}yes${NC}" || echo "${YELLOW}no${NC}")"
    echo -e "  conntrack: $(command -v conntrack &>/dev/null && echo "${GREEN}yes${NC}" || echo "${YELLOW}no${NC}")"
    echo -e "  ss kill:   $(command -v ss &>/dev/null && echo "${GREEN}yes${NC}" || echo "${RED}no${NC}")"
    if is_daemon_running; then
        local p; p=$(cat "$PID_FILE")
        local ch; ch=$(pgrep -P "$p" 2>/dev/null | wc -l)
        echo -e "  Daemon:    ${GREEN}● RUNNING${NC} (PID ${p}, ${ch} children)"
        echo -e "  Load:      $(awk '{print $1, $2, $3}' /proc/loadavg)"
    else
        echo -e "  Daemon:    ${RED}○ STOPPED${NC}"
    fi
    echo -e "  User:      ${CYAN}${TRUSTED_USER}${NC}"
    echo -e "  IPs:       ${TRUSTED_IPS}"
    echo -e "  Networks:  ${TRUSTED_NETWORKS}"
    echo ""
    if [[ -s "$BLOCKED_FILE" ]]; then
        local bc; bc=$(wc -l < "$BLOCKED_FILE")
        echo -e "  ${RED}Blocked IPs (${bc}):${NC}"
        while IFS='|' read -r ip _ reason; do
            [[ -z "$ip" ]] && continue
            echo -e "    ${RED}✗${NC} ${ip} (${reason})"
        done < "$BLOCKED_FILE" | head -20
    else
        echo -e "  Blocked IPs: ${GREEN}0${NC}"
    fi
    if [[ -s "${QUARANTINE_DIR}/quarantine.log" ]]; then
        local qc; qc=$(wc -l < "${QUARANTINE_DIR}/quarantine.log")
        echo -e "  Quarantine: ${RED}${qc}${NC} files"
    else
        echo -e "  Quarantine: ${GREEN}0${NC} files"
    fi
    if [[ -s "$JAIL_REGISTRY" ]]; then
        echo -e "  Jailed:    ${RED}$(wc -l < "$JAIL_REGISTRY")${NC} users"
    fi
    if [[ -f "$LOG_FILE" ]]; then
        local total crit
        total=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
        crit=$(grep -c "CRITICAL" "$LOG_FILE" 2>/dev/null || echo 0)
        echo -e "  Events:    ${total} total | ${RED}${crit} critical${NC}"
    fi
    press_enter
}

action_view_logs() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}View logs${NC}\n"
    echo "  1) Recent (last 50 lines)"
    echo "  2) Critical only"
    echo "  3) High + Critical"
    echo "  4) Logins"
    echo "  5) Blocked IPs"
    echo "  6) Quarantined files"
    echo "  7) Severed connections"
    echo "  0) Back"
    echo ""
    local choice
    choice=$(prompt "Choose")
    echo ""
    case "$choice" in
        1) [[ -f "$LOG_FILE" ]] && tail -50 "$LOG_FILE" || epg_warn "No logs." ;;
        2) [[ -f "$LOG_FILE" ]] && grep CRITICAL "$LOG_FILE" | tail -50 || epg_warn "No logs." ;;
        3) [[ -f "$LOG_FILE" ]] && grep -E "(CRITICAL|HIGH)" "$LOG_FILE" | tail -50 || epg_warn "No logs." ;;
        4) [[ -f "$LOG_FILE" ]] && grep -iE "(LOGIN|session|Accepted|Failed)" "$LOG_FILE" | tail -50 || epg_warn "No logs." ;;
        5) if [[ -s "$BLOCKED_FILE" ]]; then
               while IFS='|' read -r ip ts reason; do
                   echo -e "  ${RED}${ip}${NC}   ${reason}   (at $(date -d @"$ts" 2>/dev/null || echo "?"))"
               done < "$BLOCKED_FILE"
           else epg_ok "No blocked IPs."; fi ;;
        6) if [[ -s "${QUARANTINE_DIR}/quarantine.log" ]]; then
               while IFS='|' read -r ts orig dest hash reason; do
                   echo -e "  ${MAGENTA}${reason}${NC}: ${orig} → $(basename "$dest")"
               done < "${QUARANTINE_DIR}/quarantine.log"
           else epg_ok "No quarantined files."; fi ;;
        7) [[ -s "$KILLED_CONNS" ]] && tail -30 "$KILLED_CONNS" || epg_ok "No connections severed." ;;
        0) return ;;
        *) epg_err "Invalid choice." ;;
    esac
    press_enter
}

action_block_ip() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}Block IP${NC}\n"
    local ip
    ip=$(prompt "IP to block")
    [[ -z "$ip" ]] && { epg_err "No IP provided."; press_enter; return; }
    DAEMON_MODE=true   # so safe_block_ip can log
    safe_block_ip "$ip" "manual"
    DAEMON_MODE=false
    epg_ok "Block requested for ${ip} (mode: ${SAFETY_MODE})"
    press_enter
}

action_unblock_ip() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}Unblock IP${NC}\n"
    local ip
    ip=$(prompt "IP to unblock")
    [[ -z "$ip" ]] && { epg_err "No IP provided."; press_enter; return; }
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
    iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
    iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null
    iptables -D FORWARD -d "$ip" -j DROP 2>/dev/null
    sed -i "/^ALL: ${ip}$/d" /etc/hosts.deny 2>/dev/null
    sed -i "/^${ip}|/d" "$BLOCKED_FILE" 2>/dev/null
    epg_ok "Unblocked: ${ip}"
    press_enter
}

action_test_telegram() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}Telegram test${NC}\n"
    if [[ -z "$TELEGRAM_BOT_TOKEN" ]]; then
        epg_err "Telegram not configured. Use the Setup option."
        press_enter; return
    fi
    local r
    r=$(curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=EPG Test ✅ $(date '+%H:%M:%S') $(hostname)" 2>&1)
    if echo "$r" | grep -q '"ok":true'; then
        epg_ok "✓ Telegram test message sent"
    else
        epg_err "✗ Failed: ${r}"
    fi
    press_enter
}

action_run_scan() {
    clear_screen; print_banner
    echo -e "${CYAN}${BOLD}On-demand security scan${NC}\n"
    require_root
    DAEMON_MODE=true
    init_directories_silent
    detect_my_ips
    epg_info "[1/4] Scanning for active reverse shells via /proc/<pid>/fd ..."
    local rs_count=0
    for pid in /proc/[0-9]*; do
        pid=$(basename "$pid")
        local result
        result=$(inspect_pid_for_revshell "$pid")
        if [[ -n "$result" ]]; then
            rs_count=$((rs_count + 1))
            IFS='|' read -r rs_pid rs_user rs_exe rs_remote rs_cmd <<< "$result"
            echo -e "  ${RED}✗ REVERSE SHELL${NC} pid=${rs_pid} user=${rs_user} → ${rs_remote}"
            echo -e "    ${DIM}exe=${rs_exe}${NC}"
            echo -e "    ${DIM}cmd=$(echo "$rs_cmd" | head -c 200)${NC}"
            local rs_ip="${rs_remote%:*}" rs_port="${rs_remote##*:}"
            safe_kill_process "$rs_pid" "$rs_user" "ondemand_revshell"
            kernel_kill_conn "$rs_ip" "$rs_port"
            safe_block_ip "$rs_ip" "ondemand_revshell"
        fi
    done
    [[ "$rs_count" -eq 0 ]] && epg_ok "  ✓ No reverse shells found."

    epg_info "[2/5] Auditing every active connection (ss/netstat sweep) ..."
    local audit_hits
    audit_hits=$(audit_connections_once "no" 2>/dev/null)
    if [[ "${audit_hits:-0}" -gt 0 ]]; then
        epg_err "  ✗ Killed/blocked ${audit_hits} suspicious connection(s)"
    else
        epg_ok "  ✓ No suspicious connections."
    fi

    epg_info "[3/5] Scanning processes for C2 indicators ..."
    local c2_count=0
    for pid in /proc/[0-9]*; do
        pid=$(basename "$pid")
        [[ ! -f "/proc/$pid/cmdline" ]] && continue
        is_own_process "$pid" && continue
        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        [[ -z "$cmdline" ]] && continue
        local user; user=$(stat -c %U "/proc/$pid" 2>/dev/null)
        is_protected_user "$user" && continue
        for ind in "${C2_DOMAINS[@]}"; do
            if echo "$cmdline" | grep -qiF "$ind" 2>/dev/null; then
                c2_count=$((c2_count + 1))
                echo -e "  ${RED}✗ C2 INDICATOR${NC} pid=${pid} user=${user} → ${ind}"
                echo -e "    ${DIM}cmd=$(echo "$cmdline" | head -c 200)${NC}"
                safe_kill_process "$pid" "$user" "ondemand_c2"
                break
            fi
        done
    done
    [[ "$c2_count" -eq 0 ]] && epg_ok "  ✓ No C2 indicators found."

    epg_info "[4/5] Scanning persistence locations ..."
    local persist_hits
    persist_hits=$(scan_persistence_for_payloads)
    if [[ "${persist_hits:-0}" -gt 0 ]]; then
        epg_err "  ✗ Found and cleaned ${persist_hits} persistence payloads"
    else
        epg_ok "  ✓ No persistence trojans found."
    fi

    epg_info "[5/5] Checking sensitive file integrity ..."
    init_file_integrity
    check_file_integrity
    epg_ok "  ✓ File integrity check complete."

    DAEMON_MODE=false
    echo ""
    epg_ok "Scan complete. Reverse shells: ${rs_count} | Connections killed: ${audit_hits:-0} | C2: ${c2_count} | Persistence: ${persist_hits:-0}"
    press_enter
}

action_install_service() {
    clear_screen; print_banner
    require_root
    local sp; sp=$(readlink -f "$0" 2>/dev/null || echo "$0")
    mkdir -p "$INSTALL_DIR"
    cp "$sp" "${INSTALL_DIR}/endpointguard.sh"
    chmod 700 "${INSTALL_DIR}/endpointguard.sh"
    ln -sf "${INSTALL_DIR}/endpointguard.sh" /usr/local/bin/endpointguard 2>/dev/null
    cat > /etc/systemd/system/endpointguard.service <<EOF
[Unit]
Description=EndpointGuard v${EPG_VERSION} — Linux Sentinel
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
    systemctl enable endpointguard 2>/dev/null
    systemctl start endpointguard 2>/dev/null
    epg_ok "✓ Installed as systemd service: endpointguard"
    epg_info "  Use: systemctl {start|stop|status} endpointguard"
    press_enter
}

action_uninstall() {
    clear_screen; print_banner
    require_root
    epg_warn "This will completely remove EndpointGuard."
    local confirm
    confirm=$(prompt "Type YES to confirm")
    [[ "$confirm" != "YES" ]] && { epg_info "Cancelled."; press_enter; return; }
    is_daemon_running && stop_daemon
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
    rm -f /tmp/.epg_hp.log /etc/ssh/banner /usr/local/bin/endpointguard 2>/dev/null
    uninstall_pam_hooks
    rm -rf "$INSTALL_DIR" 2>/dev/null
    epg_ok "✓ EndpointGuard removed."
    press_enter
}

action_restore_quarantine() {
    clear_screen; print_banner
    require_root
    echo -e "${CYAN}${BOLD}Restore from quarantine${NC}\n"
    if [[ ! -s "${QUARANTINE_DIR}/quarantine.log" ]]; then
        epg_ok "Quarantine is empty."
        press_enter; return
    fi
    echo -e "  ${YELLOW}Quarantined files:${NC}"
    local i=0
    declare -a paths_orig paths_dest
    while IFS='|' read -r ts orig dest hash reason; do
        [[ -z "$orig" ]] && continue
        i=$((i + 1))
        paths_orig[i]="$orig"
        paths_dest[i]="$dest"
        printf "  %3d) %s\n        ${DIM}from: %s  reason: %s${NC}\n" "$i" "$orig" "$(basename "$dest")" "$reason"
    done < "${QUARANTINE_DIR}/quarantine.log"
    echo ""
    echo "  Enter a number to restore that file, 'all' to restore everything,"
    echo "  or press Enter to cancel."
    local choice
    choice=$(prompt "Choice")
    if [[ -z "$choice" ]]; then
        epg_info "Cancelled."
        press_enter; return
    fi
    if [[ "$choice" == "all" ]]; then
        local restored=0
        local k
        for ((k=1; k<=i; k++)); do
            local o="${paths_orig[k]}" d="${paths_dest[k]}"
            [[ -z "$o" || -z "$d" ]] && continue
            if [[ -f "$d" ]]; then
                chmod 644 "$d" 2>/dev/null
                mkdir -p "$(dirname "$o")" 2>/dev/null
                mv "$d" "$o" 2>/dev/null && restored=$((restored + 1))
            fi
        done
        : > "${QUARANTINE_DIR}/quarantine.log"
        epg_ok "Restored ${restored} file(s)."
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "$i" ]]; then
        local o="${paths_orig[choice]}" d="${paths_dest[choice]}"
        if [[ -f "$d" ]]; then
            chmod 644 "$d" 2>/dev/null
            mkdir -p "$(dirname "$o")" 2>/dev/null
            if mv "$d" "$o" 2>/dev/null; then
                # Remove that line from the log
                grep -vF "$d" "${QUARANTINE_DIR}/quarantine.log" > "${QUARANTINE_DIR}/quarantine.log.tmp" 2>/dev/null
                mv "${QUARANTINE_DIR}/quarantine.log.tmp" "${QUARANTINE_DIR}/quarantine.log" 2>/dev/null
                epg_ok "Restored: ${o}"
            else
                epg_err "Failed to move ${d} → ${o}"
            fi
        else
            epg_err "Quarantined file no longer exists: ${d}"
        fi
    else
        epg_err "Invalid choice."
    fi
    press_enter
}

action_show_about() {
    clear_screen; print_banner
    cat <<EOF
  ${BOLD}EndpointGuard v${EPG_VERSION} — Linux Sentinel${NC}

  Author:  Prince Gaur (Mr-N1ck)
  GitHub:  https://github.com/Mr-N1ck/EndpointGuard
  License: MIT

  ${BOLD}What's new in v5${NC}
    • Pure interactive TUI (no command-line arguments)
    • First-run setup wizard auto-detects your IPs and user
    • /proc/<pid>/fd reverse-shell hunter — detects bash/sh/dash/zsh/
      python/perl/ruby/php/lua/node/awk/socat/ncat/openssl reverse shells
      regardless of how they were invoked, including base64-encoded payloads
    • C2 channel detector — Discord webhooks, Telegram bots, IRC, ngrok,
      serveo, pastebin/transfer.sh/0x0.st/anonfile, etc.
    • Connection auditor — every ${CONN_AUDIT_INTERVAL}s sweeps every TCP/UDP
      connection via ss/netstat, scores against ${#SUSPICIOUS_PORTS[@]}
      suspicious ports, ${#C2_DOMAINS[@]} C2 domains, dropper-path checks,
      reverse-DNS, htop-equivalent CPU monitoring, and shell-on-stdio
      detection. Auto-kills + severs + blocks at score >=
      ${CONN_RISK_THRESHOLD}/100.
    • Beaconing detector — catches periodic call-home traffic
    • Kernel-level connection severing (ss -K + conntrack)
    • Quarantine system — locks malicious files in ${QUARANTINE_DIR}
    • Deep persistence sweep — cron, systemd, .bashrc, .profile,
      authorized_keys, /etc/profile.d, rc.local, ld.so.preload
    • Watchdog auto-restarts crashed monitor modules
    • Self-healing PAM hook — reinstalls if attacker removes

  ${BOLD}Indicators tracked${NC}: ${#C2_DOMAINS[@]} C2 domains, ${#TRULY_MALICIOUS_PATTERNS[@]} payload patterns, ${#SUSPICIOUS_PORTS[@]} suspicious ports
  ${BOLD}Whitelisted kernel modules${NC}: ${#WHITELISTED_KMODS[@]}
EOF
    press_enter
}

# Live dashboard — keeps re-running the connection auditor in report-only
# mode and prints a colourised, scored table. Like htop but for risky sockets.
action_live_audit() {
    clear_screen; print_banner
    require_root
    DAEMON_MODE=true
    init_directories_silent
    detect_my_ips
    DAEMON_MODE=false
    echo -e "${CYAN}${BOLD}Live connection audit${NC}  ${DIM}(refresh every ${CONN_AUDIT_INTERVAL}s — Ctrl+C to return)${NC}\n"
    trap "echo; echo -e '${YELLOW}Returning to menu...${NC}'; trap - INT; sleep 1; return 2>/dev/null" INT
    while true; do
        clear_screen
        print_banner
        echo -e "${CYAN}${BOLD}Live connection audit${NC}    Threshold: ${BOLD}${CONN_RISK_THRESHOLD}/100${NC}    ${DIM}Ctrl+C → menu${NC}"
        echo ""
        printf "  %-7s %-7s %-12s %-30s %-25s %s\n" "SCORE" "PID" "USER" "BINARY" "REMOTE" "REASONS"
        echo "  ─────────────────────────────────────────────────────────────────────────────────────────────"
        local found=0
        local sweep
        sweep=$(audit_connections_once "yes" 2>/dev/null)
        if [[ -z "$sweep" ]]; then
            echo -e "  ${GREEN}✓ No risky connections detected.${NC}"
        else
            # Sort by score descending
            sweep=$(echo "$sweep" | sort -t'|' -k1,1 -nr)
            local line
            while IFS='|' read -r s pid user exe remote reasons; do
                [[ -z "$s" ]] && continue
                found=$((found + 1))
                local color="$GREEN"
                if   [[ "$s" -ge "$CONN_RISK_THRESHOLD" ]]; then color="$RED"
                elif [[ "$s" -ge 40 ]]; then color="$YELLOW"
                fi
                local short_exe="$exe"
                [[ ${#short_exe} -gt 28 ]] && short_exe="...${short_exe: -25}"
                printf "  ${color}%-7s${NC} %-7s %-12s %-30s %-25s ${DIM}%s${NC}\n" \
                    "${s}" "${pid}" "${user}" "${short_exe}" "${remote}" "${reasons}"
            done <<< "$sweep"
        fi
        echo ""
        echo -e "${DIM}  Lower-than-threshold rows are shown for awareness.${NC}"
        echo -e "${DIM}  Daemon (if running) is auto-killing/blocking score ≥ ${CONN_RISK_THRESHOLD} in real time.${NC}"
        sleep "$CONN_AUDIT_INTERVAL"
    done
    trap - INT
}

action_setup() { setup_wizard; }

###############################################################################
# ============== MAIN MENU ==================================================
###############################################################################

main_menu() {
    while true; do
        clear_screen
        print_banner
        print_status_bar
        echo -e "${BOLD}  Main menu${NC}"
        echo ""
        if is_daemon_running; then
            echo -e "   1) ${YELLOW}Stop${NC} protection daemon"
            echo -e "   2) ${BLUE}Restart${NC} protection daemon"
        else
            echo -e "   1) ${GREEN}Start${NC} protection daemon"
            echo -e "   2) ${BLUE}Restart${NC} protection daemon"
        fi
        echo -e "   3) ${MAGENTA}Run on-demand security scan${NC} (find + remove threats now)"
        echo -e "   4) ${MAGENTA}Live connection audit${NC} (htop-style — see every risky socket)"
        echo -e "   5) Show status"
        echo -e "   6) View logs / blocked / quarantine"
        echo -e "   7) Block IP (manual)"
        echo -e "   8) Unblock IP"
        echo -e "   9) Test Telegram alerts"
        echo -e "  10) Setup / reconfigure"
        echo -e "  11) Install as systemd service (auto-start at boot)"
        echo -e "  12) Restore files from quarantine"
        echo -e "  13) Uninstall completely"
        echo -e "  14) About / what's new"
        echo -e "   0) Exit"
        echo ""
        local choice
        choice=$(prompt "Choose")
        case "$choice" in
            1) if is_daemon_running; then action_stop; else action_start; fi ;;
            2) action_restart ;;
            3) action_run_scan ;;
            4) action_live_audit ;;
            5) action_status ;;
            6) action_view_logs ;;
            7) action_block_ip ;;
            8) action_unblock_ip ;;
            9) action_test_telegram ;;
            10) action_setup ;;
            11) action_install_service ;;
            12) action_restore_quarantine ;;
            13) action_uninstall ;;
            14) action_show_about ;;
            0|q|Q|exit) clear_screen; epg_ok "Stay safe."; exit 0 ;;
            *) ;;
        esac
    done
}

###############################################################################
# ============== ENTRY POINT ================================================
###############################################################################

# Internal flags used by systemd / re-exec
case "${1:-}" in
    __daemon_run)
        # Internal: run as the daemon (called by systemd or our own re-exec)
        load_config
        DAEMON_MODE=true
        start_daemon
        exit $?
        ;;
    __stop)
        load_config
        stop_daemon
        exit $?
        ;;
esac

# All other invocations open the menu
load_config
init_directories_silent
require_root
main_menu
