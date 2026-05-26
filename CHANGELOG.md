# 📋 Changelog

All notable changes to EndpointGuard are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [5.0.0] — 2026-05-27

### 🚀 Added — Linux Sentinel & Proactive Threat Hunting
- **Pure Interactive TUI Menu** — zero-argument, user-friendly menu interface that handles all operations.
- **First-Run Setup Wizard** — auto-detects owner IP, SSH connection, and local subnets to write config to a separate file, eliminating manual script edits.
- **Proactive Reverse-Shell Hunter** — inspects `/proc/<pid>/fd` to match sockets to shell interpreters, bypassing all command obfuscations.
- **C2 & Exfiltration Channel Detector** — monitors connection destinations and file changes for Discord webhooks, Telegram bots, `ngrok`, `serveo`, paste sites, etc.
- **Outbound Connection Beaconing Detector** — identifies periodic calls to C2 endpoints by measuring interval variance over a sliding window.
- **Active Forensic Quarantine** — moves threat files to a secure directory, strips execution permissions (`chmod 000`), and removes file immunities to preserve forensics safely.
- **Kernel-Level Socket Termination** — uses `ss -K` and `conntrack -D` to drop live attacker TCP sessions instantly at the packet layer.
- **Deep Persistence Sweep** — proactively sweeps and cleans backdoors/tunnels inside cron, systemd, `.bashrc`, and SSH `authorized_keys`.
- **Self-Healing PAM Hook** — automatically reinstalls the PAM login trigger if an attacker deletes it from config paths.
- **Watchdog Module** — monitors EPG threads and automatically restarts any module if killed or crashed.
- **Auditd Integration** — optional hook for kernel-level `execve` auditing.

### 🔧 Improved
- **Clean Configuration Layout** — all logs, config, bans, and quarantine databases structured under `/opt/.epg/`.
- **Optimized Resources** — adaptive scans that automatically back off under heavy system CPU load (~25 MB memory footprint).
- **Safety Gating** — safety modes (`monitor`, `moderate`, `active`) configurable directly from the TUI.

## [4.0.0] — 2026-03-25

### 🚀 Added — Instant Intrusion Response
- **PAM hook** for instant detection of ALL login methods (SSH, console,
  su, VNC, RDP)
- **Rapid login detection** with 2-3 second response time
- **Session-specific blocking** — never harms owner sessions
- **Trusted account compromise detection** — honeypot redirect for
  attackers using stolen credentials
- **WTMP rapid watcher** for non-SSH login detection
- **Auto-detect owner IP** at startup to prevent self-lockout
- **Multi-method detection** covering 11+ login vectors

### 🔧 Improved
- **Atomic locking** with `flock` (no TOCTOU race conditions)
- **Event-driven file monitoring** with `inotifywait` (automatic fallback
  to polling)
- **Multi-format log parsing** (Debian/RHEL/journalctl JSON)
- **Crash-safe honeypot jail** with auto-recovery on startup
- **Process group management** — no orphaned processes
- **Resource-aware scanning** with adaptive intervals and load throttling

### 🛡️ Security
- Owner IP auto-detection prevents self-lockout
- Session-specific actions never affect trusted sessions
- Crash recovery ensures no user is permanently jailed
- Atomic file operations prevent data corruption

## [3.0.0] — 2024-XX-XX

### Added
- Initial multi-module security monitoring
- SSH brute force detection
- Basic honeypot deployment
- Telegram alerting system
- Three safety modes (monitor/moderate/active)

## [2.0.0] — 2024-XX-XX

### Added
- File integrity monitoring
- Network port scanning
- Process monitoring
- Persistence detection

## [1.0.0] — 2024-XX-XX

### Added
- Initial release
- Basic SSH monitoring
- IP blocking
