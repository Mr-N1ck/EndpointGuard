# 📋 Changelog

All notable changes to EndpointGuard are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [4.0.0] — 2024-XX-XX

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
