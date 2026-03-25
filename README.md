<div align="center">

<img src="docs/images/banner.png" alt="EndpointGuard Banner" width="100%">

<br><br>

# 🛡️ EndpointGuard v4.0

### Advanced Endpoint Security with Instant Intrusion Response

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Bash](https://img.shields.io/badge/Built_With-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/Mr-N1ck/EndpointGuard)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Passing-brightgreen?style=for-the-badge)](https://www.shellcheck.net/)
[![Stars](https://img.shields.io/github/stars/Mr-N1ck/EndpointGuard?style=for-the-badge&color=yellow)](https://github.com/Mr-N1ck/EndpointGuard/stargazers)
[![Forks](https://img.shields.io/github/forks/Mr-N1ck/EndpointGuard?style=for-the-badge&color=blue)](https://github.com/Mr-N1ck/EndpointGuard/network/members)
[![Issues](https://img.shields.io/github/issues/Mr-N1ck/EndpointGuard?style=for-the-badge&color=orange)](https://github.com/Mr-N1ck/EndpointGuard/issues)

<br>

> **A zero-dependency, pure Bash endpoint security daemon that detects intrusions in 2-3 seconds, deploys honeypot traps, and provides instant automated response — built for Linux servers and cybersecurity professionals.**

<br>

[📖 Documentation](#-documentation) •
[⚡ Quick Start](#-quick-start) •
[🏗️ Architecture](#%EF%B8%8F-architecture) •
[🎯 Features](#-features) •
[📡 Modules](#-14-security-modules) •
[🤝 Contributing](#-contributing)

<br>

---

<img src="docs/images/demo.gif" alt="EndpointGuard Demo" width="85%">

<br>

*Real-time intrusion detection, honeypot deployment, and instant Telegram alerts*

---

</div>

<br>

## 🔥 Why EndpointGuard?

Most endpoint security tools are **bloated**, require **complex dependencies**, or are **expensive commercial products**. EndpointGuard is different:

| Problem | EndpointGuard Solution |
|---|---|
| ❌ Complex installation | ✅ Single Bash script — zero dependencies |
| ❌ Slow detection (minutes) | ✅ **2-3 second** response time |
| ❌ No self-lockout protection | ✅ Auto-detects owner IPs & sessions |
| ❌ Binary-only, no transparency | ✅ 100% open source, fully auditable |
| ❌ Expensive licenses | ✅ Free forever (MIT License) |
| ❌ Requires agents/frameworks | ✅ Pure Bash — runs on ANY Linux |

<br>

## 🎯 Features

```text
┌─────────────────────────────────────────────────────────────────┐
│                    ENDPOINTGUARD v4.0 FEATURES                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔐 DETECTION              │  ⚡ RESPONSE                      │
│  ─────────────────          │  ──────────────────                │
│  • SSH brute force          │  • Instant IP blocking             │
│  • Reverse shells           │  • Session-specific termination    │
│  • Privilege escalation     │  • Honeypot jail deployment        │
│  • File tampering           │  • Account lockdown                │
│  • Rootkit indicators       │  • Firewall auto-recovery          │
│  • Crypto miners            │  • PAM-level interception          │
│  • Persistence mechanisms   │  • Process group kill              │
│                             │                                    │
│  🛡️ SAFETY                 │  📡 ALERTING                      │
│  ─────────────────          │  ──────────────────                │
│  • 3 safety modes           │  • Real-time Telegram alerts       │
│  • Owner IP auto-detect     │  • Smart cooldown (no spam)        │
│  • Self-lockout prevention  │  • Daily summary reports           │
│  • Trusted user protection  │  • Severity-based urgency          │
│  • Crash-safe recovery      │  • Multi-format log parsing        │
│                             │                                    │
└─────────────────────────────────────────────────────────────────┘
```

<br>

## 🏗️ Architecture

```text
                     ┌──────────────────────┐
                     │   EndpointGuard v4.0  │
                     │    (Process Group)     │
                     └──────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
┌─────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│  DETECTION LAYER  │  │  RESPONSE LAYER  │  │  SAFETY LAYER   │
├──────────────────┤  ├─────────────────┤  ├─────────────────┤
│ SSH Monitor       │  │ IP Blocking      │  │ Owner IP Detect │
│ PAM Hook (instant)│  │ Session Kill     │  │ Trusted Users   │
│ Rapid Login (2s)  │  │ Honeypot Jail    │  │ Self-Lockout    │
│ WTMP Watcher      │  │ Account Lock     │  │  Prevention     │
│ Process Scanner   │  │ FW Recovery      │  │ Crash Recovery  │
│ Network Monitor   │  │ Telegram Alert   │  │ Atomic Locking  │
│ File Integrity    │  │                  │  │ Load Throttling │
│ Persistence Check │  │                  │  │                 │
│ Kernel Monitor    │  │                  │  │                 │
│ Resource Monitor  │  │                  │  │                 │
└──────────────────┘  └─────────────────┘  └─────────────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                     ┌──────────▼───────────┐
                     │    LOG & REPORT       │
                     │  • Atomic file writes │
                     │  • Auto-rotation      │
                     │  • Daily reports      │
                     └──────────────────────┘
```

<br>

## 📡 14 Security Modules

| # | Module | Detection Method | Response Time |
|---|--------|-----------------|---------------|
| 1 | **SSH Login Monitor** | Log tailing (auth.log/secure/journalctl) | ~1 second |
| 2 | **PAM Hook** | Kernel-level PAM interception | **Instant** |
| 3 | **Rapid Login Detector** | `who` polling every 2 seconds | 2-3 seconds |
| 4 | **WTMP Watcher** | `last` command rapid polling | 2-3 seconds |
| 5 | **SU/Sudo Monitor** | Auth log tailing | ~1 second |
| 6 | **Process Scanner** | `/proc` enumeration + pattern matching | Adaptive |
| 7 | **Network Monitor** | `ss` port/connection scanning | Adaptive |
| 8 | **File Integrity** | SHA-256 checksums / inotifywait | Event-driven* |
| 9 | **Persistence Detector** | Cron/SSH keys/systemd monitoring | Adaptive |
| 10 | **Kernel Module Watch** | `lsmod` diffing | Adaptive |
| 11 | **Resource Abuse** | CPU/process monitoring | Adaptive |
| 12 | **Anti-Tampering** | Self-integrity + firewall monitoring | Adaptive |
| 13 | **Honeypot Jail** | Fake environment with activity logging | On-trigger |
| 14 | **Daily Reporter** | Automated summary generation | 24 hours |

> *Event-driven when `inotifywait` is available; falls back to polling automatically.

<br>

## 🔒 Three Safety Modes

```text
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  🟢 MONITOR MODE (Default — Zero Risk)                      │
│  ════════════════════════════════════                        │
│  • Detects everything, blocks NOTHING                        │
│  • Perfect for learning and evaluation                       │
│  • Sends alerts only — no system changes                     │
│                                                              │
│  🟡 MODERATE MODE (Recommended for Production)              │
│  ═════════════════════════════════════════                   │
│  • Everything in Monitor mode PLUS                           │
│  • Auto-blocks brute force IPs                               │
│  • Temporary bans with auto-expiry                           │
│                                                              │
│  🔴 ACTIVE MODE (Full Auto-Response)                        │
│  ════════════════════════════════════                        │
│  • Everything in Moderate mode PLUS                          │
│  • Kills malicious processes instantly                       │
│  • Deploys honeypot jails for intruders                      │
│  • Locks compromised accounts                                │
│  • Session-specific termination                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

<br>

## ⚡ Quick Start

### One-Line Install

```bash
git clone [https://github.com/Mr-N1ck/EndpointGuard.git](https://github.com/Mr-N1ck/EndpointGuard.git) && cd EndpointGuard && sudo bash install.sh
```

### Manual Start

```bash
# Clone the repository
git clone [https://github.com/Mr-N1ck/EndpointGuard.git](https://github.com/Mr-N1ck/EndpointGuard.git)
cd EndpointGuard

# Edit configuration (IMPORTANT — set your details first)
nano src/endpointguard.sh

# Start in monitor mode (safe — no actions taken)
sudo bash src/endpointguard.sh start

# Check status
sudo bash src/endpointguard.sh status

# View logs
sudo bash src/endpointguard.sh logs critical
```

### Configuration

Before running, edit these values in `src/endpointguard.sh`:

```bash
# Safety Mode — start with "monitor" (alerts only, zero risk)
SAFETY_MODE="monitor"

# Telegram Alerts (optional but recommended)
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# Your Identity (CRITICAL — prevents self-lockout)
TRUSTED_USER="your_username"
TRUSTED_IPS="your.server.ip your.home.ip"
TRUSTED_NETWORKS="192.168.1.0/24"
```

> 📖 See `docs/CONFIGURATION.md` for complete setup guide.

<br>

### 📋 All Commands

```bash
sudo bash endpointguard.sh <command>
```

| Command | Description |
|---|---|
| `start` | Start the security daemon |
| `stop` | Stop all monitoring |
| `restart` | Restart the daemon |
| `status` | Show current status and statistics |
| `logs [filter]` | View logs (critical, high, logins, blocked, all) |
| `block <IP>` | Manually block an IP address |
| `unblock <IP>` | Remove an IP block |
| `test` | Test Telegram notification |
| `install` | Install as systemd service (auto-start on boot) |
| `uninstall` | Completely remove EndpointGuard |

<br>

## 🧠 Technical Deep Dive

### Race Condition Prevention

```text
Traditional approach (VULNERABLE):
  1. Check if lockfile exists    ← Another process can
  2. Create lockfile             ← slip in between steps
  3. Do work
  4. Remove lockfile

EndpointGuard approach (SAFE):
  1. flock() — atomic kernel-level lock
  2. Do work
  3. Lock auto-released
  (Falls back to mkdir if flock unavailable — also atomic)
```

### Self-Lockout Prevention

```text
At startup, EndpointGuard automatically detects:
  ✓ All local interface IPs
  ✓ Current SSH session source IP
  ✓ All IPs where trusted user is logged in
  ✓ Configured trusted IPs and networks
  → These IPs are NEVER blocked, even in active mode
```

### Crash-Safe Honeypot Recovery

```text
Before jailing a user:
  1. Register user in jail registry
  2. Backup original .bashrc
  3. Deploy honeypot .bashrc

On startup (after crash):
  1. Read jail registry
  2. Restore all .bashrc backups
  3. Clear registry
  → No user is ever permanently stuck in a jail
```

### Adaptive Resource Management

```text
System Load     Scan Interval Multiplier
─────────────   ─────────────────────────
Normal          1x (base interval)
High (>2x CPU)  2x (slower scanning)
Very High       4x (minimal scanning)

→ EndpointGuard never overloads your server
```

<br>

## 🔍 What Gets Detected

### Malicious Patterns (Auto-Kill in Active Mode)

```text
✗ bash -i >& /dev/tcp/...        (Reverse shells)
✗ rm -rf / --no-preserve-root    (Destructive commands)
✗ dd if=/dev/zero of=/dev/sda    (Disk wiping)
✗ :(){ :|:& };:                  (Fork bombs)
✗ curl ... | bash                (Remote code execution)
✗ export HISTSIZE=0              (Anti-forensics)
✗ python -c 'import socket...'   (Script-based reverse shells)
```

### What's NEVER Flagged (Whitelist)

```text
✓ Standard admin tools (vim, nano, grep, awk, sed...)
✓ Security tools (nmap, metasploit, burpsuite...)
✓ Development tools (python, gcc, docker, git...)
✓ System management (systemctl, apt, yum...)
✓ Your own processes and sessions
```

<br>

## 📊 Alert Examples

### Telegram Alert — Brute Force

```text
🔴 EPG [ACTIVE]

Host: production-server
Time: 2024-01-15 03:42:17
Level: CRITICAL

BRUTE FORCE
IP: 45.33.32.156 | User: root | Attempts: 15
Action: IP blocked for 3600s
```

### Telegram Alert — Compromised Account

```text
🚨 EPG [ACTIVE]

Host: production-server
Time: 2024-01-15 03:42:19
Level: CRITICAL

🚨 SUSPICIOUS LOGIN TO TRUSTED ACCOUNT 🚨
User: admin
IP: 185.220.101.42

⚠️ This IP is NOT in trusted list!
Action: Blocking IP + redirecting to honeypot in 2 seconds
```

### Telegram Alert — Daily Report

```text
ℹ️ EPG [MONITOR]

DAILY REPORT 📊
Mode: monitor | Events: 1,247
Critical: 3 | High: 12 | Blocked: 8
```

<br>

## 🖥️ System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **OS** | Any Linux (kernel 3.x+) | Ubuntu 20.04+ / Debian 11+ / RHEL 8+ |
| **Shell** | Bash 4.0+ | Bash 5.0+ |
| **Privileges**| Root | Root |
| **RAM** | ~10 MB | ~25 MB |
| **CPU** | Negligible | Negligible |
| **Dependencies**| None (pure Bash) | `inotify-tools`, `flock` (auto-detected) |
| **Network** | None required | Internet (for Telegram alerts) |

<br>

## 🧪 Testing

```bash
# Run basic tests
sudo bash tests/test_basic.sh

# Test detection capabilities (safe — uses monitor mode)
sudo bash tests/test_detection.sh

# Test safety mechanisms
sudo bash tests/test_safety.sh
```

<br>

## 📖 Documentation

| Document | Description |
|---|---|
| Installation Guide | Complete setup instructions |
| Configuration Reference | All options explained |
| Architecture Overview | How it works internally |
| Module Reference | Detailed module documentation |
| Safety Modes | Understanding the three modes |
| Troubleshooting | Common issues and solutions |
| Changelog | Version history |

<br>

## 🗺️ Roadmap

- [x] 14 security monitoring modules
- [x] PAM hook instant detection
- [x] Crash-safe honeypot jail
- [x] Atomic locking (flock)
- [x] Event-driven file monitoring
- [x] Adaptive resource management
- [x] Self-lockout prevention
- [ ] Web dashboard (planned v5.0)
- [ ] Cluster mode — multi-server (planned v5.0)
- [ ] YARA rule integration (planned v5.1)
- [ ] MITRE ATT&CK mapping (planned v5.1)
- [ ] Slack/Discord webhook support (planned v4.1)
- [ ] JSON structured logging (planned v4.1)

<br>

## 🤝 Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` before submitting.

```bash
# Fork → Clone → Branch → Code → Test → PR
git checkout -b feature/your-feature
# Make changes
sudo bash tests/test_basic.sh
git commit -m "feat: your feature description"
git push origin feature/your-feature
# Open Pull Request
```

<br>

## 📜 License

This project is licensed under the MIT License — see LICENSE for details.
You are free to use, modify, and distribute this tool for any purpose.

<br>

## ⚠️ Disclaimer

This tool is designed for authorized security monitoring only. Always ensure you have proper authorization before deploying on any system. The author is not responsible for misuse or unauthorized deployment.

<br>

<div align="center">

👨‍💻 **Author**

<img src="https://github.com/Mr-N1ck.png" width="120" style="border-radius: 50%">
<br>

**Prince Gaur** *Cybersecurity Enthusiast & Tool Developer*

<br>

<a href="https://www.linkedin.com/in/mr-n1ck/">
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
</a>
<a href="https://github.com/Mr-N1ck">
  <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
</a>

<br><br>

If EndpointGuard helps you, consider giving it a ⭐

Built with ❤️ for the cybersecurity community
<br>
<img src="https://img.shields.io/badge/Made_in-India_🇮🇳-orange?style=for-the-badge" alt="Made in India">

</div>
