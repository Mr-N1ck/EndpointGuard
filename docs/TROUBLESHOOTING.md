# 🛠️ Troubleshooting & Diagnostics Manual

This guide helps you diagnose and resolve common issues encountered while deploying or operating **EndpointGuard**.

---

## 🔍 General Diagnostics

If you encounter unexpected behavior, run the built-in diagnostic checks through the TUI:
1. Run `sudo endpointguard`
2. Select Option **`4) Show status`** to inspect daemon health, systemd service states, and kernel socket modules.
3. Select Option **`5) View logs / blocked / quarantine`** to check events live.

---

## ❌ Common Issues & Solutions

### 1. `ss -K` fails or socket killing is not severing sessions
* **Symptoms**: Malicious shell processes are killed, but the TCP socket connection remains open or in `CLOSE_WAIT`, allowing the attacker to re-connect.
* **Cause**: Your kernel lacks `CONFIG_INET_DIAG_DESTROY` or the `ss` utility does not support the socket kill option (`-K`).
* **Resolution**:
  - EndpointGuard automatically falls back to `conntrack -D` to drop the session state. Ensure `conntrack` is installed:
    ```bash
    # Ubuntu/Debian
    sudo apt-get install conntrack ss -y
    
    # RHEL/Rocky Linux/CentOS
    sudo dnf install conntrack-tools -y
    ```
  - Verify that the connection tracking kernel module is loaded:
    ```bash
    sudo modprobe nf_conntrack
    ```

### 2. Lockout protection / Accidentally blocked owner IP
* **Symptoms**: The system blocked your SSH or administrative terminal session.
* **Cause**: Your connection came from a new or dynamic IP address that was not added to the trusted list during the setup wizard.
* **Resolution**:
  - Log in via your cloud provider's console or direct physical terminal (which bypassed IP rules) and run the unblock utility:
    ```bash
    sudo iptables -D INPUT -s <YOUR_BLOCKED_IP> -j DROP
    ```
  - Launch `endpointguard`, select **`7) Unblock IP`**, select your IP, and then add it permanently via Option **`10) Setup / reconfigure`**.

### 3. High CPU usage under heavy payload scanning
* **Symptoms**: The EndpointGuard script consumes high CPU (>10%) during high disk write events.
* **Cause**: Deep file persistence or exfiltration scanner is searching large directories.
* **Resolution**:
  - EndpointGuard includes an **adaptive load throttler**. If system load average exceeds your CPU core count, the daemon doubles its scan sleep intervals automatically.
  - You can manually increase scan intervals in `/opt/.epg/config.conf`:
    ```ini
    SCAN_INTERVAL=5
    ```

### 4. Systemd service fails to start or auto-restart
* **Symptoms**: Selecting Option `11` in the menu installs the service, but it fails to enter a running state.
* **Cause**: Missing execution bits or missing configuration file.
* **Resolution**:
  - Ensure `/opt/.epg/endpointguard.sh` has executable permissions:
    ```bash
    sudo chmod +x /opt/.epg/endpointguard.sh
    ```
  - Inspect the systemd logs:
    ```bash
    sudo journalctl -u endpointguard -n 50 --no-pager
    ```
  - Re-run the configuration wizard (Option `10` in TUI) to ensure `/opt/.epg/config.conf` is properly populated.

### 5. False Positives / Allowed connection is scored as threat
* **Symptoms**: A legitimate user terminal shell, backup script, or network agent is killed.
* **Cause**: A background job is running commands over custom raw TCP sockets.
* **Resolution**:
  - Add the user or connection path to the allowlist using Option **`10) Setup / reconfigure`**.
  - Add specific allowed ports or daemon binaries in the config file (`/opt/.epg/config.conf`).
