---
name: "🐛 Bug Report"
about: Report a bug, detection failure, or runtime issue in EndpointGuard
title: "[BUG] <Short description of the problem>"
labels: bug
assignees: ""
---

### 🛡️ EndpointGuard Version
* Run option `13` (About / what's new) in the menu or check `/opt/.epg/endpointguard.sh` version:
* Output of `endpointguard --version` (if applicable):

### 💻 System Information
* **Linux Distribution & Version**: (e.g. Ubuntu 22.04 LTS, Debian 12, Rocky Linux 9)
* **Kernel Version** (`uname -r`):
* **Bash Version** (`bash --version`):
* **Active Security Tools** (e.g. UFW, firewalld, AppArmor, SELinux):

### 📝 Describe the Bug
A clear and concise description of what the bug is, what happened, and what you expected to happen instead.

### 🔄 How to Reproduce
Steps to reproduce the behavior:
1. Setup EndpointGuard in mode `<monitor / moderate / active>`
2. Trigger the action or connection: `...`
3. Notice the failure / incorrect behavior: `...`

### 📊 Relevant Logs
Please paste the end of your EndpointGuard logs (`/opt/.epg/epg.log` or `/opt/.epg/alerts.log`):
```text
<paste logs here>
```

### 📷 Screenshots / TUI Layout
If applicable, add screenshots or copy-pasted ASCII layouts from the terminal to help explain the problem.

### ❓ Additional Context
Add any other context about the problem here (e.g. custom container environments, specific SSH proxy configs).
