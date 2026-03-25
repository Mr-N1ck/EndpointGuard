# 🤝 Contributing to EndpointGuard

Thank you for your interest in contributing to EndpointGuard! This document
provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

## 📜 Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold this code.

## 🚀 How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/Mr-N1ck/EndpointGuard/issues)
   first
2. Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)
3. Include your OS, Bash version, and relevant logs

### Suggesting Features

1. Use the
   [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md)
2. Explain the use case clearly
3. Consider security implications

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `sudo bash tests/test_basic.sh`
5. Commit with conventional commits:
   `git commit -m "feat: add new detection module"`
6. Push and open a Pull Request

## 💻 Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/EndpointGuard.git
cd EndpointGuard

# Create a test VM (recommended — never test on production!)
# Use Vagrant, Docker, or a cloud VM

# Run in monitor mode for safe testing
sudo bash src/endpointguard.sh start

📏 Coding Standards
Bash Style

    Use [[ ]] for conditionals (not [ ])
    Quote all variables: "$variable" not $variable
    Use local for function variables
    Add error handling with 2>/dev/null where appropriate
    Follow existing code style and patterns

Naming Conventions

    Functions: snake_case (e.g., monitor_ssh_logins)
    Constants: UPPER_SNAKE_CASE (e.g., MAX_FAILED_LOGINS)
    Local variables: lower_snake_case

Security Requirements

    NEVER hardcode credentials
    Always validate user input
    Use atomic operations for file locking
    Protect against race conditions
    Test self-lockout prevention

Comments

    Add comments for complex logic
    Document function purpose and parameters
    Explain security-critical decisions

🧪 Testing

Bash

# All tests
sudo bash tests/test_basic.sh
sudo bash tests/test_detection.sh
sudo bash tests/test_safety.sh

# ShellCheck (install: apt install shellcheck)
shellcheck src/endpointguard.sh

📤 Pull Request Process

    Update documentation if needed
    Add tests for new features
    Ensure all tests pass
    Update CHANGELOG.md
    Request review from maintainers

Commit Message Format

text

type: short description

Longer description if needed.

Types: feat, fix, docs, style, refactor, test, chore

🏷️ Issue Labels
Label	Description
bug	Something isn't working
enhancement	New feature request
security	Security-related issue
documentation	Documentation improvement
good first issue	Good for newcomers
help wanted	Extra attention needed

Thank you for helping make EndpointGuard better! 🛡️

text


---

### **FILE 4: `SECURITY.md`**

```markdown
# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 4.0.x   | ✅ Active support  |
| 3.x     | ❌ No longer supported |
| < 3.0   | ❌ No longer supported |

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

### How to Report

1. **Email:** Send details to the author via
   [LinkedIn](https://www.linkedin.com/in/mr-n1ck/) direct message
2. **GitHub:** Use the
   [Security Vulnerability](.github/ISSUE_TEMPLATE/security_vulnerability.md)
   template (private)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Release:** Within 2 weeks for critical issues

### Responsible Disclosure

Please allow reasonable time for fixes before public disclosure.
We credit all reporters (unless anonymity is requested).

## Security Design Principles

EndpointGuard follows these security principles:

1. **Least Privilege:** Only requests necessary permissions
2. **Defense in Depth:** Multiple detection layers
3. **Fail Safe:** Monitor mode is the default — no actions without
   explicit configuration
4. **Self-Protection:** Anti-tampering and integrity checks
5. **No Persistence of Secrets:** Credentials are never stored in logs
6. **Atomic Operations:** Race condition prevention with flock
7. **Crash Recovery:** Automatic cleanup of jailed users on restart
