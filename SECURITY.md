# Security Policy

## Supported Versions

Only the latest release of `uncloak` receives active security updates and vulnerability patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

The Uncloak project takes the security of its endpoint inspection engine seriously. If you discover a security vulnerability (such as privilege escalation, memory corruption in packet dissection, or denial of service), please report it responsibly.

**Please do NOT file public GitHub issues for security vulnerabilities.**

Instead, please send an encrypted or direct advisory to:
- **Email:** `security@uncloak.dev` (or via private GitHub Security Advisory)

### What to Include in Your Report:
1. Type of issue (e.g. buffer overrun, unhandled Win32 API exception, BPF bypass).
2. Exact steps to reproduce the vulnerability.
3. Proof-of-concept (PoC) code or PCAP capture if applicable.
4. Target operating system and environment (Windows version, Npcap driver build).

### Response Timeline:
- **Initial Response:** Within 48 hours acknowledging receipt of the advisory.
- **Triage & Status Update:** Within 7 business days with a remediation plan or fix timeline.
- **Public Disclosure:** Coordinated after a patched release is published.
