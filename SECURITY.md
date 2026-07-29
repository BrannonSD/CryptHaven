# Security Policy

## Supported Versions

Currently, the `main` branch of CryptHaven is supported with security updates.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests. 

Instead, report them via GitHub Security Advisories by clicking on the "Security" tab in this repository and selecting "Report a vulnerability".

### Response Timeline
- We will acknowledge receipt of your vulnerability report within 72 hours.
- We will send you regular updates about our progress.
- We will notify you when the vulnerability is fixed and when the fix is released.

### What Constitutes a Vulnerability
- Authentication or authorization bypass
- Cross-site scripting (XSS) or Cross-Site Request Forgery (CSRF) in the web UI
- Weaknesses in the encryption or key derivation implementation
- Path traversal or arbitrary file access

### Scope Note
Please note that CryptHaven is designed as a **local-network server**. It is **not** designed for direct exposure to the public internet. Vulnerabilities that require the attacker to have already compromised the host machine or require the server to be exposed to the public internet without a reverse proxy or VPN may be classified as out-of-scope or informational.
