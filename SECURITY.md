# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.2.x  | ✅ Active  |
| v0.1.x  | ⚠️ Upgrade recommended — uses legacy Fernet (AES-128-CBC) encryption |

## Encryption Overview

CryptHaven v0.2.0+ uses the following cryptographic primitives:

- **AES-256-GCM** authenticated encryption (via Python `cryptography` library)
- **Argon2id** key derivation (time_cost=3, memory_cost=64MB, parallelism=4)
- **DEK/KEK** key wrapping architecture (password changes do not re-encrypt media)
- **CSRF** token protection on all state-changing endpoints
- **TLS 1.2+** with HSTS for transport security

Legacy v0.1.x vaults using Fernet (AES-128-CBC + HMAC-SHA256) are supported for backward compatibility and can be migrated in-place to v0.2.0 format.

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
- Session token leakage or fixation

### Scope Note
Please note that CryptHaven is designed as a **local-network server**. It is **not** designed for direct exposure to the public internet. Vulnerabilities that require the attacker to have already compromised the host machine or require the server to be exposed to the public internet without a reverse proxy or VPN may be classified as out-of-scope or informational.
