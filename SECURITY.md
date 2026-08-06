# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.3.x  | ✅ Active |
| v0.2.x  | ⚠️ Upgrade recommended — lacks transactional v3 hardening |
| v0.1.x  | ⚠️ Upgrade recommended — uses legacy Fernet (AES-128-CBC) encryption |

## Encryption Overview

CryptHaven v0.3.0+ uses the following cryptographic primitives:

- **AES-256-GCM** authenticated encryption (via Python `cryptography` library)
- **Argon2id** key derivation (time_cost=3, memory_cost=64MB, parallelism=4)
- **Versioned DEK/KEK envelope** with atomic replacement (password changes do not re-encrypt media)
- **Context-bound v3 ciphertexts** that authenticate whether data belongs to the index, a media ID, or a thumbnail ID
- **CSRF** token protection on all state-changing endpoints
- **TLS 1.2+** with HSTS for transport security

Legacy v0.1.x vaults using Fernet (AES-128-CBC + HMAC-SHA256) and v0.2.x vaults using AES-GCM without context binding remain readable. Both can be migrated to v3 through the authenticated admin workflow.

The migration performs a strict preflight before changing live data. Every indexed media and thumbnail ciphertext must exist, every file in the encrypted data directory must have a known index context, and duplicate identifiers may not cross media/thumbnail contexts. CryptHaven then stages and authenticates every v3 replacement before a journaled directory/index/envelope commit. Pre-commit interruptions roll back; post-commit recovery removes obsolete v1/v2 key files and temporary backups. This design intentionally fails closed when ciphertext cannot be migrated unambiguously.

Users should still keep an independent, offline or otherwise separately protected backup before migration. Transactional recovery protects against application interruption; it does not replace disaster recovery for disk failure, filesystem corruption, malware, or operator deletion.

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
CryptHaven is designed as a **trusted local-network server** and is **not** intended for direct public-internet exposure. The running process has access to the password-derived key, DEK, and plaintext while unlocked, so host compromise is outside the at-rest protection model. The default self-signed certificate provides encryption but must be explicitly verified or trusted to resist an active LAN impersonation attack.
