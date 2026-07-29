# CryptHaven Vault Directory

This directory is where CryptHaven stores all encrypted media data.

**On first launch**, the server will automatically create:
- `vault_salt.bin` — Random cryptographic salt for key derivation
- `vault_index.json` — Encrypted file index (AES-256)

**The `data/` subdirectory** stores all encrypted media files (`enc_*.enc`).

> ⚠️ **Do not commit vault data to version control.**  
> The `.gitignore` is configured to exclude all sensitive vault files.
