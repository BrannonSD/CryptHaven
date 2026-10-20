# CryptHaven Vault Directory

This directory is where CryptHaven stores all encrypted media data.

**On first launch**, the server will automatically create:
- `vault_key_envelope.json` — password-wrapped data-encryption key; the 256-bit Argon2 salt is stored in its header
- `vault_index.json` — encrypted file index (AES-256)

Legacy v2 vaults may also contain `vault_salt.bin`; it is read for migration but is not written for a new v3 vault.

**The `data/` subdirectory** stores all encrypted media files (`enc_*.enc`).

> ⚠️ **Do not commit vault data to version control.**  
> The `.gitignore` is configured to exclude all sensitive vault files.
