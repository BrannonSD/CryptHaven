# CryptHaven Vault Directory

This directory is a **sample vault location**, not a location the application always uses. The GUI can select another folder, and headless mode uses the configured `--vault-dir` / `CRYPTHAVEN_VAULT_DIR` location or the user's default documents vault. Keep the contents of any real vault private.

## Fresh vaults (v3)

After choosing an **empty vault directory** and initializing it with a master password, the current implementation creates:

- `vault_key_envelope.json` — versioned, Argon2id-protected wrapped data-encryption key, including the per-vault KDF salt. **Fresh v3 vaults do not create `vault_salt.bin`.**
- `vault_index.json` — authenticated, AES-256-GCM encrypted index bound to its `index` context.
- `data/` — encrypted media and thumbnails (`enc_*.enc`) as content is added.

At runtime the app can create `vault_cert.pem` and `vault_key.pem` for its self-signed local HTTPS endpoint. If an operation needs migration or integrity recovery, it may also create `vault_migration.json`, `.migration-*` working directories, or `vault_recovery/` bundles. **Do not delete or rename them to force a restart**; follow the documented recovery flow.

## Older vaults

Legacy v1/v2 formats can contain `vault_salt.bin` and, for v2, `vault_dek.bin`; these are **legacy files, not the current initialization format**. The authenticated migration creates the v3 envelope and context-bound ciphertext. See the root [README](../README.md) and [security notes](../SECURITY.md) before migration.

> **Never commit vault material.** This repository's `.gitignore` excludes the expected sensitive paths **under this sample `vault/` directory**; it does not protect arbitrarily selected vault folders outside that path. Keep a separate, private backup, and do not use Git as a vault backup system.
