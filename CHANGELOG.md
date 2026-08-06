# Changelog

## v0.3.1-alpha - 2026-08-05

### Fixed

- Excluded intentional folder-placeholder metadata from v1/v2 migration ciphertext preflight, preventing false "Indexed ciphertext is missing" failures.
- Fixed phone connectivity when Cloudflare WARP or another CGNAT tunnel was selected instead of the real Wi-Fi/Ethernet interface.
- Added multi-interface RFC1918 listener binding and automatic TLS certificate rotation when LAN address coverage changes.

### Integrity & Recovery

- Added an authenticated Vault Integrity & Repair dashboard for missing media, missing thumbnails, unindexed ciphertext, unexpected data entries, and context conflicts.
- Added safe thumbnail-reference clearing so available media can regenerate thumbnails.
- Added explicitly confirmed removal of unrecoverable missing-media index records.
- Added reversible quarantine for unindexed ciphertext instead of deletion.
- Added timestamped recovery bundles containing the encrypted pre-repair index, a repair manifest, and preserved companion ciphertext where applicable.

### Distribution

- Added regression and repair tests using synthetic vaults only, including WARP-like adapter selection and TLS SAN rotation.
- Updated the Windows executable and version-resource metadata for v0.3.1-alpha.

## v0.3.0-alpha - 2026-08-05

### Security

- Added context-bound v3 AES-256-GCM ciphertext for indexes, media, and thumbnails.
- Added Argon2id key derivation and an authenticated, atomically replaceable DEK/KEK envelope.
- Added strict path, request-size, session-expiry, CSRF, authentication, and migration validation.
- Added journaled v1 and v2 migration with staged authentication, rollback, and restart recovery.
- Added fail-closed migration preflight for missing, unindexed, or context-conflicting ciphertext.

### Fixed

- Removed stale PyInstaller `_MEI...` extraction directories from recent-vault history.
- Stopped packaged GUI builds from creating a vault beside their temporary extracted source.
- Preserved compatibility with v1 Fernet and v2 AES-GCM vaults while exposing migration for both.

### Distribution

- Added a reproducible PyInstaller specification and Windows version-resource metadata.
- Added a packaged self-test covering Tk initialization, AES-GCM round-trip, and tamper rejection.
