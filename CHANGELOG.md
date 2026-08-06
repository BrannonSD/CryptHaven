# Changelog

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
