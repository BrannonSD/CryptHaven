# 🛡️ CryptHaven

[![Version](https://img.shields.io/badge/version-v0.3.1--alpha-blue.svg)](https://github.com/BrannonSD/CryptHaven/releases)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Encryption: AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg)](#security-architecture)
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-green.svg)](#security-architecture)

> **Self-hosted encrypted media vault server — password-protected AES-256-GCM encryption for photos and videos with a responsive local web gallery.**

CryptHaven is a self-hosted media vault server that keeps your personal photos and videos encrypted at rest on your machine while serving a responsive local web gallery across your home LAN.

---

## ✨ Features

- **🗃️ Multi-Vault Launcher UI**: Select, open, or transform any directory into a media vault from a single Windows GUI launcher.
- **📶 Reliable LAN Discovery**: Wi-Fi and Ethernet listeners ignore Cloudflare WARP and other CGNAT tunnel addresses, bind every detected private LAN address, and keep generated TLS certificates synchronized with those addresses.
- **🔒 Encrypted at Rest**: All media is encrypted using AES-256-GCM with Argon2id key derivation and a DEK/KEK key architecture.
- **📱 Responsive Local Web Gallery**: Full-screen media viewer with pinch-to-zoom, touch navigation, auto-fading controls, and side-tap zone navigation.
- **🛡️ Configurable DRM & Download Controls**: Toggle media downloading and saving permissions per vault session directly from the launcher.
- **🔄 System Tray Integration & Vault Switching**: Switch vaults on the fly or manage server actions from the Windows system tray.
- **📁 Folder Management & Bulk Actions**: Organize media into subfolders with multi-select bulk move, delete, and export.
- **🔍 Search & Duplicate Cleaner**: Search files by name and identify duplicate files to reclaim storage space.
- **🩺 Vault Integrity & Repair**: Inventory missing media, missing thumbnails, orphaned ciphertext, unexpected data entries, and identifier conflicts with conservative, recovery-backed repair actions.
- **☁️ Google Drive Backup**: Optional encrypted cloud backup for vault datasets.
- **🔑 Privacy & Access Security**: Passcode authentication, CSRF protection, automatic 15-minute inactivity lock, rate-limiting, and HttpOnly/Secure/SameSite session cookies.

---

## 🏗️ Security Architecture

CryptHaven is designed to protect vault contents at rest while the vault is locked. It is not a zero-knowledge service: the local server receives the password and holds decrypted keys and media while serving an unlocked vault.

- **Key Derivation**: Argon2id (time_cost=3, memory_cost=64MB, parallelism=4) with unique 256-bit salt per vault.
- **Key Architecture**: A versioned, atomically replaced DEK/KEK envelope keeps password changes recoverable without re-encrypting media.
- **Encryption**: AES-256-GCM authenticated encryption for all media files at rest, with v3 associated data binding ciphertext to its index/media identifier.
- **Transport Security**: Self-signed TLS 1.2+ certificates with HSTS for local HTTPS. HTTP automatically redirects to HTTPS.
- **Web Security**: CSRF tokens, secure HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), rate limiting, HttpOnly/Secure/SameSite cookies.
- **Path Traversal Protection**: All file-serving endpoints use canonicalized path validation.

*Note: CryptHaven is designed for trusted local-LAN use and should not be directly exposed to the public internet. Its automatically generated self-signed TLS certificate encrypts traffic but does not provide publicly trusted server identity; install/trust the intended certificate before relying on it against an active LAN attacker.*

---

## 🚀 Quick Start

### Executable Download (Windows)
Download pre-built standalone binaries from the **[Releases](https://github.com/BrannonSD/CryptHaven/releases)** section (`CryptHaven-v0.3.1-alpha.exe`).

### Running from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BrannonSD/CryptHaven.git
   cd CryptHaven
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the server:**
   ```bash
   python crypthaven_server.py
   ```

4. **Open in Web Browser:**
   Navigate to `https://localhost:8443`. HTTP requests on port 8080 will automatically redirect to HTTPS.

---

## ⬆️ Upgrading to v0.3.1

CryptHaven v0.3.1 remains backward compatible with both older formats:

- **v1**: Fernet ciphertext with a PBKDF2-derived key.
- **v2**: AES-256-GCM ciphertext without v3 context binding, using separate salt and wrapped-DEK files.

After unlocking a v1 or v2 vault, open **Admin & Statistics** and select **Migrate Vault to Context-Bound v3**. Enter the existing master password when prompted. The migration preserves the v2 data-encryption key, creates a fresh authenticated key envelope, and re-encrypts the index, media, and thumbnails with v3 context binding.

Migration is transactional: replacements are written into a staging directory, authenticated and compared with their plaintext, then committed through a recovery journal. An interruption before the new envelope commit rolls every live path back; an interruption after commit finishes cleanup on the next launch. Internal `.folder_placeholder` records are metadata and are correctly excluded from ciphertext preflight in v0.3.1. CryptHaven still refuses migration if real indexed ciphertext is missing or unindexed ciphertext cannot be assigned a safe context. Nothing is changed in that case.

### Vault integrity and repair

Before migrating a heavily hand-edited vault, open **Admin & Statistics → Vault Integrity & Repair**. The scan is read-only and reports structural discrepancies without decrypting payload content. Missing thumbnail references can be cleared so the gallery regenerates them. Missing media records require explicit selection and typed confirmation. Unindexed ciphertext can be quarantined outside the active `data` directory rather than deleted.

Every repair creates a timestamped `vault_recovery/integrity-*` bundle containing the encrypted pre-repair index and a manifest. When companion ciphertext would otherwise be removed, it is copied into that bundle first. Keep these recovery bundles until you have verified the repaired vault and completed an independent backup.

Keep an independent backup before any bulk cryptographic migration. Do not delete `vault_migration.json` or `.migration-*` entries manually if a migration is interrupted; restart CryptHaven and let recovery complete.

### Recent-vault cleanup

Older one-file Windows builds could save PyInstaller extraction paths such as `%LOCALAPPDATA%\Temp\_MEI123456\vault` as recent vaults. v0.3.0 removes those entries automatically. A fresh GUI launch now starts with an empty recent list until a user selects a real folder; headless mode uses `%USERPROFILE%\Documents\CryptHaven Vault` unless `CRYPTHAVEN_VAULT_DIR` is set.

### Phone and Wi-Fi access

CryptHaven v0.3.1 enumerates RFC1918 Wi-Fi and Ethernet addresses instead of trusting the operating system's default route. This prevents VPN adapters such as Cloudflare WARP (`100.64.0.0/10`) from replacing the real LAN listener. Generated self-signed certificates are automatically rotated when their subject-alternative names no longer cover the active LAN addresses.

Connect the phone to the same trusted Wi-Fi network and open the LAN URL shown by CryptHaven, normally `https://<computer-lan-ip>:8443`. A browser warning is expected for the self-signed certificate. Windows Firewall must allow the exact CryptHaven executable on the active network profile.

---

## ⚙️ Configuration & Flags

Customize CryptHaven using launcher toggles, environment variables, or CLI flags:

- **CLI Arguments**:
  - `--vault-dir <path>`: Directly launch the specified vault directory.
  - `--headless`: Run in headless mode without opening the GUI launcher window.
- **Environment Variables**:
  - `CRYPTHAVEN_PORT`: Custom HTTP port (default `8080`).
  - `CRYPTHAVEN_HTTPS_PORT`: Custom HTTPS port (default `8443`).
  - `CRYPTHAVEN_ALLOW_DOWNLOADS`: Set `true` to default-enable media downloads.
  - `CRYPTHAVEN_ENABLE_SHUTDOWN`: Set `true` to enable remote PC shutdown action.
  - `CRYPTHAVEN_MAX_UPLOAD_MB`: Maximum file upload size in MB (default `128`). Raising this also raises peak memory use because the current AES-GCM media path is not streaming.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Maintained by [BrannonSD](https://github.com/BrannonSD)*
