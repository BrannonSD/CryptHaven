# 🛡️ CryptHaven

[![Version](https://img.shields.io/badge/version-v0.2.0--alpha-blue.svg)](https://github.com/BrannonSD/CryptHaven/releases)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Encryption: AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg)](#security-architecture)
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-green.svg)](#security-architecture)

> **Self-hosted encrypted media vault server — AES-256-GCM zero-knowledge encryption for photos & videos with a responsive local web gallery.**

CryptHaven is a self-hosted media vault server that keeps your personal photos and videos encrypted at rest on your machine while serving a responsive local web gallery across your home LAN.

---

## ✨ Features

- **🗃️ Multi-Vault Launcher UI**: Select, open, or transform any directory into a media vault from a single Windows GUI launcher.
- **🔒 Zero-Knowledge Encryption**: All media is encrypted at rest using AES-256-GCM with Argon2id key derivation and a DEK/KEK key architecture.
- **📱 Responsive Local Web Gallery**: Full-screen media viewer with pinch-to-zoom, touch navigation, auto-fading controls, and side-tap zone navigation.
- **🛡️ Configurable DRM & Download Controls**: Toggle media downloading and saving permissions per vault session directly from the launcher.
- **🛑 Single-Instance Safeguard**: Windows Mutex enforcement prevents duplicate server instances with a system-modal warning dialog.
- **🔄 System Tray Integration & Vault Switching**: Switch vaults on the fly or manage server actions from the Windows system tray.
- **📁 Folder Management & Bulk Actions**: Organize media into subfolders with multi-select bulk move, delete, and export.
- **🔍 Search & Duplicate Cleaner**: Search files by name and identify duplicate files to reclaim storage space.
- **☁️ Google Drive Backup**: Optional encrypted cloud backup for vault datasets.
- **🔑 Privacy & Access Security**: Passcode authentication, CSRF protection, automatic 15-minute inactivity lock, rate-limiting, and HttpOnly/Secure/SameSite session cookies.

---

## 🏗️ Security Architecture

CryptHaven is designed with a strict zero-knowledge security model:

- **Key Derivation**: Argon2id (time_cost=3, memory_cost=64MB, parallelism=4) with unique 256-bit salt per vault.
- **Key Architecture**: DEK/KEK (Data Encryption Key / Key Encryption Key) — password changes are instant and never require re-encrypting media.
- **Encryption**: AES-256-GCM authenticated encryption for all media files at rest.
- **Transport Security**: Self-signed TLS 1.2+ certificates with HSTS for local HTTPS. HTTP automatically redirects to HTTPS.
- **Web Security**: CSRF tokens, secure HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), rate limiting, HttpOnly/Secure/SameSite cookies.
- **Path Traversal Protection**: All file-serving endpoints use canonicalized path validation.

*Note: CryptHaven is designed for local LAN use and should not be directly exposed to the public internet.*

---

## 🚀 Quick Start

### Executable Download (Windows)
Download pre-built standalone binaries from the **[Releases](https://github.com/BrannonSD/CryptHaven/releases)** section (`CryptHaven.exe`).

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

## ⬆️ Upgrading from v0.1.0

CryptHaven v0.2.0 is backward compatible with v0.1.0 vaults. When you open a legacy vault (Fernet/AES-128-CBC), it will unlock normally. To upgrade your vault's encryption to AES-256-GCM, use the **Migrate Vault** option in the admin settings. Migration re-encrypts all media files in-place — make sure you have a backup before proceeding.

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
  - `CRYPTHAVEN_MAX_UPLOAD_MB`: Maximum file upload size in MB (default `500`).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Maintained by [BrannonSD](https://github.com/BrannonSD)*
