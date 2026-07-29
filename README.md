# 🛡️ CryptHaven

[![Version](https://img.shields.io/badge/version-v0.1.0--alpha-blue.svg)](https://github.com/BrannonSD/CryptHaven/releases)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Encryption: AES-256](https://img.shields.io/badge/Encryption-AES--256-green.svg)](#security-architecture)

> **Self-hosted encrypted media vault server — AES-256 zero-knowledge encryption for photos & videos with a responsive local web gallery.**

CryptHaven is a self-hosted media vault server that keeps your personal photos and videos encrypted at rest on your machine while serving a responsive local web gallery across your home LAN.

---

## ✨ Features

- **🗃️ Multi-Vault Launcher UI**: Select, open, or transform any directory into a media vault from a single Windows GUI launcher.
- **🔒 Zero-Knowledge Encryption**: All media is encrypted at rest using AES-256 (Fernet) derived via PBKDF2-HMAC-SHA256 (100,000 iterations).
- **📱 Responsive Local Web Gallery**: Full-screen media viewer with pinch-to-zoom, touch navigation, auto-fading controls, and side-tap zone navigation.
- **🛡️ Configurable DRM & Download Controls**: Toggle media downloading and saving permissions per vault session directly from the launcher.
- **🛑 Single-Instance Safeguard**: Windows Mutex enforcement prevents duplicate server instances with a system-modal warning dialog.
- **🔄 System Tray Integration & Vault Switching**: Switch vaults on the fly or manage server actions from the Windows system tray.
- **📁 Folder Management & Bulk Actions**: Organize media into subfolders with multi-select bulk move, delete, and export.
- **🔍 Search & Duplicate Cleaner**: Search files by name and identify duplicate files to reclaim storage space.
- **☁️ Google Drive Backup**: Optional encrypted cloud backup for vault datasets.
- **🔑 Privacy & Access Security**: Passcode authentication, automatic 15-minute inactivity lock, rate-limiting, and generic login prompts.

---

## 🏗️ Security Architecture

CryptHaven is designed with a strict zero-knowledge security model:

- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique salt per vault.
- **Encryption**: AES-256-CBC with HMAC-SHA256 authentication applied to all media files at rest.
- **Transport Security**: Self-signed TLS certificates for local HTTPS.
- **Web Security**: Secure HTTP headers (CSP, HSTS, X-Frame-Options), rate limiting against brute-force attacks, and session token authentication.

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
   Navigate to `https://localhost:8443` or `http://localhost:8080`.

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
