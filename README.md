# 🛡️ CryptHaven

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Encryption: AES-256](https://img.shields.io/badge/Encryption-AES--256-green.svg)](#security-architecture)

> **Your personal encrypted media vault — zero-knowledge AES-256 encryption for photos & videos with a beautiful mobile-first web gallery.**

CryptHaven is a fully self-hosted, secure media server that keeps your photos and videos encrypted at rest. Access your media through a stunning, glassmorphism-styled web interface on any device in your local network.

---

## ✨ Features

- **🗃️ Multi-Vault Launcher UI**: Select, open, or transform any folder into a media vault from a single executable launcher.
- **🔄 On-the-fly Vault Switching**: Switch between different media vaults directly from the system tray menu without restarting the program.
- **🔒 Zero-Knowledge Encryption**: All media is encrypted at rest using AES-256 Fernet.
- **📱 Mobile-First Web UI**: A beautiful, responsive glassmorphism gallery to view and manage media.
- **📁 Folder Management**: Organize your photos and videos into subfolders.
- **✨ Multi-Select & Bulk Operations**: Easily manage large collections with bulk move, delete, and export.
- **⭐ Star & Favorites**: Quickly access your most important memories.
- **🔍 Search & Sort**: Find media by name, date, or size.
- **🧹 Duplicate Cleaner**: Automatically detect and clean up duplicate files.
- **☁️ Google Drive Backup**: Optional integration for secure, encrypted cloud backups.
- **🔑 Secure Access**: Password change support, session auto-lock, and rate limiting.
- **💻 Windows System Tray Integration**: Manage the server quietly in the background with quick access to browser, cloud backup, and vault switching.

## 🖼️ Screenshots

*Screenshots coming soon!*

## 🏗️ Security Architecture

CryptHaven is built from the ground up with security in mind:

- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique salt.
- **Encryption**: AES-256 (via the `cryptography` Fernet implementation) applied to all media at rest.
- **Transport Security**: Auto-generated self-signed TLS certificates for local HTTPS.
- **Web Security**: Secure HTTP headers (CSP, HSTS, X-Frame-Options), strict rate limiting, and a 15-minute auto-lock timeout.

*Note: CryptHaven is designed for local network usage and should not be exposed directly to the public internet.*

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/BrannonSD/CryptHaven.git
   cd CryptHaven
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the program:**
   ```bash
   python crypthaven_server.py
   ```
   The **CryptHaven Vault Launcher** window will open. From here, you can:
   - Select a previously opened vault from the **Recent Vaults** list.
   - Click **📁 Open Vault...** to select an existing vault directory.
   - Click **➕ Create / Transform...** to transform any folder into a new media vault.

4. **Access the Vault:**
   Open your browser and navigate to `https://localhost:8443` or `http://localhost:8080`.

## ⚙️ Configuration

You can customize CryptHaven's behavior using environment variables or command-line arguments:

- **Command-Line Arguments**:
  - `--vault-dir <path>`: Directly launch the specified vault directory (bypasses launcher UI).
  - `--headless`: Run in headless mode without opening the GUI launcher window.
- **Ports**: 
  - HTTP: `CRYPTHAVEN_PORT` (default `8080`)
  - HTTPS: `CRYPTHAVEN_HTTPS_PORT` (default `8443`)
- **Vault Directory**: `CRYPTHAVEN_VAULT_DIR` — change default storage location for headless mode.
- **Remote Shutdown**: `CRYPTHAVEN_ENABLE_SHUTDOWN=true` to enable remote PC shutdown (default: `false`).
- **Max Upload Size**: `CRYPTHAVEN_MAX_UPLOAD_MB` — maximum file upload size in MB (default: `500`).
- **Auto-Lock Timeout**: The web session will automatically lock after 15 minutes of inactivity.

## 🤝 Contributing

Contributions are welcome! If you have suggestions, bug reports, or feature requests, please open an issue or submit a pull request. For security vulnerabilities, please refer to our [SECURITY.md](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Created by [BrannonSD](https://github.com/BrannonSD)*
