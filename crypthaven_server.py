import os
import sys
import json
import base64
import secrets
import io
import time
import shutil
import string
import hashlib
import threading
import webbrowser
import urllib.parse
import datetime
import mimetypes
import ssl
import socket
import subprocess
import argparse
import ipaddress
import tempfile
import re
from collections import defaultdict
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from PIL import Image, ImageDraw
import pillow_heif
import pystray

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type as Argon2Type

pillow_heif.register_heif_opener()
if sys.stdout is not None and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ---------------------------------------------------------------------------
#  CryptHaven — Encrypted Media Vault Server
#  https://github.com/BrannonSD/CryptHaven
# ---------------------------------------------------------------------------

# ── Configuration ──────────────────────────────────────────────────────────
VERSION = "v0.3.0-alpha"
PORT = int(os.environ.get('CRYPTHAVEN_PORT', 8080))
HTTPS_PORT = int(os.environ.get('CRYPTHAVEN_HTTPS_PORT', 8443))
ALLOW_DOWNLOADS = os.environ.get('CRYPTHAVEN_ALLOW_DOWNLOADS', 'false').lower() == 'true'
ENABLE_REMOTE_SHUTDOWN = os.environ.get('CRYPTHAVEN_ENABLE_SHUTDOWN', 'false').lower() == 'true'
MAX_UPLOAD_BYTES = int(os.environ.get('CRYPTHAVEN_MAX_UPLOAD_MB', 128)) * 1024 * 1024
MAX_REQUEST_METADATA_BYTES = 1024 * 1024
MAX_LOGIN_BODY_BYTES = 16 * 1024
MIN_PASSWORD_LENGTH = 12
SESSION_ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60
MAX_CONCURRENT_KDF_OPERATIONS = 1

# ── Encryption Constants (v2 — AES-256-GCM) ───────────────────────────────
VAULT_FORMAT_VERSION = 3
NONCE_SIZE = 12   # 96-bit nonce for AES-256-GCM (NIST SP 800-38D)
DEK_SIZE = 32     # 256-bit data encryption key
KEK_SALT_SIZE = 32  # 256-bit salt for Argon2id
KEY_ENVELOPE_MAGIC = "CryptHaven-KeyEnvelope"
KEY_ENVELOPE_VERSION = 1
CONTENT_AAD_PREFIX = b"CryptHaven:v3:"
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4



def detect_local_ip():
    """Detect the primary LAN IP address of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'


LOCAL_IP = detect_local_ip()

APP_MUTEX = None
SINGLE_INSTANCE_SOCKET = None


def show_already_running_popup():
    """Display a popup notification when another instance is already active."""
    msg = (
        "CryptHaven is already running!\n\n"
        "Please check your system tray (near the clock) for the blue lock icon 🔒 to access the web gallery or manage settings."
    )
    title = "CryptHaven Already Running"

    if sys.platform == 'win32':
        import ctypes
        # MB_OK (0x0) | MB_ICONWARNING (0x30) | MB_SYSTEMMODAL (0x1000)
        ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30 | 0x1000)
    else:
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            messagebox.showwarning(title, msg, parent=root)
            root.destroy()
        except Exception as e:
            print(f"CryptHaven is already running! (Notice: {e})")


def ensure_single_instance():
    """Ensure only one instance of CryptHaven is running at a time."""
    global APP_MUTEX, SINGLE_INSTANCE_SOCKET
    if sys.platform == 'win32':
        import ctypes
        mutex_name = "Local\\CryptHaven_SingleInstance_Mutex_98a7b3c2"
        APP_MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
        last_error = ctypes.windll.kernel32.GetLastError()
        ERROR_ALREADY_EXISTS = 183

        if last_error == ERROR_ALREADY_EXISTS:
            show_already_running_popup()
            sys.exit(0)
    else:
        import socket
        try:
            SINGLE_INSTANCE_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            SINGLE_INSTANCE_SOCKET.bind(('127.0.0.1', 59483))
        except Exception:
            show_already_running_popup()
            sys.exit(0)

# ── Vault Path Management & Dynamic Resolution ──────────────────────────────
VAULT_FOLDER = ""
DATA_DIR = ""
SALT_PATH = ""
INDEX_PATH = ""
DEK_PATH = ""
KEY_ENVELOPE_PATH = ""
CERT_PATH = ""
KEY_PATH = ""
MIGRATION_JOURNAL_PATH = ""


def set_vault_folder(folder_path: str):
    """Dynamically set the active vault folder and resolve associated paths."""
    global VAULT_FOLDER, DATA_DIR, SALT_PATH, INDEX_PATH, CERT_PATH, KEY_PATH, DEK_PATH
    global KEY_ENVELOPE_PATH, MIGRATION_JOURNAL_PATH
    VAULT_FOLDER = os.path.abspath(folder_path)
    DATA_DIR = os.path.join(VAULT_FOLDER, "data")
    SALT_PATH = os.path.join(VAULT_FOLDER, "vault_salt.bin")
    INDEX_PATH = os.path.join(VAULT_FOLDER, "vault_index.json")
    DEK_PATH = os.path.join(VAULT_FOLDER, "vault_dek.bin")
    KEY_ENVELOPE_PATH = os.path.join(VAULT_FOLDER, "vault_key_envelope.json")
    CERT_PATH = os.path.join(VAULT_FOLDER, "vault_cert.pem")
    KEY_PATH = os.path.join(VAULT_FOLDER, "vault_key.pem")
    MIGRATION_JOURNAL_PATH = os.path.join(VAULT_FOLDER, "vault_migration.json")
    os.makedirs(DATA_DIR, exist_ok=True)
    recover_interrupted_migration()


def atomic_write(path: str, data: bytes, mode: int | None = None):
    """Durably replace one file without exposing a partially written destination."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, 'wb') as temp_file:
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        if mode is not None:
            os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def _migration_paths(token: str) -> dict:
    if len(token) != 32 or any(ch not in string.hexdigits for ch in token):
        raise ValueError("Invalid migration token")
    return {
        "stage": os.path.join(VAULT_FOLDER, f".migration-stage-{token}"),
        "backup_data": os.path.join(VAULT_FOLDER, f".migration-backup-data-{token}"),
        "backup_index": os.path.join(VAULT_FOLDER, f".migration-backup-index-{token}"),
        "backup_envelope": os.path.join(VAULT_FOLDER, f".migration-backup-envelope-{token}"),
    }


def _safe_remove_tree(path: str):
    vault_root = os.path.abspath(VAULT_FOLDER)
    target = os.path.abspath(path)
    if os.path.commonpath([vault_root, target]) != vault_root or target == vault_root:
        raise ValueError("Refusing to remove path outside vault")
    if os.path.isdir(target):
        shutil.rmtree(target)


def recover_interrupted_migration():
    """Finish cleanup or roll back a journaled vault migration after interruption."""
    if not MIGRATION_JOURNAL_PATH or not os.path.exists(MIGRATION_JOURNAL_PATH):
        return
    try:
        with open(MIGRATION_JOURNAL_PATH, 'r', encoding='utf-8') as journal_file:
            journal = json.load(journal_file)
        paths = _migration_paths(journal["token"])
        expected_hash = journal.get("new_envelope_sha256", "")
        envelope_committed = False
        if expected_hash and os.path.exists(KEY_ENVELOPE_PATH):
            with open(KEY_ENVELOPE_PATH, 'rb') as envelope_file:
                envelope_committed = secrets.compare_digest(
                    hashlib.sha256(envelope_file.read()).hexdigest(), expected_hash
                )

        if not envelope_committed:
            if os.path.isdir(paths["backup_data"]):
                if os.path.isdir(DATA_DIR):
                    _safe_remove_tree(DATA_DIR)
                os.replace(paths["backup_data"], DATA_DIR)
            if os.path.exists(paths["backup_index"]):
                os.replace(paths["backup_index"], INDEX_PATH)
            if os.path.exists(paths["backup_envelope"]):
                os.replace(paths["backup_envelope"], KEY_ENVELOPE_PATH)
            elif journal.get("previous_envelope") is False and os.path.exists(KEY_ENVELOPE_PATH):
                os.remove(KEY_ENVELOPE_PATH)
        elif journal.get("remove_legacy_keys") is True:
            for legacy_key_path in (SALT_PATH, DEK_PATH):
                if os.path.exists(legacy_key_path):
                    os.remove(legacy_key_path)

        for cleanup_path in (paths["stage"], paths["backup_data"]):
            _safe_remove_tree(cleanup_path)
        for cleanup_path in (paths["backup_index"], paths["backup_envelope"]):
            if os.path.exists(cleanup_path):
                os.remove(cleanup_path)
        os.remove(MIGRATION_JOURNAL_PATH)
    except Exception as exc:
        raise RuntimeError(f"Vault migration recovery failed: {exc}") from exc


def vault_metadata_state(folder_path: str) -> str:
    """Classify a vault without converting damaged metadata into a new vault."""
    salt = os.path.exists(os.path.join(folder_path, "vault_salt.bin"))
    index = os.path.exists(os.path.join(folder_path, "vault_index.json"))
    dek = os.path.exists(os.path.join(folder_path, "vault_dek.bin"))
    envelope = os.path.exists(os.path.join(folder_path, "vault_key_envelope.json"))
    data_dir = os.path.join(folder_path, "data")
    has_data = os.path.isdir(data_dir) and any(
        os.path.isfile(os.path.join(data_dir, name)) for name in os.listdir(data_dir)
    )

    if index and envelope:
        return "v3"
    if index and salt and dek:
        return "v2"
    if index and salt and not dek and not envelope:
        return "legacy"
    if not any((salt, index, dek, envelope, has_data)):
        return "empty"
    return "damaged"


def is_valid_vault(folder_path: str) -> bool:
    """Check if a directory contains existing CryptHaven vault metadata."""
    if not folder_path or not os.path.isdir(folder_path):
        return False
    return vault_metadata_state(folder_path) in {"legacy", "v2", "v3"}


def initialize_vault_folder(folder_path: str) -> bool:
    """Prepare a directory structure to serve as a CryptHaven vault."""
    try:
        os.makedirs(os.path.join(folder_path, "data"), exist_ok=True)
        return True
    except Exception as e:
        print(f"Error initializing vault folder: {e}")
        return False


def get_config_path() -> str:
    """Get persistent configuration file path for CryptHaven."""
    if sys.platform == "win32":
        base_dir = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base_dir = os.path.expanduser("~/.config")
    config_dir = os.path.join(base_dir, "CryptHaven")
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "config.json")


def default_vault_dir() -> str:
    """Return a stable default that never points inside a PyInstaller extraction."""
    configured = os.environ.get('CRYPTHAVEN_VAULT_DIR')
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    if sys.platform == "win32":
        return os.path.join(os.path.expanduser("~"), "Documents", "CryptHaven Vault")
    return os.path.join(os.path.expanduser("~"), "CryptHaven Vault")


def is_pyinstaller_temp_path(folder_path: str) -> bool:
    """Identify stale one-file extraction paths accidentally saved by older builds."""
    if not isinstance(folder_path, str) or not folder_path.strip():
        return False
    normalized = os.path.normcase(os.path.abspath(os.path.expanduser(folder_path)))
    components = re.split(r"[\\/]", normalized)
    return any(re.fullmatch(r"_mei[0-9a-z_-]+", component, re.IGNORECASE) for component in components)


def load_vault_history() -> list:
    """Load list of recent vault folder paths from config."""
    cfg_path = get_config_path()
    history = []
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                history = data.get("recent_vaults", [])
        except Exception:
            pass

    cleaned_history = []
    for entry in history if isinstance(history, list) else []:
        if not isinstance(entry, str) or not entry.strip() or is_pyinstaller_temp_path(entry):
            continue
        normalized = os.path.abspath(os.path.expanduser(entry))
        if normalized not in cleaned_history:
            cleaned_history.append(normalized)
    if cleaned_history != history:
        save_vault_history(cleaned_history)

    return cleaned_history


def save_vault_history(history: list):
    """Save list of recent vault folder paths to config."""
    cfg_path = get_config_path()
    try:
        data = {}
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data["recent_vaults"] = history
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Failed to save vault history: {e}")


def add_to_vault_history(folder_path: str):
    """Add a vault folder path to the recent vault history."""
    folder_path = os.path.abspath(folder_path)
    if is_pyinstaller_temp_path(folder_path):
        return
    history = load_vault_history()
    if folder_path in history:
        history.remove(folder_path)
    history.insert(0, folder_path)
    history = history[:15]
    save_vault_history(history)


def remove_from_vault_history(folder_path: str):
    """Remove a vault folder path from the recent vault history."""
    folder_path = os.path.abspath(folder_path)
    history = load_vault_history()
    if folder_path in history:
        history.remove(folder_path)
        save_vault_history(history)


def launch_vault_selector_ui() -> str:
    """Open Tkinter Vault Selector GUI for choosing or initializing a vault folder."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except ImportError:
        print("Tkinter GUI not available. Falling back to default vault location.")
        default_dir = default_vault_dir()
        initialize_vault_folder(default_dir)
        return default_dir

    selected_path = {"val": None}

    root = tk.Tk()
    root.title(f"CryptHaven — Vault Launcher ({VERSION})")
    root.geometry("640x480")
    root.minsize(580, 420)
    root.configure(bg="#0f172a")

    if os.path.exists("app_icon.ico"):
        try:
            root.iconbitmap("app_icon.ico")
        except Exception:
            pass

    # Center window on screen and bring to front
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")
    root.lift()
    root.attributes('-topmost', True)
    root.after_idle(root.attributes, '-topmost', False)

    # Header Frame
    header_frame = tk.Frame(root, bg="#0f172a", pady=15, padx=20)
    header_frame.pack(fill="x")

    title_label = tk.Label(
        header_frame,
        text=f"🛡️ CryptHaven Vault Launcher ({VERSION})",
        font=("Segoe UI", 16, "bold"),
        fg="#38bdf8",
        bg="#0f172a"
    )
    title_label.pack(anchor="w")

    subtitle_label = tk.Label(
        header_frame,
        text="Select an existing media vault or transform a folder into a vault",
        font=("Segoe UI", 9),
        fg="#94a3b8",
        bg="#0f172a"
    )
    subtitle_label.pack(anchor="w", pady=(2, 0))

    # Content Frame
    content_frame = tk.Frame(root, bg="#0f172a", padx=20)
    content_frame.pack(fill="both", expand=True)

    history_label = tk.Label(
        content_frame,
        text="Recent Vaults",
        font=("Segoe UI", 11, "bold"),
        fg="#f8fafc",
        bg="#0f172a"
    )
    history_label.pack(anchor="w", pady=(5, 5))

    list_frame = tk.Frame(content_frame, bg="#1e293b", bd=1, relief="solid")
    list_frame.pack(fill="both", expand=True, pady=(0, 10))

    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side="right", fill="y")

    vault_listbox = tk.Listbox(
        list_frame,
        bg="#1e293b",
        fg="#f8fafc",
        selectbackground="#0284c7",
        selectforeground="#ffffff",
        font=("Consolas", 10),
        bd=0,
        highlightthickness=0,
        yscrollcommand=scrollbar.set
    )
    vault_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    scrollbar.config(command=vault_listbox.yview)

    history = load_vault_history()

    def refresh_history():
        vault_listbox.delete(0, tk.END)
        for item in history:
            status = "✓ [Vault]" if is_valid_vault(item) else "📁 [Folder]"
            vault_listbox.insert(tk.END, f"{status} {item}")

    refresh_history()
    if history:
        vault_listbox.selection_set(0)

    download_var = tk.BooleanVar(value=ALLOW_DOWNLOADS)
    chk_download = tk.Checkbutton(
        content_frame,
        text="💾 Allow Media Saving, Downloading & Direct Export (Disabled by default)",
        variable=download_var,
        font=("Segoe UI", 9),
        bg="#0f172a",
        fg="#cbd5e1",
        selectcolor="#1e293b",
        activebackground="#0f172a",
        activeforeground="#38bdf8",
        cursor="hand2"
    )
    chk_download.pack(anchor="w", pady=(0, 2))

    shutdown_var = tk.BooleanVar(value=ENABLE_REMOTE_SHUTDOWN)
    chk_shutdown = tk.Checkbutton(
        content_frame,
        text="🔴 Enable Remote PC Shutdown button in Web UI",
        variable=shutdown_var,
        font=("Segoe UI", 9),
        bg="#0f172a",
        fg="#cbd5e1",
        selectcolor="#1e293b",
        activebackground="#0f172a",
        activeforeground="#38bdf8",
        cursor="hand2"
    )
    chk_shutdown.pack(anchor="w", pady=(0, 5))

    def finish_launch(path):
        global ENABLE_REMOTE_SHUTDOWN, ALLOW_DOWNLOADS
        ALLOW_DOWNLOADS = download_var.get()
        ENABLE_REMOTE_SHUTDOWN = shutdown_var.get()
        selected_path["val"] = path
        root.destroy()

    # Actions Frame
    btn_frame = tk.Frame(root, bg="#0f172a", padx=20, pady=15)
    btn_frame.pack(fill="x")

    def on_launch_selected():
        sel = vault_listbox.curselection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select a vault folder from the list or browse for one.", parent=root)
            return
        idx = sel[0]
        path = history[idx]
        if not os.path.exists(path):
            messagebox.showerror("Path Not Found", f"The folder does not exist:\n{path}", parent=root)
            return
        if not is_valid_vault(path):
            ans = messagebox.askyesno(
                "Initialize Vault?",
                f"The folder:\n{path}\nis not initialized as a CryptHaven vault yet.\n\nDo you want to set it up as a new vault?",
                parent=root
            )
            if not ans:
                return
            initialize_vault_folder(path)
        finish_launch(path)

    def on_browse_open():
        folder = filedialog.askdirectory(title="Select Vault Folder", parent=root)
        if folder:
            folder = os.path.abspath(folder)
            if not is_valid_vault(folder):
                ans = messagebox.askyesno(
                    "Initialize New Vault?",
                    f"The selected folder:\n{folder}\nis not a CryptHaven vault yet.\n\nWould you like to transform it into a vault?",
                    parent=root
                )
                if not ans:
                    return
                initialize_vault_folder(folder)
            finish_launch(folder)

    def on_browse_create():
        folder = filedialog.askdirectory(title="Select Folder to Transform into Vault", parent=root)
        if folder:
            folder = os.path.abspath(folder)
            initialize_vault_folder(folder)
            finish_launch(folder)

    def on_remove_history():
        sel = vault_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        path = history[idx]
        remove_from_vault_history(path)
        del history[idx]
        refresh_history()

    vault_listbox.bind("<Double-Button-1>", lambda event: on_launch_selected())
    vault_listbox.bind("<Return>", lambda event: on_launch_selected())

    btn_open = tk.Button(
        btn_frame,
        text="📁 Open Vault...",
        command=on_browse_open,
        font=("Segoe UI", 10),
        bg="#334155",
        fg="#ffffff",
        activebackground="#475569",
        activeforeground="#ffffff",
        bd=0,
        padx=12,
        pady=6,
        cursor="hand2"
    )
    btn_open.pack(side="left", padx=(0, 8))

    btn_create = tk.Button(
        btn_frame,
        text="➕ Create / Transform...",
        command=on_browse_create,
        font=("Segoe UI", 10),
        bg="#334155",
        fg="#ffffff",
        activebackground="#475569",
        activeforeground="#ffffff",
        bd=0,
        padx=12,
        pady=6,
        cursor="hand2"
    )
    btn_create.pack(side="left", padx=(0, 8))

    btn_remove = tk.Button(
        btn_frame,
        text="🗑️ Remove",
        command=on_remove_history,
        font=("Segoe UI", 10),
        bg="#475569",
        fg="#cbd5e1",
        activebackground="#64748b",
        activeforeground="#ffffff",
        bd=0,
        padx=10,
        pady=6,
        cursor="hand2"
    )
    btn_remove.pack(side="left", padx=(0, 8))

    btn_launch = tk.Button(
        btn_frame,
        text="🚀 Launch Vault",
        command=on_launch_selected,
        font=("Segoe UI", 10, "bold"),
        bg="#0284c7",
        fg="#ffffff",
        activebackground="#0369a1",
        activeforeground="#ffffff",
        bd=0,
        padx=16,
        pady=6,
        cursor="hand2"
    )
    btn_launch.pack(side="right")

    root.protocol("WM_DELETE_WINDOW", lambda: root.destroy())
    root.mainloop()

    return selected_path["val"]

# ── Runtime State ──────────────────────────────────────────────────────────
ACTIVE_SESSIONS = {}
ACTIVE_FERNET = None   # Legacy — kept for Fernet migration fallback
ACTIVE_DEK = None      # v2 — the active Data Encryption Key (AES-256-GCM)
DECRYPTED_INDEX = []
ENC_ID_LOOKUP = {}  # enc_id -> item dict for O(1) lookups
LAST_ACTIVITY_TIME = time.time()
INACTIVITY_TIMEOUT_SECONDS = 900  # 15 minutes auto-lock
FAILED_LOGINS = {}  # IP -> {'count': int, 'lockout_until': float}
FAILED_LOGINS_LOCK = threading.Lock()
LOGIN_KDF_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_KDF_OPERATIONS)
VAULT_OPERATION_LOCK = threading.RLock()
MIGRATION_IN_PROGRESS = False

TRAY_ICON = None
SERVER_HTTPD = None
SERVER_HTTPS = None

def generate_self_signed_ssl_certificate():
    """Auto-generate 2048-bit RSA Self-Signed TLS Certificate for 100% Encrypted Local HTTPS."""
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return True

    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptHaven TLS"),
            x509.NameAttribute(NameOID.COMMON_NAME, LOCAL_IP),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address(LOCAL_IP)),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())

        private_key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        atomic_write(KEY_PATH, private_key_bytes, mode=0o600)
        atomic_write(CERT_PATH, cert.public_bytes(serialization.Encoding.PEM), mode=0o644)

        print("🔒 Auto-generated 2048-bit RSA Self-Signed TLS Certificate & Key.")
        return True
    except Exception as e:
        print(f"SSL Generation Warning: {e}")
        return False

# ── v2 Encryption Core (AES-256-GCM + DEK/KEK) ───────────────────────────

def derive_kek(password: str, salt: bytes, *, time_cost=ARGON2_TIME_COST,
               memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM) -> bytes:
    """Derive a 256-bit Key Encryption Key from password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID
    )

def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key."""
    return secrets.token_bytes(DEK_SIZE)

def wrap_dek(dek: bytes, kek: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt the DEK with the KEK using AES-256-GCM. Returns nonce(12) + ciphertext+tag."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(kek)
    ciphertext = aesgcm.encrypt(nonce, dek, aad)
    return nonce + ciphertext

def unwrap_dek(wrapped: bytes, kek: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt the DEK using the KEK. Input: nonce(12) + ciphertext+tag."""
    if len(wrapped) != NONCE_SIZE + DEK_SIZE + 16:
        raise ValueError("Invalid wrapped DEK length")
    nonce = wrapped[:NONCE_SIZE]
    ciphertext = wrapped[NONCE_SIZE:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext, aad)

def content_aad(context: str | bytes | None) -> bytes:
    if context is None:
        context = b"generic"
    elif isinstance(context, str):
        context = context.encode('utf-8')
    return CONTENT_AAD_PREFIX + context


def vault_encrypt(plaintext: bytes, dek: bytes, context: str | bytes | None = None) -> bytes:
    """Encrypt v3 data with AES-256-GCM and bind it to its application context."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, content_aad(context))
    return b'\x03' + nonce + ciphertext

def vault_decrypt(data: bytes, dek: bytes, fernet_fallback=None,
                  context: str | bytes | None = None) -> bytes:
    """Decrypt v3 context-bound data, v2 AES-GCM data, or legacy Fernet data."""
    if len(data) < 1 + NONCE_SIZE + 16:
        if fernet_fallback is not None and not data.startswith((b'\x02', b'\x03')):
            return fernet_fallback.decrypt(data)
        raise ValueError("Encrypted payload is truncated")
    if data[0:1] in (b'\x02', b'\x03'):
        version = data[0]
        nonce = data[1:1 + NONCE_SIZE]
        ciphertext = data[1 + NONCE_SIZE:]
        aesgcm = AESGCM(dek)
        aad = content_aad(context) if version == 3 else None
        return aesgcm.decrypt(nonce, ciphertext, aad)
    else:
        if fernet_fallback is not None:
            return fernet_fallback.decrypt(data)
        raise ValueError("Legacy Fernet format detected but no fallback key provided")


def encrypted_payload_version(path: str) -> int:
    """Return the on-disk ciphertext version without decrypting the payload."""
    with open(path, 'rb') as payload_file:
        marker = payload_file.read(1)
    if marker == b'\x02':
        return 2
    if marker == b'\x03':
        return 3
    return 1


def active_vault_format_version() -> int | None:
    """Report the unlocked vault's actual ciphertext format, not just its metadata layout."""
    if ACTIVE_FERNET is not None and ACTIVE_DEK is None:
        return 1
    if ACTIVE_DEK is not None and os.path.exists(INDEX_PATH):
        # Original v2 vaults use separate salt/wrapped-DEK files. They still need
        # an envelope migration even if a recent index write already emitted v3.
        if not os.path.exists(KEY_ENVELOPE_PATH):
            return 2
        versions = {encrypted_payload_version(INDEX_PATH)}
        for item in DECRYPTED_INDEX:
            for identifier in (item.get('enc_id'), item.get('enc_thumb_id')):
                if identifier:
                    payload_path = safe_vault_path(identifier)
                    if os.path.isfile(payload_path):
                        versions.add(encrypted_payload_version(payload_path))
        if versions <= {3}:
            return 3
        if versions <= {2, 3} and 2 in versions:
            return 2
    return None


def key_envelope_header(salt: bytes, *, time_cost=ARGON2_TIME_COST,
                        memory_cost=ARGON2_MEMORY_COST,
                        parallelism=ARGON2_PARALLELISM) -> dict:
    return {
        "magic": KEY_ENVELOPE_MAGIC,
        "version": KEY_ENVELOPE_VERSION,
        "kdf": "argon2id",
        "time_cost": time_cost,
        "memory_cost": memory_cost,
        "parallelism": parallelism,
        "salt": base64.b64encode(salt).decode('ascii'),
    }


def key_envelope_aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(',', ':')).encode('utf-8')


def create_key_envelope(password: str, dek: bytes) -> bytes:
    salt = secrets.token_bytes(KEK_SALT_SIZE)
    header = key_envelope_header(salt)
    kek = derive_kek(password, salt)
    wrapped = wrap_dek(dek, kek, key_envelope_aad(header))
    envelope = dict(header)
    envelope["wrapped_dek"] = base64.b64encode(wrapped).decode('ascii')
    return (json.dumps(envelope, sort_keys=True, indent=2) + "\n").encode('utf-8')


def read_key_envelope(password: str) -> bytes:
    with open(KEY_ENVELOPE_PATH, 'r', encoding='utf-8') as envelope_file:
        envelope = json.load(envelope_file)
    if envelope.get("magic") != KEY_ENVELOPE_MAGIC or envelope.get("version") != KEY_ENVELOPE_VERSION:
        raise ValueError("Unsupported key envelope")
    if envelope.get("kdf") != "argon2id":
        raise ValueError("Unsupported key derivation function")
    time_cost = int(envelope.get("time_cost", 0))
    memory_cost = int(envelope.get("memory_cost", 0))
    parallelism = int(envelope.get("parallelism", 0))
    if not (1 <= time_cost <= 10 and 8192 <= memory_cost <= 1048576 and 1 <= parallelism <= 16):
        raise ValueError("Unsafe key derivation parameters")
    salt = base64.b64decode(envelope["salt"], validate=True)
    wrapped = base64.b64decode(envelope["wrapped_dek"], validate=True)
    if len(salt) != KEK_SALT_SIZE:
        raise ValueError("Invalid key envelope salt")
    header = key_envelope_header(
        salt, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
    )
    kek = derive_kek(
        password, salt, time_cost=time_cost, memory_cost=memory_cost,
        parallelism=parallelism
    )
    return unwrap_dek(wrapped, kek, key_envelope_aad(header))

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def save_index():
    """Save the decrypted index to disk, encrypted with the active key."""
    with VAULT_OPERATION_LOCK:
        if DECRYPTED_INDEX is not None:
            new_json_bytes = json.dumps(DECRYPTED_INDEX, indent=2).encode('utf-8')
            if ACTIVE_DEK is not None:
                ciphertext = vault_encrypt(new_json_bytes, ACTIVE_DEK, context="index")
            elif ACTIVE_FERNET is not None:
                ciphertext = ACTIVE_FERNET.encrypt(new_json_bytes)
            else:
                return
            atomic_write(INDEX_PATH, ciphertext)


def validate_encrypted_id(value: str) -> str:
    allowed = set(string.ascii_letters + string.digits + '._-')
    if not isinstance(value, str) or not value or len(value) > 128 or any(ch not in allowed for ch in value):
        raise ValueError("Invalid encrypted file identifier")
    if value in {'.', '..'}:
        raise ValueError("Invalid encrypted file identifier")
    return value

def sanitize_decrypted_index():
    """Ensure every item in DECRYPTED_INDEX has valid, non-null properties."""
    global DECRYPTED_INDEX, ENC_ID_LOOKUP
    valid_items = []
    seen_ids = set()
    for item in DECRYPTED_INDEX:
        if not isinstance(item, dict):
            continue
        if not item.get('enc_id'):
            item['enc_id'] = f"enc_{secrets.token_hex(8)}.enc"
        item['enc_id'] = validate_encrypted_id(item['enc_id'])
        if item['enc_id'] in seen_ids:
            raise ValueError("Duplicate encrypted file identifier in vault index")
        seen_ids.add(item['enc_id'])
        if not item.get('name'):
            item['name'] = 'unnamed'
        if item.get('subfolder') is None:
            item['subfolder'] = ''
        if 'starred' not in item or item['starred'] is None:
            item['starred'] = False
        if 'enc_thumb_id' not in item:
            item['enc_thumb_id'] = None
        elif item['enc_thumb_id'] is not None:
            item['enc_thumb_id'] = validate_encrypted_id(item['enc_thumb_id'])
        if 'is_live_photo' not in item or item['is_live_photo'] is None:
            item['is_live_photo'] = False
        if 'is_video' not in item or item['is_video'] is None:
            item['is_video'] = False
        if 'size' not in item or item['size'] is None:
            item['size'] = 0
        if 'mtime' not in item or item['mtime'] is None:
            item['mtime'] = 0
        valid_items.append(item)

    DECRYPTED_INDEX = valid_items
    ENC_ID_LOOKUP = {item['enc_id']: item for item in DECRYPTED_INDEX}

def load_vault(password: str, *, allow_initialize=False):
    """Unlock a valid vault, or explicitly initialize a provably empty local vault."""
    global ACTIVE_FERNET, ACTIVE_DEK, DECRYPTED_INDEX, ENC_ID_LOOKUP, LAST_ACTIVITY_TIME

    state = vault_metadata_state(VAULT_FOLDER)
    if state == "damaged":
        return False, "Vault metadata is incomplete. Refusing destructive reinitialization."

    if state == "empty":
        if not allow_initialize:
            return False, "Vault initialization is only allowed from the local machine."
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

        dek = generate_dek()
        envelope_bytes = create_key_envelope(password, dek)
        ciphertext = vault_encrypt(
            json.dumps([]).encode('utf-8'), dek, context="index"
        )
        try:
            atomic_write(KEY_ENVELOPE_PATH, envelope_bytes)
            atomic_write(INDEX_PATH, ciphertext)
        except Exception:
            ACTIVE_DEK = None
            DECRYPTED_INDEX = []
            ENC_ID_LOOKUP = {}
            raise

        ACTIVE_DEK = dek
        ACTIVE_FERNET = None
        DECRYPTED_INDEX = []
        ENC_ID_LOOKUP = {}
        LAST_ACTIVITY_TIME = time.time()
        return True, "Vault initialized & unlocked"

    if state in {"v2", "v3"}:
        try:
            if state == "v3":
                dek = read_key_envelope(password)
            else:
                with open(SALT_PATH, 'rb') as sf:
                    salt = sf.read()
                with open(DEK_PATH, 'rb') as df:
                    wrapped_dek = df.read()
                if len(salt) != KEK_SALT_SIZE:
                    raise ValueError("Invalid vault salt")
                dek = unwrap_dek(wrapped_dek, derive_kek(password, salt))
        except Exception:
            return False, "Invalid Password"

        try:
            with open(INDEX_PATH, 'rb') as idx_f:
                ciphertext = idx_f.read()
            plaintext = vault_decrypt(ciphertext, dek, context="index")
            candidate_index = json.loads(plaintext.decode('utf-8'))
            if not isinstance(candidate_index, list):
                raise ValueError("Vault index must be a list")
            DECRYPTED_INDEX = candidate_index
            sanitize_decrypted_index()
        except Exception:
            DECRYPTED_INDEX = []
            ENC_ID_LOOKUP = {}
            return False, "Vault index failed authentication or is corrupt"

        ACTIVE_DEK = dek
        ACTIVE_FERNET = None
        LAST_ACTIVITY_TIME = time.time()
        return True, "Vault unlocked successfully"

    # Legacy Fernet vault.
    with open(SALT_PATH, 'rb') as sf:
        salt = sf.read()
    try:
        fernet = Fernet(derive_key(password, salt))
        with open(INDEX_PATH, 'rb') as idx_f:
            plaintext = fernet.decrypt(idx_f.read())
        candidate_index = json.loads(plaintext.decode('utf-8'))
        if not isinstance(candidate_index, list):
            raise ValueError("Vault index must be a list")
        DECRYPTED_INDEX = candidate_index
        sanitize_decrypted_index()
    except Exception:
        DECRYPTED_INDEX = []
        ENC_ID_LOOKUP = {}
        return False, "Invalid Password"

    ACTIVE_FERNET = fernet
    ACTIVE_DEK = None
    LAST_ACTIVITY_TIME = time.time()
    return True, "Vault unlocked successfully (legacy format — migration available)"

def lock_vault():
    """Lock the vault — clear all keys and session state from memory."""
    global ACTIVE_FERNET, ACTIVE_DEK, DECRYPTED_INDEX, ENC_ID_LOOKUP
    ACTIVE_FERNET = None
    ACTIVE_DEK = None
    DECRYPTED_INDEX = []
    ENC_ID_LOOKUP = {}
    ACTIVE_SESSIONS.clear()


def change_vault_password(old_password: str, new_password: str):
    """Verify the current password and atomically replace the v3 key envelope."""
    if ACTIVE_DEK is None:
        raise ValueError("Please migrate the legacy vault before changing its password")
    if len(new_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"New password must be at least {MIN_PASSWORD_LENGTH} characters")

    with VAULT_OPERATION_LOCK:
        if os.path.exists(KEY_ENVELOPE_PATH):
            verified_dek = read_key_envelope(old_password)
        else:
            with open(SALT_PATH, 'rb') as salt_file:
                old_salt = salt_file.read()
            with open(DEK_PATH, 'rb') as wrapped_file:
                wrapped = wrapped_file.read()
            verified_dek = unwrap_dek(wrapped, derive_kek(old_password, old_salt))
        if not secrets.compare_digest(verified_dek, ACTIVE_DEK):
            raise ValueError("Active DEK mismatch")

        atomic_write(KEY_ENVELOPE_PATH, create_key_envelope(new_password, ACTIVE_DEK))
        for legacy_key_path in (SALT_PATH, DEK_PATH):
            try:
                if os.path.exists(legacy_key_path):
                    os.remove(legacy_key_path)
            except OSError:
                pass

GDRIVE_CACHE_PATH = None
GDRIVE_CACHE_TIME = 0

def find_google_drive_folder():
    """Detect Google Drive mounted folder on Windows (cached for 60s)."""
    global GDRIVE_CACHE_PATH, GDRIVE_CACHE_TIME
    now = time.time()
    if GDRIVE_CACHE_PATH is not None and (now - GDRIVE_CACHE_TIME < 60):
        if os.path.exists(GDRIVE_CACHE_PATH):
            return GDRIVE_CACHE_PATH

    user_home = os.path.expanduser('~')
    fast_candidates = [
        os.path.join(user_home, "Google Drive", "My Drive"),
        os.path.join(user_home, "Google Drive"),
        os.path.join(user_home, "My Drive"),
        "G:\\My Drive",
        "G:\\Google Drive",
        "GDrive:\\My Drive"
    ]
    for path in fast_candidates:
        if os.path.exists(path) and os.path.isdir(path):
            GDRIVE_CACHE_PATH = path
            GDRIVE_CACHE_TIME = now
            return path

    for letter in string.ascii_uppercase:
        p1 = f"{letter}:\\My Drive"
        p2 = f"{letter}:\\Google Drive"
        if os.path.exists(p1) and os.path.isdir(p1):
            GDRIVE_CACHE_PATH = p1
            GDRIVE_CACHE_TIME = now
            return p1
        if os.path.exists(p2) and os.path.isdir(p2):
            GDRIVE_CACHE_PATH = p2
            GDRIVE_CACHE_TIME = now
            return p2

    GDRIVE_CACHE_PATH = None
    GDRIVE_CACHE_TIME = now
    return None

def perform_google_drive_backup():
    """Copies/updates fully encrypted vault package to Google Drive."""
    gdrive_root = find_google_drive_folder()
    if not gdrive_root:
        return False, "Google Drive folder not found on this computer. Please ensure Google Drive for Desktop is installed and logged in.", None, 0, 0

    target_backup_dir = os.path.join(gdrive_root, "EncryptedVault_Backup")
    target_data_dir = os.path.join(target_backup_dir, "data")
    os.makedirs(target_data_dir, exist_ok=True)

    copied_files_count = 0
    total_bytes_copied = 0

    main_files = [INDEX_PATH]
    if os.path.exists(KEY_ENVELOPE_PATH):
        main_files.append(KEY_ENVELOPE_PATH)
    else:
        main_files.append(SALT_PATH)
        if os.path.exists(DEK_PATH):
            main_files.append(DEK_PATH)

    for main_file in main_files:
        if os.path.exists(main_file):
            dest_file = os.path.join(target_backup_dir, os.path.basename(main_file))
            if not os.path.exists(dest_file) or os.path.getmtime(main_file) > os.path.getmtime(dest_file):
                shutil.copy2(main_file, dest_file)
                copied_files_count += 1
                total_bytes_copied += os.path.getsize(main_file)

    if os.path.exists(DATA_DIR):
        for fname in os.listdir(DATA_DIR):
            src_p = os.path.join(DATA_DIR, fname)
            dst_p = os.path.join(target_data_dir, fname)

            if os.path.isfile(src_p):
                if not os.path.exists(dst_p) or os.path.getsize(src_p) != os.path.getsize(dst_p):
                    shutil.copy2(src_p, dst_p)
                    copied_files_count += 1
                    total_bytes_copied += os.path.getsize(src_p)

    copied_mb = f"{total_bytes_copied / (1024*1024):.2f} MB"
    return True, f"Cloud backup complete to {target_backup_dir}", target_backup_dir, copied_files_count, copied_mb
def safe_child_path(root: str, *parts: str) -> str:
    """Resolve a child path beneath root, including symlink/junction resolution."""
    root_path = os.path.normcase(os.path.realpath(os.path.abspath(root)))
    full_path = os.path.normcase(os.path.realpath(os.path.abspath(os.path.join(root, *parts))))
    if os.path.commonpath([root_path, full_path]) != root_path or full_path == root_path:
        raise ValueError("Path traversal blocked")
    return full_path


def safe_vault_path(filename: str) -> str:
    return safe_child_path(DATA_DIR, filename)


def validate_filename(filename: str) -> str:
    if not filename or filename in {'.', '..'}:
        raise ValueError("Invalid filename")
    if filename != os.path.basename(filename) or '/' in filename or '\\' in filename:
        raise ValueError("Filename must not contain path separators")
    if any(ord(ch) < 32 or ch == '\x7f' for ch in filename):
        raise ValueError("Filename contains control characters")
    return filename


def normalize_subfolder(value: str) -> str:
    normalized = value.strip().replace('\\', '/').strip('/')
    if not normalized or normalized in {'.', '__UNCATEGORIZED__', '__ALL__'}:
        return ''
    parts = normalized.split('/')
    if any(part in {'', '.', '..'} or any(ord(ch) < 32 or ch == '\x7f' for ch in part) for part in parts):
        raise ValueError("Invalid subfolder")
    return '/'.join(parts)


def commit_item_deletions(items: list) -> int:
    """Commit index removals before deleting ciphertext, avoiding dangling index entries."""
    if not items:
        return 0
    with VAULT_OPERATION_LOCK:
        original_index = list(DECRYPTED_INDEX)
        removal_ids = {id(item) for item in items}
        DECRYPTED_INDEX[:] = [item for item in DECRYPTED_INDEX if id(item) not in removal_ids]
        try:
            save_index()
        except Exception:
            DECRYPTED_INDEX[:] = original_index
            raise

        live_cipher_ids = {
            identifier
            for item in DECRYPTED_INDEX
            for identifier in (item.get('enc_id'), item.get('enc_thumb_id'))
            if identifier
        }
        for item in items:
            for identifier in (item.get('enc_id'), item.get('enc_thumb_id')):
                if not identifier or identifier in live_cipher_ids:
                    continue
                try:
                    path = safe_vault_path(identifier)
                    if os.path.exists(path):
                        os.remove(path)
                except OSError as exc:
                    print(f"Ciphertext cleanup notice for {identifier}: {exc}")
        return len(items)


def migrate_vault_to_v3(password: str, *, _fault_at: str | None = None) -> int:
    """Transactionally migrate an unlocked v1 or v2 vault to context-bound v3."""
    global ACTIVE_DEK, ACTIVE_FERNET, MIGRATION_IN_PROGRESS
    source_version = active_vault_format_version()
    if source_version not in (1, 2):
        raise ValueError("No v1 or v2 vault is active")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    if source_version == 1:
        with open(SALT_PATH, 'rb') as salt_file:
            legacy_salt = salt_file.read()
        candidate_fernet = Fernet(derive_key(password, legacy_salt))
        with open(INDEX_PATH, 'rb') as index_file:
            candidate_fernet.decrypt(index_file.read())
        dek = generate_dek()

        def decrypt_source(ciphertext: bytes, context: str) -> bytes:
            return candidate_fernet.decrypt(ciphertext)
    else:
        candidate_fernet = None
        if os.path.exists(KEY_ENVELOPE_PATH):
            verified_dek = read_key_envelope(password)
        else:
            with open(SALT_PATH, 'rb') as salt_file:
                salt = salt_file.read()
            with open(DEK_PATH, 'rb') as wrapped_file:
                wrapped_dek = wrapped_file.read()
            if len(salt) != KEK_SALT_SIZE:
                raise ValueError("Invalid vault salt")
            verified_dek = unwrap_dek(wrapped_dek, derive_kek(password, salt))
        if ACTIVE_DEK is None or not secrets.compare_digest(verified_dek, ACTIVE_DEK):
            raise ValueError("Active DEK mismatch")
        dek = ACTIVE_DEK

        def decrypt_source(ciphertext: bytes, context: str) -> bytes:
            if not ciphertext.startswith((b'\x02', b'\x03')):
                raise ValueError(f"Expected AES-GCM ciphertext for {context}")
            return vault_decrypt(ciphertext, dek, context=context)

    expected_contexts = {}
    media_ids = set()
    for item in DECRYPTED_INDEX:
        identifiers = (
            (item.get('enc_id'), 'media'),
            (item.get('enc_thumb_id'), 'thumb'),
        )
        for identifier, kind in identifiers:
            if not identifier:
                continue
            validate_encrypted_id(identifier)
            context = f"{kind}:{identifier}"
            previous_context = expected_contexts.setdefault(identifier, context)
            if previous_context != context:
                raise ValueError(f"Ciphertext identifier is reused across contexts: {identifier}")
            if kind == 'media':
                media_ids.add(identifier)

    actual_files = set()
    for filename in os.listdir(DATA_DIR):
        source_path = safe_vault_path(filename)
        if not os.path.isfile(source_path):
            raise ValueError(f"Unexpected directory in encrypted data: {filename}")
        actual_files.add(filename)
    missing_files = sorted(set(expected_contexts) - actual_files)
    unindexed_files = sorted(actual_files - set(expected_contexts))
    if missing_files:
        raise ValueError(f"Indexed ciphertext is missing: {missing_files[0]}")
    if unindexed_files:
        raise ValueError(
            f"Unindexed ciphertext cannot be safely context-bound: {unindexed_files[0]}"
        )

    token = secrets.token_hex(16)
    paths = _migration_paths(token)
    stage_data = os.path.join(paths["stage"], "data")
    os.makedirs(stage_data, exist_ok=False)
    # Always generate a fresh envelope so its hash is an unambiguous commit marker,
    # including v2 vaults that already gained an envelope via a password change.
    new_envelope = create_key_envelope(password, dek)
    new_index = vault_encrypt(
        json.dumps(DECRYPTED_INDEX, indent=2).encode('utf-8'), dek, context="index"
    )
    migrated_count = 0
    journal_written = False

    MIGRATION_IN_PROGRESS = True
    try:
        with VAULT_OPERATION_LOCK:
            for identifier, context in expected_contexts.items():
                source_path = safe_vault_path(identifier)
                with open(source_path, 'rb') as source_file:
                    plaintext = decrypt_source(source_file.read(), context)
                migrated = vault_encrypt(plaintext, dek, context=context)
                destination = os.path.join(stage_data, identifier)
                atomic_write(destination, migrated)
                with open(destination, 'rb') as verify_file:
                    if vault_decrypt(verify_file.read(), dek, context=context) != plaintext:
                        raise ValueError(f"Migration verification failed for {identifier}")
                if identifier in media_ids:
                    migrated_count += 1

            decoded_index = vault_decrypt(new_index, dek, context="index")
            if json.loads(decoded_index.decode('utf-8')) != DECRYPTED_INDEX:
                raise ValueError("Migration index verification failed")

            shutil.copy2(INDEX_PATH, paths["backup_index"])
            previous_envelope = os.path.exists(KEY_ENVELOPE_PATH)
            if previous_envelope:
                shutil.copy2(KEY_ENVELOPE_PATH, paths["backup_envelope"])
            journal = {
                "token": token,
                "source_version": source_version,
                "previous_envelope": previous_envelope,
                "remove_legacy_keys": True,
                "new_envelope_sha256": hashlib.sha256(new_envelope).hexdigest(),
            }
            atomic_write(
                MIGRATION_JOURNAL_PATH,
                (json.dumps(journal, sort_keys=True, indent=2) + "\n").encode('utf-8')
            )
            journal_written = True

            os.replace(DATA_DIR, paths["backup_data"])
            os.replace(stage_data, DATA_DIR)
            if _fault_at == "after_data_swap":
                raise RuntimeError("Injected migration interruption after data swap")
            atomic_write(INDEX_PATH, new_index)
            if _fault_at == "after_index_replace":
                raise RuntimeError("Injected migration interruption after index replacement")
            atomic_write(KEY_ENVELOPE_PATH, new_envelope)

            ACTIVE_DEK = dek
            ACTIVE_FERNET = None
            recover_interrupted_migration()
            return migrated_count
    except Exception:
        if journal_written:
            recover_interrupted_migration()
        else:
            _safe_remove_tree(paths["stage"])
        raise
    finally:
        MIGRATION_IN_PROGRESS = False


def migrate_legacy_vault(password: str, *, _fault_at: str | None = None) -> int:
    """Backward-compatible API name for the v1/v2-to-v3 migration."""
    return migrate_vault_to_v3(password, _fault_at=_fault_at)


class VaultGalleryHandler(BaseHTTPRequestHandler):

    def address_string(self):
        """Override to prevent slow/hanging reverse DNS lookups on client IP addresses."""
        return self.client_address[0]

    def log_message(self, format, *args):
        """Safely handle log_message when sys.stderr is None in PyInstaller --noconsole mode."""
        if sys.stderr is not None and hasattr(sys.stderr, 'write'):
            try:
                sys.stderr.write("%s - - [%s] %s\n" %
                                 (self.address_string(),
                                  self.log_date_time_string(),
                                  format % args))
            except Exception:
                pass

    def inject_security_headers(self):
        """Hardened Security Headers to block XSS, MIME-sniffing, Framing, and Clickjacking."""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

    def validate_request_size(self, path: str) -> bool:
        if self.headers.get('Transfer-Encoding'):
            self.send_json({'error': 'Transfer-Encoding is not supported'}, status=400)
            return False
        raw_length = self.headers.get('Content-Length')
        if raw_length is None:
            return True
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self.send_json({'error': 'Invalid Content-Length'}, status=400)
            return False
        if length < 0:
            self.send_json({'error': 'Invalid Content-Length'}, status=400)
            return False
        if path == '/login':
            limit = MAX_LOGIN_BODY_BYTES
        elif path == '/api/upload':
            limit = MAX_UPLOAD_BYTES + MAX_REQUEST_METADATA_BYTES
        else:
            limit = MAX_REQUEST_METADATA_BYTES
        if length > limit:
            self.send_json({'error': 'Request body too large'}, status=413)
            return False
        return True

    def session_token_from_request(self) -> str:
        cookie_header = self.headers.get('Cookie', '')
        cookies = dict(c.strip().split('=', 1) for c in cookie_header.split(';') if '=' in c)
        return cookies.get('auth_session', '') or self.headers.get('X-Auth-Token', '')

    def validate_csrf(self) -> bool:
        token = getattr(self, 'auth_session_token', '') or self.session_token_from_request()
        session = ACTIVE_SESSIONS.get(token)
        expected = session.get('csrf', '') if session else ''
        provided = self.headers.get('X-CSRF-Token', '')
        return bool(expected and provided and secrets.compare_digest(provided, expected))

    def client_is_loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def check_rate_limit(self, client_ip):
        now = time.time()
        with FAILED_LOGINS_LOCK:
            if client_ip in FAILED_LOGINS:
                rec = FAILED_LOGINS[client_ip]
                if rec['lockout_until'] > now:
                    return False, int(rec['lockout_until'] - now)
                elif rec['lockout_until'] != 0:
                    FAILED_LOGINS[client_ip] = {'count': 0, 'lockout_until': 0}
        return True, 0

    def record_failed_login(self, client_ip):
        now = time.time()
        with FAILED_LOGINS_LOCK:
            if client_ip not in FAILED_LOGINS:
                FAILED_LOGINS[client_ip] = {'count': 1, 'lockout_until': 0}
            else:
                FAILED_LOGINS[client_ip]['count'] += 1
                if FAILED_LOGINS[client_ip]['count'] >= 5:
                    FAILED_LOGINS[client_ip]['lockout_until'] = now + 900

    def is_https_request(self) -> bool:
        """Check if request is over HTTPS."""
        if hasattr(self, 'request') and isinstance(self.request, ssl.SSLSocket):
            return True
        if self.headers.get('X-Forwarded-Proto', '').lower() == 'https':
            return True
        return False

    def check_auth(self):
        global LAST_ACTIVITY_TIME
        now = time.time()
        self.auth_session_token = ''

        if MIGRATION_IN_PROGRESS:
            return False
        
        if now - LAST_ACTIVITY_TIME > INACTIVITY_TIMEOUT_SECONDS:
            lock_vault()
            return False

        if ACTIVE_FERNET is None and ACTIVE_DEK is None:
            return False

        session_token = self.session_token_from_request()
        session = ACTIVE_SESSIONS.get(session_token)
        if session:
            created = session.get('created', 0)
            if now - created > SESSION_ABSOLUTE_TIMEOUT_SECONDS:
                ACTIVE_SESSIONS.pop(session_token, None)
                return False
            session['last_seen'] = now
            self.auth_session_token = session_token
            LAST_ACTIVITY_TIME = now
            return True

        return False

    def send_html(self, content, status=200):
        self.send_response(status)
        self.inject_security_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def send_json(self, data, status=200):
        self.send_response(status)
        self.inject_security_headers()
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_bytes(self, data, mime, status=200):
        try:
            self.send_response(status)
            self.inject_security_headers()
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Cache-Control', 'private, no-store')
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def do_POST(self):
        # The active vault and index are process-global. Serialize mutations so
        # concurrent HTTP threads cannot interleave index/file commits.
        with VAULT_OPERATION_LOCK:
            return self._do_POST()

    def _do_POST(self):
        global ACTIVE_FERNET, ACTIVE_DEK
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)

        if not self.validate_request_size(parsed.path):
            return
        
        if parsed.path == '/login':
            allowed, remaining_sec = self.check_rate_limit(client_ip)
            if not allowed:
                self.send_json({'success': False, 'error': f'Too many failed attempts. Locked out for {remaining_sec} seconds.'}, status=429)
                return

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            pwd = params.get('password', [''])[0]
            if not LOGIN_KDF_SEMAPHORE.acquire(blocking=False):
                self.send_json({'success': False, 'error': 'Server is busy processing login attempts. Try again shortly.'}, status=503)
                return
            try:
                success, msg = load_vault(pwd, allow_initialize=self.client_is_loopback())
            finally:
                LOGIN_KDF_SEMAPHORE.release()

            accept_hdr = self.headers.get('Accept', '')
            is_ajax = 'application/json' in accept_hdr or self.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if success:
                if client_ip in FAILED_LOGINS: FAILED_LOGINS[client_ip] = {'count': 0, 'lockout_until': 0}
                
                new_session_token = secrets.token_hex(16)
                csrf_token = secrets.token_hex(32)
                ACTIVE_SESSIONS[new_session_token] = {
                    'csrf': csrf_token, 'created': time.time(), 'last_seen': time.time()
                }

                if is_ajax:
                    self.send_response(200)
                    self.inject_security_headers()
                    self.send_header('Set-Cookie', f'auth_session={new_session_token}; Path=/; Max-Age={SESSION_ABSOLUTE_TIMEOUT_SECONDS}; HttpOnly; Secure; SameSite=Strict')
                    self.send_header('Set-Cookie', f'csrf_token={csrf_token}; Path=/; Max-Age={SESSION_ABSOLUTE_TIMEOUT_SECONDS}; Secure; SameSite=Strict')
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
                else:
                    self.send_response(302)
                    self.inject_security_headers()
                    self.send_header('Set-Cookie', f'auth_session={new_session_token}; Path=/; Max-Age={SESSION_ABSOLUTE_TIMEOUT_SECONDS}; HttpOnly; Secure; SameSite=Strict')
                    self.send_header('Set-Cookie', f'csrf_token={csrf_token}; Path=/; Max-Age={SESSION_ABSOLUTE_TIMEOUT_SECONDS}; Secure; SameSite=Strict')
                    self.send_header('Location', '/')
                    self.end_headers()
            else:
                self.record_failed_login(client_ip)
                if is_ajax:
                    public_error = msg if vault_metadata_state(VAULT_FOLDER) in {'empty', 'damaged'} and self.client_is_loopback() else 'Access denied'
                    self.send_json({'success': False, 'error': public_error}, status=401)
                else:
                    self.send_html(HTML_LOGIN.replace('id="err" class="err"></div>', 'id="err" class="err">Invalid Passcode</div>'), status=401)
            return

        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, status=401)
            return

        # CSRF validation for state-changing requests
        if not self.validate_csrf():
            self.send_json({'error': 'CSRF token invalid'}, status=403)
            return

        if parsed.path == '/logout':
            ACTIVE_SESSIONS.pop(self.auth_session_token, None)
            self.send_response(200)
            self.inject_security_headers()
            self.send_header('Set-Cookie', 'auth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict')
            self.send_header('Set-Cookie', 'csrf_token=; Path=/; Max-Age=0; Secure; SameSite=Strict')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': 'Logged out!'}).encode('utf-8'))
            return

        if parsed.path == '/api/admin/cloud_backup':
            success, message, path, count, copied_mb = perform_google_drive_backup()
            if success:
                self.send_json({
                    'success': True,
                    'message': message,
                    'path': path,
                    'synced_count': count,
                    'copied_mb': copied_mb
                })
            else:
                self.send_json({'success': False, 'error': message}, status=400)
            return

        if parsed.path == '/api/folders/create':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            parent_sub = params.get('parent_folder', [''])[0].strip().replace('\\', '/').strip('/')
            folder_name = params.get('folder_name', [''])[0].strip().replace('\\', '/').strip('/')
            
            if not folder_name or '/' in folder_name or '..' in folder_name:
                self.send_json({'success': False, 'error': 'Invalid folder name.'}, status=400)
                return

            full_folder_path = f"{parent_sub}/{folder_name}" if parent_sub else folder_name

            existing_folders = set(item['subfolder'].lower() for item in DECRYPTED_INDEX if item['subfolder'])
            if full_folder_path.lower() in existing_folders:
                self.send_json({'success': False, 'error': f"A folder named '{full_folder_path}' already exists!"}, status=400)
                return

            placeholder_id = f"enc_folder_{secrets.token_hex(16)}.enc"
            DECRYPTED_INDEX.append({
                "enc_id": placeholder_id,
                "name": ".folder_placeholder",
                "subfolder": full_folder_path,
                "rel_path": f"{full_folder_path}/.folder_placeholder",
                "size": 0,
                "is_video": False,
                "is_live_photo": False,
                "mtime": time.time(),
                "starred": False
            })
            save_index()
            self.send_json({'success': True, 'folder': full_folder_path})
            return

        if parsed.path == '/api/folders/rename':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            old_folder = params.get('old_folder', [''])[0].strip().replace('\\', '/').strip('/')
            new_name = params.get('new_name', [''])[0].strip().replace('\\', '/').strip('/')

            if not old_folder or not new_name or '/' in new_name or '..' in new_name:
                self.send_json({'success': False, 'error': 'Invalid folder rename request'}, status=400)
                return

            parent_dir = os.path.dirname(old_folder)
            new_folder_path = f"{parent_dir}/{new_name}" if parent_dir else new_name

            existing_folders = set(item['subfolder'].lower() for item in DECRYPTED_INDEX if item['subfolder'])
            if new_folder_path.lower() in existing_folders and new_folder_path.lower() != old_folder.lower():
                self.send_json({'success': False, 'error': f"Target folder '{new_folder_path}' already exists!"}, status=400)
                return

            updated_count = 0
            for item in DECRYPTED_INDEX:
                if item['subfolder'] == old_folder:
                    item['subfolder'] = new_folder_path
                    item['rel_path'] = f"{new_folder_path}/{item['name']}"
                    updated_count += 1
                elif item['subfolder'].startswith(old_folder + '/'):
                    suffix = item['subfolder'][len(old_folder):]
                    item['subfolder'] = new_folder_path + suffix
                    item['rel_path'] = f"{new_folder_path}{suffix}/{item['name']}"
                    updated_count += 1

            if updated_count > 0: save_index()
            self.send_json({'success': True, 'old': old_folder, 'new': new_folder_path, 'updated': updated_count})
            return

        if parsed.path == '/api/folders/delete':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            target_folder = params.get('folder_path', [''])[0].strip().replace('\\', '/').strip('/')
            delete_mode = params.get('mode', ['keep_files'])[0]

            if not target_folder:
                self.send_json({'success': False, 'error': 'Invalid folder path'}, status=400)
                return

            items_to_modify = [item for item in DECRYPTED_INDEX if item['subfolder'] == target_folder or item['subfolder'].startswith(target_folder + '/')]

            if delete_mode == 'delete_files':
                commit_item_deletions(items_to_modify)
            else:
                for item in items_to_modify:
                    item['subfolder'] = ''
                    item['rel_path'] = item['name']
                save_index()
            self.send_json({'success': True, 'folder': target_folder, 'mode': delete_mode, 'count': len(items_to_modify)})
            return

        if parsed.path == '/api/file/star':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            enc_id = params.get('enc_id', [''])[0]
            
            item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
            if item:
                item['starred'] = not item.get('starred', False)
                save_index()
                self.send_json({'success': True, 'enc_id': enc_id, 'starred': item['starred']})
                return
            self.send_json({'success': False, 'error': 'File not found'}, status=404)
            return

        if parsed.path == '/api/file/move':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            enc_id = params.get('enc_id', [''])[0]
            target_sub = params.get('target_subfolder', [''])[0].strip().replace('\\', '/').strip('/')
            if target_sub in ['.', '..', '__UNCATEGORIZED__', '__ALL__']: target_sub = ''

            item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
            if item:
                item['subfolder'] = target_sub
                item['rel_path'] = f"{target_sub}/{item['name']}" if target_sub else item['name']
                save_index()
                self.send_json({'success': True, 'enc_id': enc_id})
                return
            self.send_json({'success': False, 'error': 'File not found'}, status=404)
            return

        if parsed.path == '/api/file/delete':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            enc_id = params.get('enc_id', [''])[0]

            item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
            if item:
                commit_item_deletions([item])
                self.send_json({'success': True, 'enc_id': enc_id})
                return
            self.send_json({'success': False, 'error': 'File not found'}, status=404)
            return

        # 1-Click Cryptographic SHA-256 Hash Duplicate Cleaner (Zero False-Positives Guarantee!)
        if parsed.path == '/api/admin/auto_clean_all_duplicates':
            if not ACTIVE_DEK and not ACTIVE_FERNET:
                self.send_json({'success': False, 'error': 'Vault locked'}, status=401)
                return

            hash_map = defaultdict(list)
            for item in DECRYPTED_INDEX:
                if item['name'].startswith('.'): continue
                enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                if os.path.exists(enc_fpath):
                    try:
                        with open(enc_fpath, 'rb') as ef: ciphertext = ef.read()
                        plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{item['enc_id']}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)
                        content_hash = hashlib.sha256(plaintext).hexdigest()
                        hash_map[content_hash].append(item)
                    except Exception:
                        pass

            to_remove = []
            deleted_count = 0
            freed_bytes = 0

            for chash, items in hash_map.items():
                if len(items) > 1:
                    items.sort(key=lambda x: x.get('mtime', 0))
                    for extra_item in items[1:]:
                        to_remove.append(extra_item)
                        deleted_count += 1
                        freed_bytes += extra_item['size']

            if deleted_count > 0:
                commit_item_deletions(to_remove)

            self.send_json({
                'success': True,
                'deleted_count': deleted_count,
                'freed_mb': f"{freed_bytes / (1024*1024):.2f} MB",
                'freed_gb': f"{freed_bytes / (1024*1024*1024):.2f} GB"
            })
            return

        if parsed.path == '/api/files/bulk_move':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            data = json.loads(body)
            enc_ids = data.get('enc_ids', [])
            target_sub = data.get('target_subfolder', '').strip().replace('\\', '/').strip('/')
            if target_sub in ['.', '..', '__UNCATEGORIZED__', '__ALL__']: target_sub = ''

            moved_count = 0
            for item in DECRYPTED_INDEX:
                if item['enc_id'] in enc_ids:
                    item['subfolder'] = target_sub
                    item['rel_path'] = f"{target_sub}/{item['name']}" if target_sub else item['name']
                    moved_count += 1

            if moved_count > 0: save_index()
            self.send_json({'success': True, 'count': moved_count})
            return

        if parsed.path == '/api/files/bulk_delete':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            data = json.loads(body)
            enc_ids = data.get('enc_ids', [])

            to_remove = [item for item in DECRYPTED_INDEX if item['enc_id'] in enc_ids]
            deleted_count = commit_item_deletions(to_remove)
            self.send_json({'success': True, 'count': deleted_count})
            return

        if parsed.path == '/api/files/bulk_star':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            data = json.loads(body)
            enc_ids = data.get('enc_ids', [])
            starred = data.get('starred', True)

            updated_count = 0
            for item in DECRYPTED_INDEX:
                if item['enc_id'] in enc_ids:
                    item['starred'] = starred
                    updated_count += 1

            if updated_count > 0: save_index()
            self.send_json({'success': True, 'count': updated_count})
            return

        if parsed.path == '/api/upload':
            content_type = self.headers.get('Content-Type', '')
            length = int(self.headers.get('Content-Length', 0))
            
            if 'multipart/form-data' in content_type and 'boundary=' in content_type and length > 0:
                boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode('utf-8')
                raw_body = self.rfile.read(length)

                parts = raw_body.split(b'--' + boundary)
                subfolder = ""
                filename = ""
                file_bytes = b""

                for part in parts:
                    if b'name="subfolder"' in part:
                        subfolder = part.split(b'\r\n\r\n')[1].rstrip(b'\r\n').decode('utf-8')
                    elif b'name="file";' in part:
                        headers_part, content_part = part.split(b'\r\n\r\n', 1)
                        content_part = content_part.rsplit(b'\r\n', 1)[0]
                        
                        header_lines = headers_part.decode('utf-8', errors='ignore').split('\r\n')
                        for line in header_lines:
                            if 'filename="' in line:
                                filename = line.split('filename="')[1].split('"')[0]
                        file_bytes = content_part

                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    self.send_json({'success': False, 'error': 'Uploaded file exceeds configured limit.'}, status=413)
                    return

                if filename and file_bytes and (ACTIVE_DEK or ACTIVE_FERNET):
                    try:
                        filename = validate_filename(filename)
                        clean_sub = normalize_subfolder(subfolder)
                    except ValueError as exc:
                        self.send_json({'success': False, 'error': str(exc)}, status=400)
                        return

                    enc_id = f"enc_{secrets.token_hex(16)}.enc"
                    enc_fpath = safe_vault_path(enc_id)

                    ciphertext = vault_encrypt(file_bytes, ACTIVE_DEK, context=f"media:{enc_id}") if ACTIVE_DEK else ACTIVE_FERNET.encrypt(file_bytes)
                    atomic_write(enc_fpath, ciphertext)

                    ext = os.path.splitext(filename)[1].lower()
                    is_video = ext in ['.mov', '.mp4', '.m4v', '.avi']
                    rel_path = f"{clean_sub}/{filename}" if clean_sub else filename
                    item_meta = {
                        "enc_id": enc_id,
                        "name": filename,
                        "subfolder": clean_sub,
                        "rel_path": rel_path,
                        "size": len(file_bytes),
                        "is_video": is_video,
                        "is_live_photo": False,
                        "mtime": time.time(),
                        "starred": False,
                        "enc_thumb_id": None
                    }

                    try:
                        DECRYPTED_INDEX.append(item_meta)
                        save_index()
                    except Exception:
                        if item_meta in DECRYPTED_INDEX:
                            DECRYPTED_INDEX.remove(item_meta)
                        try:
                            os.remove(enc_fpath)
                        except OSError:
                            pass
                        raise

                    self.send_json({'success': True, 'name': filename, 'enc_id': enc_id})
                    return

            self.send_json({'success': False, 'error': 'Invalid upload payload'}, status=400)
            return

        if parsed.path == '/api/admin/change_password':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            old_pwd = params.get('old_password', [''])[0]
            new_pwd = params.get('new_password', [''])[0]

            if not old_pwd or not new_pwd:
                self.send_json({'success': False, 'error': 'Both old and new passwords are required.'}, status=400)
                return

            if len(new_pwd) < MIN_PASSWORD_LENGTH:
                self.send_json({'success': False, 'error': f'New password must be at least {MIN_PASSWORD_LENGTH} characters.'}, status=400)
                return

            if not ACTIVE_DEK and not ACTIVE_FERNET:
                self.send_json({'success': False, 'error': 'Vault is locked.'}, status=401)
                return

            if ACTIVE_DEK:
                try:
                    change_vault_password(old_pwd, new_pwd)
                except Exception:
                    self.send_json({'success': False, 'error': 'Current password is incorrect.'}, status=403)
                    return
                self.send_json({'success': True, 'message': 'Master password changed successfully!'})
            else:
                # Legacy Fernet vault — verify by attempting decrypt
                try:
                    with open(SALT_PATH, 'rb') as sf:
                        old_salt = sf.read()
                    old_key = derive_key(old_pwd, old_salt)
                    test_fernet = Fernet(old_key)
                    with open(INDEX_PATH, 'rb') as idx_f:
                        test_fernet.decrypt(idx_f.read())
                except Exception:
                    self.send_json({'success': False, 'error': 'Current password is incorrect.'}, status=403)
                    return

                self.send_json({'success': False, 'error': 'Please migrate this v1 vault to v3 before changing its password.'}, status=400)
            return

        if parsed.path == '/api/admin/migrate_vault':
            source_version = active_vault_format_version()
            if source_version not in (1, 2):
                self.send_json({'success': False, 'error': 'No v1 or v2 vault to migrate (already v3 or vault locked).'}, status=400)
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
                params = urllib.parse.parse_qs(body)
                password = params.get('password', [''])[0]

                if not password:
                    self.send_json({'success': False, 'error': 'Password required for migration.'}, status=400)
                    return
                migrated_count = migrate_vault_to_v3(password)

                self.send_json({
                    'success': True,
                    'message': f'Vault migrated transactionally from v{source_version} to context-bound v3! {migrated_count} media files re-encrypted.',
                    'source_version': source_version,
                    'target_version': 3,
                    'migrated_count': migrated_count
                })

            except Exception as e:
                self.send_json({'success': False, 'error': f'Migration failed: {e}'}, status=500)
            return

        if parsed.path == '/api/admin/export_vault':
            if not ALLOW_DOWNLOADS:
                self.send_json({'success': False, 'error': 'Decrypted media export is disabled for this vault session.'}, status=403)
                return

            export_dir = os.path.join(VAULT_FOLDER, "Exported_Decrypted_Media")
            os.makedirs(export_dir, exist_ok=True)

            exported_count = 0
            if (ACTIVE_DEK or ACTIVE_FERNET) and DECRYPTED_INDEX:
                for item in DECRYPTED_INDEX:
                    if item['name'].startswith('.'): continue
                    enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                    if os.path.exists(enc_fpath):
                        try:
                            with open(enc_fpath, 'rb') as ef: ciphertext = ef.read()
                            plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{item['enc_id']}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)

                            clean_subfolder = normalize_subfolder(item.get('subfolder', ''))
                            safe_name = validate_filename(item['name'])
                            sub_dir = safe_child_path(export_dir, *clean_subfolder.split('/')) if clean_subfolder else export_dir
                            os.makedirs(sub_dir, exist_ok=True)
                            out_p = safe_child_path(sub_dir, safe_name)

                            atomic_write(out_p, plaintext)
                            exported_count += 1
                        except Exception as e:
                            print(f"Export error for {item['name']}: {e}")

            self.send_json({'success': True, 'count': exported_count, 'path': export_dir})
            return

        if parsed.path == '/shutdown':
            if not ENABLE_REMOTE_SHUTDOWN:
                self.send_json({'success': False, 'error': 'Remote shutdown is disabled. Set CRYPTHAVEN_ENABLE_SHUTDOWN=true to enable.'}, status=403)
                return
            system_root = os.environ.get('SystemRoot', r'C:\Windows')
            shutdown_exe = os.path.join(system_root, 'System32', 'shutdown.exe')
            if not os.path.isfile(shutdown_exe):
                self.send_json({'success': False, 'error': 'Windows shutdown executable not found.'}, status=500)
                return
            try:
                subprocess.Popen([shutdown_exe, '/s', '/t', '5'], shell=False)
            except OSError as exc:
                self.send_json({'success': False, 'error': f'Unable to schedule shutdown: {exc}'}, status=500)
                return
            print("--- RECEIVED REMOTE SHUTDOWN COMMAND ---")
            self.send_json({'success': True, 'message': 'PC shutting down in 5 seconds...'})
            return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/login':
            self.send_html(HTML_LOGIN)
            return

        if parsed.path == '/api/vault_status':
            is_init = is_valid_vault(VAULT_FOLDER)
            format_version = active_vault_format_version()
            self.send_json({
                'initialized': is_init,
                'allow_downloads': ALLOW_DOWNLOADS,
                'is_legacy': format_version == 1,
                'vault_format_version': format_version,
                'migration_available': format_version in (1, 2)
            })
            return

        if not self.check_auth():
            if parsed.path.startswith('/api/'):
                self.send_json({'error': 'Unauthorized'}, status=401)
                return
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return

        if parsed.path == '/':
            self.send_html(HTML_GALLERY)
            return

        if parsed.path == '/api/folders':
            folder_counts = defaultdict(int)
            for item in DECRYPTED_INDEX:
                if item['name'].startswith('.'): continue
                folder_counts[item['subfolder']] += 1

            subfolders = set(item['subfolder'] for item in DECRYPTED_INDEX if item['subfolder'])
            
            folder_list = [
                {"name": "🌐 All Media", "path": "__ALL__", "count": sum(folder_counts.values())},
                {"name": "📂 Uncategorized", "path": "__UNCATEGORIZED__", "count": folder_counts['']},
                {"name": "⭐ Favorites", "path": "__FAVORITES__", "count": sum(1 for item in DECRYPTED_INDEX if item.get('starred'))}
            ]
            
            for sf in sorted(subfolders):
                folder_list.append({"name": sf, "path": sf, "count": folder_counts[sf]})
                
            self.send_json({'folders': folder_list})
            return

        if parsed.path == '/api/files':
            query = urllib.parse.parse_qs(parsed.query)
            target_sub = query.get('subfolder', ['__ALL__'])[0].strip().replace('\\', '/').strip('/')
            sort_by = query.get('sort', ['newest'])[0]
            search_query = query.get('q', [''])[0].lower().strip()

            filtered_files = []
            for idx_id, item in enumerate(DECRYPTED_INDEX):
                if item['name'].startswith('.'): continue

                if target_sub == '__FAVORITES__':
                    if not item.get('starred', False): continue
                elif target_sub == '__UNCATEGORIZED__':
                    if item['subfolder'] != '': continue
                elif target_sub != '__ALL__':
                    if item['subfolder'] != target_sub: continue

                if search_query and search_query not in item['name'].lower():
                    continue

                sub = item.get('subfolder', '')
                if sub is None: sub = ''
                filtered_files.append({
                    'idx': idx_id,
                    'name': item.get('name', ''),
                    'enc_id': item.get('enc_id', ''),
                    'subfolder': sub,
                    'size': f"{item.get('size', 0) / (1024*1024):.2f} MB",
                    'raw_size': item.get('size', 0),
                    'is_video': item.get('is_video', False),
                    'is_live_photo': item.get('is_live_photo', False),
                    'mtime': item.get('mtime', 0),
                    'starred': item.get('starred', False)
                })

            if sort_by == 'newest': filtered_files.sort(key=lambda x: x['mtime'], reverse=True)
            elif sort_by == 'oldest': filtered_files.sort(key=lambda x: x['mtime'])
            elif sort_by == 'size_desc': filtered_files.sort(key=lambda x: x['raw_size'], reverse=True)
            elif sort_by == 'size_asc': filtered_files.sort(key=lambda x: x['raw_size'])
            elif sort_by == 'name': filtered_files.sort(key=lambda x: x['name'].lower())

            self.send_json({'files': filtered_files, 'total': len(filtered_files), 'subfolder': target_sub})
            return

        # Cryptographic SHA-256 Hash Duplicate Scanner
        if parsed.path == '/api/admin/duplicates':
            if not ACTIVE_DEK and not ACTIVE_FERNET:
                self.send_json({'success': False, 'error': 'Vault locked'}, status=401)
                return

            query = urllib.parse.parse_qs(parsed.query)
            limit_param = query.get('limit', ['500'])[0]

            hash_map = defaultdict(list)
            for item in DECRYPTED_INDEX:
                if item['name'].startswith('.'): continue
                enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                if os.path.exists(enc_fpath):
                    try:
                        with open(enc_fpath, 'rb') as ef: ciphertext = ef.read()
                        plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{item['enc_id']}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)
                        chash = hashlib.sha256(plaintext).hexdigest()
                        hash_map[chash].append({
                            'enc_id': item['enc_id'],
                            'name': item['name'],
                            'size': item['size'],
                            'size_mb': f"{item['size']/(1024*1024):.2f} MB",
                            'subfolder': item['subfolder'],
                            'is_video': item['is_video'],
                            'is_live_photo': item.get('is_live_photo', False),
                            'mtime': item.get('mtime', 0)
                        })
                    except Exception:
                        pass

            duplicate_groups = []
            total_waste_bytes = 0
            for chash, items in hash_map.items():
                if len(items) > 1:
                    items.sort(key=lambda x: x['mtime'])
                    sz = items[0]['size']
                    duplicate_groups.append({
                        'size_raw': sz,
                        'size_formatted': f"{sz/(1024*1024):.2f} MB",
                        'copies_count': len(items),
                        'items': items
                    })
                    total_waste_bytes += sz * (len(items) - 1)

            duplicate_groups.sort(key=lambda x: x['size_raw'], reverse=True)
            res_groups = duplicate_groups if limit_param == 'all' else duplicate_groups[:int(limit_param)]

            self.send_json({
                'groups_count': len(duplicate_groups),
                'displayed_count': len(res_groups),
                'potential_waste_mb': f"{total_waste_bytes / (1024*1024):.2f} MB",
                'potential_waste_gb': f"{total_waste_bytes / (1024*1024*1024):.2f} GB",
                'duplicate_groups': res_groups
            })
            return

        if parsed.path == '/api/admin/stats':
            total_size = 0
            photos_count = 0
            videos_count = 0
            starred_count = 0
            size_map = {}
            duplicates_count = 0

            for item in DECRYPTED_INDEX:
                if item['name'].startswith('.'): continue
                total_size += item['size']
                if item['is_video']: videos_count += 1
                else: photos_count += 1
                if item.get('starred'): starred_count += 1

                sz = item['size']
                size_map[sz] = size_map.get(sz, 0) + 1

            for sz, cnt in size_map.items():
                if cnt > 1: duplicates_count += (cnt - 1)

            total_disk, used_disk, free_disk = shutil.disk_usage(VAULT_FOLDER)
            gdrive_found = find_google_drive_folder() is not None
            format_version = active_vault_format_version()

            self.send_json({
                'total_files': len(DECRYPTED_INDEX),
                'total_vault_mb': f"{total_size / (1024*1024):.2f} MB",
                'total_vault_gb': f"{total_size / (1024*1024*1024):.2f} GB",
                'photos_count': photos_count,
                'videos_count': videos_count,
                'starred_count': starred_count,
                'potential_duplicates': duplicates_count,
                'free_disk_gb': f"{free_disk / (1024*1024*1024):.2f} GB",
                'gdrive_available': gdrive_found,
                'enable_remote_shutdown': ENABLE_REMOTE_SHUTDOWN,
                'is_legacy': format_version == 1,
                'vault_format_version': format_version,
                'migration_available': format_version in (1, 2)
            })
            return

        if parsed.path.startswith('/thumb/'):
            enc_id = urllib.parse.unquote(parsed.path[7:])
            if '?' in enc_id: enc_id = enc_id.split('?')[0]
            
            item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
            
            if item and item.get('enc_thumb_id'):
                enc_thumb_path = os.path.join(DATA_DIR, item['enc_thumb_id'])
                if os.path.exists(enc_thumb_path) and (ACTIVE_DEK or ACTIVE_FERNET):
                    try:
                        with open(enc_thumb_path, 'rb') as ef: ciphertext = ef.read()
                        thumb_bytes = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"thumb:{item['enc_thumb_id']}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)
                        self.send_bytes(thumb_bytes, 'image/jpeg')
                        return
                    except Exception: pass

            try:
                enc_file_path = safe_vault_path(enc_id)
            except ValueError:
                self.send_json({'error': 'Invalid path'}, status=404)
                return
            if os.path.exists(enc_file_path) and (ACTIVE_DEK or ACTIVE_FERNET):
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{enc_id}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)
                    
                    with Image.open(io.BytesIO(plaintext)) as img:
                        img.thumbnail((200, 200))
                        if img.mode != 'RGB': img = img.convert('RGB')
                        thumb_io = io.BytesIO()
                        img.save(thumb_io, 'JPEG', quality=75)
                        thumb_bytes = thumb_io.getvalue()

                        enc_thumb_id = f"enc_t_{secrets.token_hex(8)}.enc"
                        enc_thumb_fpath = os.path.join(DATA_DIR, enc_thumb_id)
                        enc_thumb_bytes = vault_encrypt(thumb_bytes, ACTIVE_DEK, context=f"thumb:{enc_thumb_id}") if ACTIVE_DEK else ACTIVE_FERNET.encrypt(thumb_bytes)
                        with open(enc_thumb_fpath, 'wb') as tf:
                            tf.write(enc_thumb_bytes)

                        if item:
                            item['enc_thumb_id'] = enc_thumb_id
                            save_index()

                        self.send_bytes(thumb_bytes, 'image/jpeg')
                        return
                except Exception as e:
                    print(f"Decryption / Thumbnail error for {enc_id}: {e}")

        if parsed.path.startswith('/media/'):
            enc_id = urllib.parse.unquote(parsed.path[7:])
            if '?' in enc_id: enc_id = enc_id.split('?')[0]
            try:
                enc_file_path = safe_vault_path(enc_id)
            except ValueError:
                self.send_json({'error': 'Invalid path'}, status=404)
                return

            if os.path.exists(enc_file_path) and (ACTIVE_DEK or ACTIVE_FERNET):
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{enc_id}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)

                    item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
                    is_video = item['is_video'] if item else False

                    if is_video:
                        total_len = len(plaintext)
                        range_header = self.headers.get('Range')

                        if range_header and '=' in range_header:
                            range_spec = range_header.split('=')[1]
                            parts = range_spec.split('-')
                            start = int(parts[0]) if parts[0] else 0
                            end = int(parts[1]) if parts[1] and parts[1].isdigit() else total_len - 1
                            if end >= total_len: end = total_len - 1

                            chunk_len = end - start + 1
                            chunk = plaintext[start : end + 1]

                            try:
                                self.send_response(206)
                                self.inject_security_headers()
                                self.send_header('Content-Type', 'video/mp4')
                                self.send_header('Content-Range', f'bytes {start}-{end}/{total_len}')
                                self.send_header('Content-Length', str(chunk_len))
                                self.send_header('Accept-Ranges', 'bytes')
                                self.send_header('Cache-Control', 'private, no-store')
                                self.end_headers()
                                self.wfile.write(chunk)
                                return
                            except Exception:
                                pass
                        else:
                            self.send_bytes(plaintext, 'video/mp4')
                            return
                    else:
                        with Image.open(io.BytesIO(plaintext)) as img:
                            if img.mode != 'RGB': img = img.convert('RGB')
                            media_io = io.BytesIO()
                            img.save(media_io, 'JPEG', quality=85)
                            self.send_bytes(media_io.getvalue(), 'image/jpeg')
                            return
                except Exception as e:
                    print(f"Decryption / Media error for {enc_id}: {e}")

        if parsed.path.startswith('/download/'):
            if not ALLOW_DOWNLOADS:
                self.send_json({'success': False, 'error': 'Media downloading is disabled for this vault session.'}, status=403)
                return
            enc_id = urllib.parse.unquote(parsed.path[10:])
            if '?' in enc_id: enc_id = enc_id.split('?')[0]
            try:
                enc_file_path = safe_vault_path(enc_id)
            except ValueError:
                self.send_json({'error': 'Invalid path'}, status=404)
                return

            if os.path.exists(enc_file_path) and (ACTIVE_DEK or ACTIVE_FERNET):
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = vault_decrypt(ciphertext, ACTIVE_DEK, fernet_fallback=ACTIVE_FERNET, context=f"media:{enc_id}") if ACTIVE_DEK else ACTIVE_FERNET.decrypt(ciphertext)

                    item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
                    filename = item['name'] if item else 'download'
                    mime_type, _ = mimetypes.guess_type(filename)
                    if not mime_type:
                        mime_type = 'application/octet-stream'

                    safe_filename = urllib.parse.quote(filename)
                    fallback_filename = ''.join(
                        ch if 32 <= ord(ch) < 127 and ch not in {'"', '\\'} else '_'
                        for ch in os.path.basename(filename)
                    ) or 'download'

                    self.send_response(200)
                    self.inject_security_headers()
                    self.send_header('Content-Type', mime_type)
                    self.send_header('Content-Length', str(len(plaintext)))
                    self.send_header('Content-Disposition', f'attachment; filename="{fallback_filename}"; filename*=UTF-8\'\'{safe_filename}')
                    self.send_header('Cache-Control', 'private, no-store')
                    self.end_headers()
                    self.wfile.write(plaintext)
                    return
                except Exception as e:
                    print(f"Decryption / Download error for {enc_id}: {e}")

        self.send_response(404)
        self.end_headers()

HTML_LOGIN = """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>CryptHaven Sign In</title>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style>
        * { box-sizing: border-box; }
        body { 
            background: radial-gradient(circle at 50% 30%, #1e293b 0%, #090d16 100%);
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex; height: 100vh; align-items: center; justify-content: center; margin: 0; 
        }
        .card { 
            background: rgba(30, 41, 59, 0.85);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            padding: 2.5rem 2rem;
            border-radius: 1.5rem;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7), 0 0 0 1px rgba(56, 189, 248, 0.15);
            width: 88%; max-width: 360px; text-align: center;
        }
        .lock-icon {
            font-size: 2.2rem; margin-bottom: 0.5rem; display: inline-block;
            filter: drop-shadow(0 0 10px rgba(56, 189, 248, 0.4));
        }
        h2 { margin: 0 0 0.4rem 0; font-size: 1.35rem; color: #f8fafc; font-weight: 700; }
        p.sub { margin: 0 0 1.2rem 0; font-size: 0.85rem; color: #94a3b8; line-height: 1.4; }
        .badge {
            display: inline-block; background: rgba(56, 189, 248, 0.1); color: #38bdf8;
            padding: 0.25rem 0.75rem; border-radius: 1rem; font-size: 0.78rem; font-weight: 600;
            margin-bottom: 0.8rem; border: 1px solid rgba(56, 189, 248, 0.2);
        }
        input { 
            width: 100%; padding: 0.9rem; margin-bottom: 0.9rem;
            border-radius: 0.85rem; border: 1px solid rgba(51, 65, 85, 0.8);
            background: rgba(15, 23, 42, 0.9); color: #fff; font-size: 1.05rem;
            text-align: center; outline: none; transition: all 0.2s ease;
        }
        input:focus { border-color: #38bdf8; box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15); }
        button { 
            width: 100%; padding: 0.9rem; border-radius: 0.85rem; border: none;
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: #fff; font-weight: 700; font-size: 1.05rem; cursor: pointer;
            box-shadow: 0 4px 14px rgba(2, 132, 199, 0.4);
            transition: all 0.2s ease; margin-top: 0.3rem;
        }
        button:active { transform: scale(0.98); }
        .err { color: #f87171; margin-top: 0.9rem; font-size: 0.85rem; font-weight: 500; }
    </style>
</head>
<body>
    <div class="card">
        <div class="lock-icon" id="lockIcon">🔑</div>
        <h2 id="cardTitle">Sign In</h2>
        <p class="sub" id="cardSub">Enter passcode to unlock vault</p>
        
        <form id="loginForm" method="POST" action="/login" onsubmit="return handleFormSubmit(event)">
            <input type="password" id="pwd" name="password" placeholder="Passcode" autofocus>
            <input type="password" id="pwd_confirm" placeholder="Confirm Passcode" style="display: none;">
            <button type="submit" id="submitBtn">Unlock Vault</button>
        </form>
        <div id="err" class="err"></div>
    </div>
    <script>
        let isInitialized = true;

        async function checkStatus() {
            try {
                const res = await fetch('/api/vault_status');
                const data = await res.json();
                isInitialized = data.initialized;

                if (!isInitialized) {
                    document.getElementById('lockIcon').innerText = '🛡️';
                    document.getElementById('cardTitle').innerText = 'Initialize New Vault';
                    document.getElementById('cardSub').innerText = 'Set a master passcode for your new media vault. Make sure to remember this passcode!';
                    document.getElementById('pwd_confirm').style.display = 'block';
                    document.getElementById('submitBtn').innerText = 'Initialize Vault & Sign In';
                } else {
                    document.getElementById('lockIcon').innerText = '🔑';
                    document.getElementById('cardTitle').innerText = 'Unlock Vault';
                    document.getElementById('cardSub').innerText = 'Enter passcode to decrypt media';
                    document.getElementById('pwd_confirm').style.display = 'none';
                    document.getElementById('submitBtn').innerText = 'Unlock Vault';
                }
            } catch(e) {
                console.error("Status check failed:", e);
            }
        }

        async function handleFormSubmit(e) {
            const pwd = document.getElementById('pwd').value;
            const errEl = document.getElementById('err');
            errEl.innerText = '';

            if (!pwd) {
                if(e) e.preventDefault();
                errEl.innerText = 'Please enter a passcode.';
                return false;
            }

            if (!isInitialized) {
                const confirmPwd = document.getElementById('pwd_confirm').value;
                if (pwd.length < 4) {
                    if(e) e.preventDefault();
                    errEl.innerText = 'Passcode must be at least 4 characters long.';
                    return false;
                }
                if (pwd !== confirmPwd) {
                    if(e) e.preventDefault();
                    errEl.innerText = 'Passcodes do not match! Please re-check.';
                    return false;
                }
            }
            return true;
        }

        document.getElementById('pwd').addEventListener('keypress', (e) => { 
            if (e.key === 'Enter') {
                if (!isInitialized) {
                    e.preventDefault();
                    document.getElementById('pwd_confirm').focus();
                }
            }
        });

        checkStatus();
    </script>
</body>
</html>"""

HTML_GALLERY = """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>CryptHaven</title>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style>
        * { box-sizing: border-box; touch-action: manipulation; }
        body { 
            background: #090d16; color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
            margin: 0; padding: 0; -webkit-user-select: none; user-select: none;
            width: 100vw; overflow-x: hidden;
        }
        
        /* Ultra-Sleek Frosted Glass Header with Strict 100% Fluid Boundary Fit */
        header { 
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            padding: 0.6rem 0.75rem; position: sticky; top: 0; z-index: 10;
            border-bottom: 1px solid rgba(56, 189, 248, 0.15);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            width: 100%; box-sizing: border-box; overflow: hidden;
        }
        
        .top-row { 
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 0.5rem; width: 100%; min-width: 0; gap: 0.4rem;
        }
        .title-group { display: flex; align-items: center; gap: 0.4rem; min-width: 0; flex-shrink: 1; overflow: hidden; }
        
        header h1 { 
            margin: 0; font-size: 1.15rem; font-weight: 800;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        
        .header-btns { display: flex; gap: 0.35rem; align-items: center; flex-shrink: 0; }
        
        .badge { 
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 0.2rem 0.5rem; border-radius: 1rem;
            font-size: 0.7rem; color: #38bdf8; font-weight: 700;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.15);
            white-space: nowrap; flex-shrink: 0;
        }
        
        .btn-hdr-icon { 
            border: none; padding: 0.45rem 0.6rem; border-radius: 0.6rem; font-size: 0.9rem;
            cursor: pointer; touch-action: manipulation; display: flex; align-items: center; justify-content: center;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3); flex-shrink: 0;
        }
        .btn-hdr-icon:hover { transform: translateY(-2px); }
        .btn-select-toggle { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: #fff; }
        .btn-folder-toggle { background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); color: #fff; }
        .btn-menu-toggle { background: linear-gradient(135deg, #334155 0%, #1e293b 100%); color: #fff; border: 1px solid rgba(255,255,255,0.1); }

        .toolbar { display: flex; flex-direction: column; gap: 0.4rem; width: 100%; min-width: 0; }
        .toolbar-row { display: flex; gap: 0.4rem; align-items: center; width: 100%; min-width: 0; overflow: hidden; }
        
        input[type="text"], select { 
            padding: 0.55rem 0.7rem; border-radius: 0.65rem;
            border: 1px solid rgba(51, 65, 85, 0.8);
            background: rgba(15, 23, 42, 0.9); color: #38bdf8; font-weight: 700; font-size: 0.82rem;
            outline: none; transition: all 0.2s ease; box-sizing: border-box;
        }
        
        #folder-select { flex: 1; min-width: 0; width: 100%; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }
        #sort-select { width: 115px; flex-shrink: 0; min-width: 110px; text-overflow: ellipsis; overflow: hidden; }

        input[type="text"] { flex: 1; width: 100%; color: #fff; font-weight: 400; min-width: 0; }
        input[type="text"]:focus, select:focus { 
            border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2); 
        }

        /* Multi-Select Floating Action Glass Bar */
        .bulk-bar { 
            display: none; background: rgba(2, 132, 199, 0.9);
            backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
            padding: 0.75rem 1.2rem; position: sticky; top: 108px; z-index: 15;
            align-items: center; justify-content: space-between;
            border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 1rem;
            margin: 0.5rem 0.5rem 0 0.5rem; box-shadow: 0 10px 30px rgba(2, 132, 199, 0.4);
        }
        .bulk-bar.active { display: flex; }
        .bulk-btns { display: flex; gap: 0.5rem; }
        .btn-bulk { 
            background: rgba(15, 23, 42, 0.5); color: #fff; border: 1px solid rgba(255,255,255,0.3);
            padding: 0.45rem 0.85rem; border-radius: 0.6rem; font-weight: 700; font-size: 0.8rem; cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn-bulk:active { transform: scale(0.95); }

        /* Modern Grid Layout with Smooth Cards */
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(105px, 1fr)); gap: 6px; padding: 6px; width: 100%; box-sizing: border-box; }
        .thumb { 
            aspect-ratio: 1; background: #1e293b; overflow: hidden; position: relative;
            cursor: pointer; border-radius: 10px; box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.06); transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .thumb:hover { transform: translateY(-3px) scale(1.02); box-shadow: 0 8px 24px rgba(56, 189, 248, 0.25); border-color: rgba(56, 189, 248, 0.4); }
        .thumb img, .thumb video { width: 100%; height: 100%; object-fit: cover; transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .thumb:hover img { transform: scale(1.06); }

        /* Sleek Badge Overlay Pills */
        .vid-icon { 
            position: absolute; top: 6px; right: 6px; background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(8px); color: #38bdf8; padding: 3px 8px; border-radius: 6px;
            font-size: 0.68rem; font-weight: 800; border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .live-icon { 
            position: absolute; top: 6px; right: 6px; background: rgba(245, 158, 11, 0.9);
            backdrop-filter: blur(8px); color: #fff; padding: 3px 8px; border-radius: 6px;
            font-size: 0.68rem; font-weight: 800; box-shadow: 0 2px 8px rgba(245, 158, 11, 0.4);
        }
        .star-icon { 
            position: absolute; top: 6px; left: 6px; background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(8px); color: #fbbf24; padding: 2px 6px; border-radius: 6px; font-size: 0.85rem;
        }
        
        .thumb-checkbox { display: none; position: absolute; bottom: 6px; right: 6px; width: 22px; height: 22px; accent-color: #38bdf8; z-index: 5; }
        body.select-mode .thumb-checkbox { display: block; }

        /* Sleek Modal Panels */
        .modal { 
            display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            z-index: 200; align-items: center; justify-content: center; padding: 1rem;
        }
        .modal.active { display: flex; }
        .m-card { 
            background: rgba(30, 41, 59, 0.95); border: 1px solid rgba(56, 189, 248, 0.2);
            padding: 1.6rem; border-radius: 1.25rem; width: 100%; max-width: 440px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7); max-height: 90vh; overflow-y: auto;
        }
        .m-card h3 { margin-top: 0; color: #38bdf8; font-weight: 800; letter-spacing: -0.01em; }
        .m-card input, .m-card select { 
            width: 100%; padding: 0.75rem; margin: 0.6rem 0; border-radius: 0.65rem;
            border: 1px solid rgba(51, 65, 85, 0.8); background: #0f172a; color: #fff; box-sizing: border-box;
        }
        .m-card button { 
            width: 100%; padding: 0.85rem; border-radius: 0.75rem; border: none;
            font-weight: 700; margin-top: 0.5rem; cursor: pointer; transition: all 0.2s ease;
        }
        .m-card button:hover { filter: brightness(1.1); transform: translateY(-1px); }

        .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; margin: 0.8rem 0; }
        .stat-box { background: rgba(15, 23, 42, 0.8); padding: 0.9rem; border-radius: 0.75rem; text-align: center; border: 1px solid rgba(51, 65, 85, 0.6); }
        .stat-box.clickable { cursor: pointer; border-color: rgba(245, 158, 11, 0.6); background: rgba(30, 27, 75, 0.6); }
        .stat-num { font-size: 1.3rem; font-weight: 800; color: #38bdf8; }
        .stat-label { font-size: 0.75rem; color: #94a3b8; font-weight: 600; margin-top: 2px; }

        /* Folder Manager List Item Cards */
        .f-item { background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(51, 65, 85, 0.6); border-radius: 0.75rem; padding: 0.85rem; margin-bottom: 0.6rem; display: flex; justify-content: space-between; align-items: center; }
        .f-info { font-size: 0.9rem; color: #f8fafc; font-weight: 700; }
        .f-subcount { font-size: 0.75rem; color: #94a3b8; font-weight: 500; margin-top: 2px; }
        .f-actions { display: flex; gap: 0.35rem; }
        .btn-f-act { border: none; padding: 0.45rem 0.65rem; border-radius: 0.5rem; font-size: 0.75rem; font-weight: 700; cursor: pointer; }

        /* Menu Drawer Options */
        .menu-opt-btn { 
            background: rgba(15, 23, 42, 0.8); color: #f8fafc; border: 1px solid rgba(51, 65, 85, 0.8);
            padding: 0.95rem 1.1rem; border-radius: 0.85rem; text-align: left; font-size: 0.95rem; font-weight: 700;
            display: flex; align-items: center; justify-content: space-between; cursor: pointer; margin-bottom: 0.6rem;
            transition: all 0.2s ease;
        }
        .menu-opt-btn:hover { background: rgba(30, 41, 59, 0.9); border-color: #38bdf8; transform: translateX(3px); }

        /* Ultra-Smooth Zero-Flash Progressive Full-Screen Dual-Layer Lightbox Viewer */
        .viewer { display: none; position: fixed; inset: 0; background: #000; z-index: 100; flex-direction: column; }
        .viewer.active { display: flex; }
        .v-header { padding: 0.8rem 1rem; display: flex; justify-content: space-between; align-items: center; background: rgba(15,23,42,0.95); backdrop-filter: blur(12px); z-index: 110; }
        .v-title { font-size: 0.85rem; color: #cbd5e1; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 55%; }
        .v-hdr-btns { display: flex; gap: 0.4rem; align-items: center; }
        .v-star-btn { background: rgba(51, 65, 85, 0.8); color: #fbbf24; border: none; padding: 0.4rem 0.7rem; border-radius: 0.6rem; font-size: 1rem; cursor: pointer; }
        .v-dl-btn { background: rgba(51, 65, 85, 0.8); color: #10b981; border: none; padding: 0.4rem 0.7rem; border-radius: 0.6rem; font-size: 1rem; cursor: pointer; transition: all 0.2s ease; }
        .v-dl-btn:hover { background: rgba(16, 185, 129, 0.3); transform: scale(1.05); }
        .v-opt-btn { background: rgba(51, 65, 85, 0.8); color: #38bdf8; border: none; padding: 0.4rem 0.8rem; border-radius: 0.6rem; font-weight: 700; font-size: 0.85rem; cursor: pointer; }
        .v-close { background: none; border: none; color: #fff; font-size: 1.5rem; padding: 0 0.5rem; cursor: pointer; touch-action: manipulation; }
        
        .v-body { flex: 1; display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden; touch-action: none; background: #000; }
        .v-media-container { position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; }
        
        /* Thumbnail Placeholder Scaled to 100% Screen Footprint with Soft Blur (Zero Flicker) */
        .v-thumb-placeholder { 
            position: absolute; width: 100%; height: 100%; object-fit: contain;
            filter: blur(8px); transform: scale(1.05); transition: opacity 0.22s ease; z-index: 1; 
        }
        
        .v-full-media { 
            position: relative; width: 100%; height: 100%; object-fit: contain;
            opacity: 0; transition: opacity 0.22s cubic-bezier(0.4, 0, 0.2, 1); z-index: 2;
            transform-origin: center center; will-change: transform; 
        }
        
        /* Small discreet floating side navigation arrows with auto-fade */
        .v-nav-arrow {
            position: absolute; top: 50%; transform: translateY(-50%);
            width: 42px; height: 42px; border-radius: 50%;
            background: rgba(15, 23, 42, 0.7); color: #f8fafc;
            backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.15);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.4rem; font-weight: bold; cursor: pointer; z-index: 110;
            transition: opacity 0.35s ease, transform 0.2s ease, background 0.2s ease;
            opacity: 1; user-select: none; -webkit-user-select: none;
            touch-action: manipulation; box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        .v-prev-arrow { left: 0.8rem; }
        .v-next-arrow { right: 0.8rem; }
        .v-nav-arrow:hover { background: rgba(30, 41, 59, 0.95); transform: translateY(-50%) scale(1.1); border-color: #38bdf8; }
        .v-nav-arrow.faded { opacity: 0; pointer-events: none; }

        /* DRM Anti-Save & Anti-Screenshot Protection for Grid & Viewer */
        .no-save img, 
        .no-save video, 
        .no-save .v-full-media, 
        .no-save .v-thumb-placeholder,
        .no-save .thumb img,
        .no-save #grid img {
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -khtml-user-select: none !important;
            -moz-user-select: none !important;
            -ms-user-select: none !important;
            user-select: none !important;
            -webkit-user-drag: none !important;
            user-drag: none !important;
        }
        .no-save .thumb, .no-save #grid {
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            user-select: none !important;
        }
        @media print {
            body { display: none !important; }
        }

        /* DRM Hidden Screen Overlay with Eyeball Icon */
        .drm-hidden-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.96);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            z-index: 99999;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: #94a3b8;
            user-select: none;
            -webkit-user-select: none;
            cursor: pointer;
        }
        .drm-hidden-overlay.active {
            display: flex;
        }
        .drm-eye-icon {
            font-size: 4rem;
            margin-bottom: 0.6rem;
            opacity: 0.85;
            filter: drop-shadow(0 4px 12px rgba(0,0,0,0.5));
            animation: drmPulse 2s infinite ease-in-out;
        }
        .drm-hidden-text {
            font-size: 1.25rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #64748b;
        }
        .drm-tap-notice {
            font-size: 0.75rem;
            color: #475569;
            margin-top: 0.8rem;
            font-weight: 600;
        }
        @keyframes drmPulse {
            0%, 100% { transform: scale(1); opacity: 0.85; }
            50% { transform: scale(1.05); opacity: 1; }
        }
    </style>
</head>
<body>
    <div id="drm-hidden-overlay" class="drm-hidden-overlay" onclick="hideDrmHiddenScreen()">
        <div class="drm-eye-icon">👁️</div>
        <div class="drm-hidden-text">Protection Active</div>
        <div class="drm-tap-notice">Tap anywhere to resume viewing</div>
    </div>
    <div id="legacy-banner" style="display:none; background:#d97706; color:#ffffff; text-align:center; padding:0.6rem 1rem; font-weight:600; font-size:0.9rem; cursor:pointer;" onclick="openAdminModal(); migrateVaultPrompt();">⚠️ Older Vault Format — Click here to migrate transactionally to context-bound v3 encryption</div>
    <header>
        <div class="top-row">
            <div class="title-group">
                <h1>CryptHaven</h1>
                <div class="badge" id="count-badge">...</div>
            </div>
            <div class="header-btns">
                <button class="btn-hdr-icon btn-select-toggle" id="select-mode-btn" onclick="toggleSelectMode()">☑️</button>
                <button class="btn-hdr-icon btn-folder-toggle" onclick="openFolderManagerModal()">📁</button>
                <button class="btn-hdr-icon btn-menu-toggle" onclick="openMenuModal()">⚙️</button>
            </div>
        </div>
        <div class="toolbar">
            <div class="toolbar-row">
                <input type="text" id="search-input" placeholder="🔍 Search media by name..." oninput="handleSearch()">
            </div>
            <div class="toolbar-row">
                <select id="folder-select" onchange="changeSubfolder()"></select>
                <select id="sort-select" onchange="changeSort()">
                    <option value="newest">🕒 Newest</option>
                    <option value="oldest">🕒 Oldest</option>
                    <option value="size_desc">💾 Size ⬇</option>
                    <option value="size_asc">💾 Size ⬆</option>
                    <option value="name">🔤 Name A-Z</option>
                </select>
            </div>
        </div>
    </header>

    <div class="bulk-bar" id="bulk-bar">
        <span style="font-weight:bold; font-size:0.9rem;" id="bulk-count">0 Selected</span>
        <div class="bulk-btns">
            <button class="btn-bulk" onclick="openBulkMoveModal()">📁 Move</button>
            <button class="btn-bulk" onclick="submitBulkStar(true)">⭐ Star</button>
            <button class="btn-bulk" onclick="submitBulkDelete()" style="background:#dc2626;">🗑️ Delete</button>
        </div>
    </div>

    <div class="grid" id="grid"></div>

    <div class="modal" id="menu-modal">
        <div class="m-card">
            <h3>⚙️ Actions & Settings</h3>
            
            <button class="menu-opt-btn" onclick="closeModal('menu-modal'); openUploadModal();">
                <span>📤 Upload Media</span>
                <span>➔</span>
            </button>

            <button class="menu-opt-btn" style="border-color:#38bdf8;" onclick="triggerCloudBackup()">
                <span>☁️ Cloud Backup to Google Drive</span>
                <span>➔</span>
            </button>
            
            <button class="menu-opt-btn" onclick="closeModal('menu-modal'); openNewFolderModal();">
                <span>➕ Create Folder</span>
                <span>➔</span>
            </button>

            <button class="menu-opt-btn" onclick="closeModal('menu-modal'); openFolderManagerModal();">
                <span>📁 Folder Manager</span>
                <span>➔</span>
            </button>
            
            <button class="menu-opt-btn" onclick="closeModal('menu-modal'); openAdminModal();">
                <span>📊 Admin & Statistics</span>
                <span>➔</span>
            </button>

            <button class="menu-opt-btn" style="border-color:#ef4444; color:#ef4444;" onclick="lockVaultNow()">
                <span>🔒 Lock Session</span>
                <span>➔</span>
            </button>

            <button style="background:#334155; color:#fff; margin-top:0.8rem;" onclick="closeModal('menu-modal')">Close Menu</button>
        </div>
    </div>

    <div class="modal" id="bulk-move-modal">
        <div class="m-card">
            <h3>📁 Bulk Move Selected Items</h3>
            <label style="font-size:0.85rem; color:#cbd5e1;">Target Subfolder:</label>
            <select id="bulk-target-folder"></select>
            <button style="background:#0284c7; color:#fff;" onclick="submitBulkMove()">Move Items</button>
            <button style="background:#334155; color:#fff;" onclick="closeModal('bulk-move-modal')">Cancel</button>
        </div>
    </div>

    <div class="modal" id="folder-modal">
        <div class="m-card">
            <h3 id="folder-modal-title">📁 Create New Folder</h3>
            <label style="font-size:0.85rem; color:#cbd5e1;">Parent Location:</label>
            <select id="create-parent-folder-select"></select>
            <input type="text" id="new-folder-input" placeholder="Folder Name (e.g. Vacation_2026)">
            <button style="background:#0284c7; color:#fff;" onclick="submitNewFolder()">Create Folder</button>
            <button style="background:#334155; color:#fff;" onclick="closeModal('folder-modal')">Cancel</button>
        </div>
    </div>

    <div class="modal" id="folder-mgr-modal">
        <div class="m-card">
            <h3>📁 Full Folder Manager</h3>
            <p style="color:#94a3b8; font-size:0.85rem;">Manage, rename, nested subfolders, and folder deletion options.</p>

            <button style="background:#10b981; color:#fff; font-size:0.85rem; padding:0.6rem; margin-bottom:0.8rem;" onclick="openNewFolderModal()">➕ Create Top-Level or Nested Subfolder</button>

            <div id="folder-mgr-list" style="max-height:55vh; overflow-y:auto;"></div>

            <button style="background:#334155; color:#fff; margin-top:0.8rem;" onclick="closeModal('folder-mgr-modal')">Close Folder Manager</button>
        </div>
    </div>

    <div class="modal" id="upload-modal">
        <div class="m-card">
            <h3>📤 Upload Encrypted Media</h3>
            <p style="color:#94a3b8; font-size:0.85rem;">File will be encrypted on-the-fly upon upload.</p>
            <label style="font-size:0.85rem; color:#cbd5e1;">Target Folder:</label>
            <select id="upload-target-folder"></select>
            <input type="file" id="upload-file-input" multiple accept="image/*,video/*">
            <button style="background:#10b981; color:#fff;" onclick="submitUpload()">Encrypt & Upload</button>
            <button style="background:#334155; color:#fff;" onclick="closeModal('upload-modal')">Cancel</button>
            <div id="upload-status" style="margin-top:0.5rem; font-size:0.85rem; text-align:center;"></div>
        </div>
    </div>

    <div class="modal" id="item-options-modal">
        <div class="m-card">
            <h3>⚙️ Item Options</h3>
            <p id="opt-item-name" style="font-size:0.85rem; color:#94a3b8; word-break:break-all;"></p>
            
            <button id="opt-download-btn" style="background:#10b981; color:#fff; font-weight:bold; margin-bottom:1rem; display:none;" onclick="closeModal('item-options-modal'); downloadCurrentItem();">⬇️ Download Raw File</button>

            <label style="font-size:0.85rem; color:#cbd5e1;">Move to Subfolder:</label>
            <select id="opt-move-folder-select"></select>
            <button style="background:#0284c7; color:#fff;" onclick="submitMoveItem()">📁 Move Item</button>

            <hr style="border:0; border-top:1px solid #334155; margin:1rem 0;">

            <button style="background:#dc2626; color:#fff;" onclick="submitDeleteItem()">🗑️ Delete Item permanently</button>
            <button style="background:#334155; color:#fff; margin-top:0.5rem;" onclick="closeModal('item-options-modal')">Cancel</button>
        </div>
    </div>

    <div class="modal" id="dup-modal">
        <div class="m-card">
            <h3>🔍 Vault Duplicate Cleaner</h3>
            <p style="color:#94a3b8; font-size:0.85rem;" id="dup-summary-text">Scanning all duplicate groups...</p>

            <button style="background:#10b981; color:#fff; font-size:0.9rem; font-weight:bold; padding:0.8rem; margin-bottom:0.8rem;" onclick="autoCleanAllVaultDuplicates()">⚡ 1-Click Auto-Clean ALL Duplicates</button>
            
            <div style="display:flex; gap:0.4rem; margin-bottom:0.8rem;">
                <button style="background:#f59e0b; color:#fff; font-size:0.8rem; padding:0.5rem;" onclick="autoSelectDuplicateCopies()">Select Displayed Extra Copies</button>
                <button style="background:#ef4444; color:#fff; font-size:0.8rem; padding:0.5rem;" onclick="submitDeleteSelectedDuplicates()">Delete Selected</button>
            </div>

            <div id="dup-groups-list" style="max-height:50vh; overflow-y:auto;"></div>

            <button style="background:#334155; color:#fff; margin-top:0.8rem;" onclick="closeModal('dup-modal')">Close Duplicate Cleaner</button>
        </div>
    </div>

    <div class="modal" id="admin-modal">
        <div class="m-card">
            <h3>📊 Vault Statistics & Admin</h3>
            <div class="stat-grid">
                <div class="stat-box"><div class="stat-num" id="st-total-files">...</div><div class="stat-label">Total Media Files</div></div>
                <div class="stat-box"><div class="stat-num" id="st-vault-size">...</div><div class="stat-label">Vault Data Size</div></div>
                <div class="stat-box"><div class="stat-num" id="st-photos-count">...</div><div class="stat-label">Photos</div></div>
                <div class="stat-box"><div class="stat-num" id="st-videos-count">...</div><div class="stat-label">Videos</div></div>
                <div class="stat-box"><div class="stat-num" id="st-starred-count">...</div><div class="stat-label">Starred ⭐</div></div>
                <div class="stat-box clickable" onclick="openDuplicateModal()"><div class="stat-num" id="st-duplicates-count" style="color:#f59e0b;">...</div><div class="stat-label" style="color:#fbbf24; font-weight:bold;">🔍 Clean Duplicates</div></div>
                <div class="stat-box"><div class="stat-num" id="st-disk-free">...</div><div class="stat-label">Free Storage</div></div>
            </div>

            <hr style="border:0; border-top:1px solid #334155; margin:1rem 0;">

            <button style="background:#0284c7; color:#fff;" onclick="triggerCloudBackup()">☁️ Backup Encrypted Vault to Google Drive</button>
            <button style="background:#8b5cf6; color:#fff; margin-top:0.6rem;" onclick="openFolderManagerModal()">📁 Open Full Folder Manager</button>
            <button id="admin-migrate-btn" style="background:#f59e0b; color:#fff; margin-top:0.6rem; display:none;" onclick="migrateVaultPrompt()">⚡ Migrate Vault to Context-Bound v3</button>
            <button style="background:#6366f1; color:#fff; margin-top:0.6rem;" onclick="changePasswordPrompt()">🔑 Change Password</button>
            <button style="background:#0284c7; color:#fff; margin-top:0.6rem;" onclick="exportVaultPrompt()">🔓 Decrypt All Files to PC</button>
            <button id="admin-shutdown-btn" style="background:#dc2626; color:#fff; margin-top:0.6rem; display:none;" onclick="shutdownPC()">🔴 Shut Down PC</button>
            <button style="background:#334155; color:#fff; margin-top:1rem;" onclick="closeModal('admin-modal')">Close Dashboard</button>
        </div>
    </div>

    <div class="viewer" id="viewer" onmousemove="resetNavFadeTimer()" onclick="resetNavFadeTimer()">
        <div class="v-header">
            <div class="v-title" id="v-title"></div>
            <div class="v-hdr-btns">
                <button class="v-star-btn" id="v-star-btn" onclick="toggleStarItem()">☆</button>
                <button class="v-dl-btn" id="v-dl-btn" style="display:none;" onclick="downloadCurrentItem(event)" title="Download raw media file">⬇️</button>
                <button class="v-opt-btn" onclick="openItemOptionsModal()">⚙️</button>
                <button class="v-close" onclick="closeViewer()">✕</button>
            </div>
        </div>
        <button class="v-nav-arrow v-prev-arrow" id="v-prev-arrow" onclick="event.stopPropagation(); prevItem(event);" title="Previous">‹</button>
        <button class="v-nav-arrow v-next-arrow" id="v-next-arrow" onclick="event.stopPropagation(); nextItem(event);" title="Next">›</button>
        <div class="v-body" id="v-body"></div>
    </div>

    <script>
        let files = [];
        let folders = [];
        let duplicateData = null;
        let currentSubfolder = '__ALL__';
        let currentIndex = 0;
        let selectedEncIds = new Set();
        let selectedDupIds = new Set();
        let isSelectMode = false;
        
        const preloadedCache = {};

        async function authFetch(url, options = {}) {
            options.headers = options.headers || {};
            const csrfToken = document.cookie.split('; ').find(c => c.startsWith('csrf_token='));
            if (csrfToken) {
                options.headers['X-CSRF-Token'] = csrfToken.split('=')[1];
            }
            options.credentials = 'same-origin';

            try {
                const res = await fetch(url, options);
                if (res && res.status === 401) {
                    window.location.href = '/login';
                    return null;
                }
                return res;
            } catch(e) {
                console.error("Fetch Network Error:", e);
                return null;
            }
        }

        function safeSetText(id, txt) {
            const el = document.getElementById(id);
            if(el) el.innerText = txt;
        }

        let allowDownloads = false;

        async function checkVaultConfig() {
            try {
                const res = await authFetch('/api/vault_status');
                if (res) {
                    const data = await res.json();
                    allowDownloads = !!data.allow_downloads;
                    applyDrmProtections();
                }
            } catch(e) {}
        }

        function applyDrmProtections() {
            const dlBtn = document.getElementById('v-dl-btn');
            if (dlBtn) dlBtn.style.display = allowDownloads ? 'flex' : 'none';

            const optDlBtn = document.getElementById('opt-download-btn');
            if (optDlBtn) optDlBtn.style.display = allowDownloads ? 'block' : 'none';

            if (!allowDownloads) {
                document.body.classList.add('no-save');
            } else {
                document.body.classList.remove('no-save');
            }
        }

        function showDrmHiddenScreen() {
            if (allowDownloads) return;
            const overlay = document.getElementById('drm-hidden-overlay');
            if (overlay) overlay.classList.add('active');
        }

        function hideDrmHiddenScreen() {
            const overlay = document.getElementById('drm-hidden-overlay');
            if (overlay) overlay.classList.remove('active');
        }

        document.addEventListener('keydown', (e) => {
            if (!allowDownloads) {
                if (e.key === 'PrintScreen' || e.code === 'PrintScreen') {
                    e.preventDefault();
                    showDrmHiddenScreen();
                    setTimeout(() => { hideDrmHiddenScreen(); }, 1500);
                    return false;
                }
            }
        });

        // Anti-Save & Anti-Screenshot Event Interceptors for Grid & Lightbox
        document.addEventListener('contextmenu', (e) => {
            if (!allowDownloads) {
                e.preventDefault();
                return false;
            }
        }, { capture: true });

        document.addEventListener('dragstart', (e) => {
            if (!allowDownloads) {
                e.preventDefault();
                return false;
            }
        }, { capture: true });

        async function init() {
            checkVaultConfig().catch(e => console.error("checkVaultConfig error:", e));
            checkLegacyStatus().catch(e => console.error("checkLegacyStatus error:", e));
            loadFiles('__ALL__').catch(e => console.error("loadFiles error:", e));
            loadFolders().catch(e => console.error("loadFolders error:", e));
        }

        async function loadFolders() {
            try {
                const res = await authFetch('/api/folders');
                if(!res) return;
                const data = await res.json();
                folders = data.folders || [];
                
                const sel = document.getElementById('folder-select');
                const upSel = document.getElementById('upload-target-folder');
                const optSel = document.getElementById('opt-move-folder-select');
                const bulkSel = document.getElementById('bulk-target-folder');
                const parentSel = document.getElementById('create-parent-folder-select');
                
                if(sel) sel.innerHTML = '';
                if(upSel) upSel.innerHTML = '';
                if(optSel) optSel.innerHTML = '';
                if(bulkSel) bulkSel.innerHTML = '';
                if(parentSel) parentSel.innerHTML = '<option value="">📁 Root Directory (Top Level)</option>';

                folders.forEach(f => {
                    if(sel) {
                        const opt1 = document.createElement('option');
                        opt1.value = f.path; opt1.innerText = `${f.name} (${f.count || 0})`;
                        sel.appendChild(opt1);
                    }

                    if(f.path !== '__FAVORITES__' && f.path !== '__ALL__') {
                        if(upSel) { const opt2 = document.createElement('option'); opt2.value = f.path; opt2.innerText = f.name; upSel.appendChild(opt2); }
                        if(optSel) { const opt3 = document.createElement('option'); opt3.value = f.path; opt3.innerText = f.name; optSel.appendChild(opt3); }
                        if(bulkSel) { const opt4 = document.createElement('option'); opt4.value = f.path; opt4.innerText = f.name; bulkSel.appendChild(opt4); }

                        if(f.path !== '__UNCATEGORIZED__' && parentSel) {
                            const opt5 = document.createElement('option'); opt5.value = f.path; opt5.innerText = `📂 Inside ${f.name}`; parentSel.appendChild(opt5);
                        }
                    }
                });
            } catch(e) {
                console.error("Error loading folders:", e);
            }
        }

        function openMenuModal() {
            const el = document.getElementById('menu-modal');
            if(el) el.classList.add('active');
        }

        async function triggerCloudBackup() {
            closeModal('menu-modal');
            closeModal('admin-modal');
            
            if(confirm("☁️ BACKUP ENCRYPTED VAULT TO GOOGLE DRIVE?\\nThis will create/update a 100% AES-256 encrypted copy of your vault in your Google Drive.")) {
                try {
                    const res = await authFetch('/api/admin/cloud_backup', { method: 'POST' });
                    if(!res) return;
                    const data = await res.json();
                    if(data.success) {
                        alert(`${data.message}\\n\\nSynced ${data.synced_count} file(s) (${data.copied_mb}).`);
                    } else {
                        alert(`❌ Cloud Backup Failed:\\n${data.error}`);
                    }
                } catch(e) {
                    alert(`❌ Network or Backup Error: ${e.message}`);
                }
            }
        }

        async function openFolderManagerModal() {
            closeModal('menu-modal');
            await loadFolders();
            const listDiv = document.getElementById('folder-mgr-list');
            if(!listDiv) return;
            listDiv.innerHTML = '';

            const userFolders = folders.filter(f => f.path !== '__ALL__' && f.path !== '__UNCATEGORIZED__' && f.path !== '__FAVORITES__');

            if(userFolders.length === 0) {
                listDiv.innerHTML = '<p style="color:#94a3b8; text-align:center;">No custom subfolders created yet.</p>';
            } else {
                userFolders.forEach(f => {
                    const fDiv = document.createElement('div');
                    fDiv.className = 'f-item';
                    const details = document.createElement('div');
                    const info = document.createElement('div');
                    info.className = 'f-info';
                    info.textContent = '📂 ' + String(f.name || '');
                    const count = document.createElement('div');
                    count.className = 'f-subcount';
                    count.textContent = String(Number(f.count) || 0) + ' item(s)';
                    details.append(info, count);

                    const actions = document.createElement('div');
                    actions.className = 'f-actions';
                    const addButton = document.createElement('button');
                    addButton.className = 'btn-f-act';
                    addButton.style.cssText = 'background:#0284c7;color:#fff;';
                    addButton.textContent = '➕ Sub';
                    addButton.addEventListener('click', () => promptCreateSubfolder(f.path));
                    const renameButton = document.createElement('button');
                    renameButton.className = 'btn-f-act';
                    renameButton.style.cssText = 'background:#f59e0b;color:#fff;';
                    renameButton.textContent = '✏️ Rename';
                    renameButton.addEventListener('click', () => promptRenameFolder(f.path));
                    const deleteButton = document.createElement('button');
                    deleteButton.className = 'btn-f-act';
                    deleteButton.style.cssText = 'background:#ef4444;color:#fff;';
                    deleteButton.textContent = '🗑️ Delete';
                    deleteButton.addEventListener('click', () => promptDeleteFolder(f.path, Number(f.count) || 0));
                    actions.append(addButton, renameButton, deleteButton);
                    fDiv.append(details, actions);
                    listDiv.appendChild(fDiv);
                });
            }

            const fmModal = document.getElementById('folder-mgr-modal');
            if(fmModal) fmModal.classList.add('active');
        }

        function promptCreateSubfolder(parentPath) {
            closeModal('folder-mgr-modal');
            const pSel = document.getElementById('create-parent-folder-select');
            if(pSel) pSel.value = parentPath;
            openNewFolderModal();
        }

        async function promptRenameFolder(oldFolder) {
            const currentBasename = oldFolder.split('/').pop();
            const newName = prompt(`Rename folder "${oldFolder}" to:`, currentBasename);
            if(newName && newName.trim() && newName !== currentBasename) {
                const res = await authFetch('/api/folders/rename', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `old_folder=${encodeURIComponent(oldFolder)}&new_name=${encodeURIComponent(newName.trim())}`
                });
                if(!res) return;
                const data = await res.json();
                if(data.success) {
                    alert(`✨ Folder renamed to "${data.new}"!`);
                    await openFolderManagerModal();
                    await loadFolders();
                    loadFiles(currentSubfolder);
                } else {
                    alert(`❌ Error: ${data.error}`);
                }
            }
        }

        async function promptDeleteFolder(folderPath, itemCount) {
            const choice = prompt(
                '⚠️ DELETE FOLDER "' + folderPath + '" (' + itemCount + ' items inside):\\n\\n' +
                'Type "1" to KEEP all items and move them to Uncategorized Root.\\n' +
                'Type "DELETE" to PERMANENTLY DELETE folder AND all ' + itemCount + ' items inside!'
            );

            if (choice === "1") {
                const res = await authFetch('/api/folders/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `folder_path=${encodeURIComponent(folderPath)}&mode=keep_files`
                });
                if(!res) return;
                const data = await res.json();
                if(data.success) {
                    alert(`✨ Folder deleted! Moved ${data.count} items to Uncategorized Root.`);
                    await openFolderManagerModal();
                    await loadFolders();
                    loadFiles(currentSubfolder);
                }
            } else if (choice === "DELETE") {
                const res = await authFetch('/api/folders/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: `folder_path=${encodeURIComponent(folderPath)}&mode=delete_files`
                });
                if(!res) return;
                const data = await res.json();
                if(data.success) {
                    alert(`🗑️ Folder and all ${data.count} items permanently deleted.`);
                    await openFolderManagerModal();
                    await loadFolders();
                    loadFiles(currentSubfolder);
                }
            }
        }

        async function loadFiles(sub) {
            currentSubfolder = sub;
            const sortEl = document.getElementById('sort-select');
            const qEl = document.getElementById('search-input');

            const sort = sortEl ? sortEl.value : 'newest';
            const q = qEl ? qEl.value : '';

            const url = `/api/files?subfolder=${encodeURIComponent(sub)}&sort=${encodeURIComponent(sort)}&q=${encodeURIComponent(q)}`;
            const res = await authFetch(url);
            if(!res) return;
            const data = await res.json();
            files = data.files || [];
            safeSetText('count-badge', files.length + ' Items');
            renderGrid();
        }

        function changeSubfolder() {
            const sel = document.getElementById('folder-select');
            if(sel) loadFiles(sel.value);
        }

        function changeSort() { loadFiles(currentSubfolder); }
        function handleSearch() { loadFiles(currentSubfolder); }

        function toggleSelectMode() {
            isSelectMode = !isSelectMode;
            document.body.classList.toggle('select-mode', isSelectMode);
            const btn = document.getElementById('select-mode-btn');
            if(btn) btn.style.background = isSelectMode ? '#10b981' : '#f59e0b';
            if(!isSelectMode) {
                selectedEncIds.clear();
                updateBulkBar();
            }
        }

        function toggleFileSelection(enc_id, ev) {
            ev.stopPropagation();
            if(selectedEncIds.has(enc_id)) selectedEncIds.delete(enc_id);
            else selectedEncIds.add(enc_id);
            updateBulkBar();
        }

        function updateBulkBar() {
            const bar = document.getElementById('bulk-bar');
            safeSetText('bulk-count', selectedEncIds.size + ' Selected');
            if(bar) {
                if(selectedEncIds.size > 0 && isSelectMode) bar.classList.add('active');
                else bar.classList.remove('active');
            }
        }

        function renderGrid() {
            const grid = document.getElementById('grid');
            if(!grid) return;
            grid.innerHTML = '';

            if(files.length === 0) {
                grid.innerHTML = '<div style="grid-column: 1 / -1; text-align:center; padding:3rem 1rem; color:#94a3b8;">No items in this view.</div>';
                return;
            }

            const batchSize = 60;
            let currentOffset = 0;

            function renderBatch() {
                const fragment = document.createDocumentFragment();
                const limit = Math.min(currentOffset + batchSize, files.length);

                for (let idx = currentOffset; idx < limit; idx++) {
                    const f = files[idx];
                    const div = document.createElement('div');
                    div.className = 'thumb';
                    div.id = 'thumb-' + idx;
                    div.onclick = (ev) => {
                        if(isSelectMode) {
                            const cb = div.querySelector('.thumb-checkbox');
                            if(cb) cb.checked = !cb.checked;
                            toggleFileSelection(f.enc_id, ev);
                        } else {
                            openViewer(idx);
                        }
                    };

                    let starHtml = f.starred ? '<div class="star-icon">★</div>' : '';
                    let cbChecked = selectedEncIds.has(f.enc_id) ? 'checked' : '';
                    let cbHtml = `<input type="checkbox" class="thumb-checkbox" ${cbChecked} onclick="toggleFileSelection('${f.enc_id}', event)">`;
                    
                    const thumbUrl = '/thumb/' + encodeURIComponent(f.enc_id);
                    if(f.is_live_photo) {
                        div.innerHTML = `${starHtml}<img src="${thumbUrl}" loading="lazy"><div class="live-icon">📸 LIVE</div>${cbHtml}`;
                    } else if(f.is_video) {
                        div.innerHTML = `${starHtml}<img src="${thumbUrl}" loading="lazy"><div class="vid-icon">▶ VIDEO</div>${cbHtml}`;
                    } else {
                        div.innerHTML = `${starHtml}<img src="${thumbUrl}" loading="lazy">${cbHtml}`;
                    }
                    fragment.appendChild(div);
                }

                grid.appendChild(fragment);
                currentOffset = limit;

                if (currentOffset < files.length) {
                    requestAnimationFrame(renderBatch);
                }
            }

            renderBatch();
        }

        function openUploadModal() { const el = document.getElementById('upload-modal'); if(el) el.classList.add('active'); }
        function openNewFolderModal() { const el = document.getElementById('folder-modal'); if(el) el.classList.add('active'); }
        function openBulkMoveModal() { const el = document.getElementById('bulk-move-modal'); if(el) el.classList.add('active'); }
        
        async function openAdminModal() { 
            const el = document.getElementById('admin-modal');
            if(el) el.classList.add('active');
            try {
                const res = await authFetch('/api/admin/stats');
                if(!res) return;
                const stats = await res.json();
                if(stats) {
                    safeSetText('st-total-files', (stats.total_files || 0).toLocaleString());
                    safeSetText('st-vault-size', stats.total_vault_mb || '0 MB');
                    safeSetText('st-photos-count', (stats.photos_count || 0).toLocaleString());
                    safeSetText('st-videos-count', (stats.videos_count || 0).toLocaleString());
                    safeSetText('st-starred-count', (stats.starred_count || 0).toLocaleString());
                    safeSetText('st-duplicates-count', (stats.potential_duplicates || 0).toLocaleString() + " Dups");
                    safeSetText('st-disk-free', stats.free_disk_gb || '0 GB');
                    const shutdownBtn = document.getElementById('admin-shutdown-btn');
                    if (shutdownBtn) {
                        shutdownBtn.style.display = stats.enable_remote_shutdown ? 'block' : 'none';
                    }
                    const migrateBtn = document.getElementById('admin-migrate-btn');
                    if (migrateBtn) {
                        migrateBtn.style.display = stats.migration_available ? 'block' : 'none';
                    }
                    const legacyBanner = document.getElementById('legacy-banner');
                    if (legacyBanner) {
                        legacyBanner.style.display = stats.migration_available ? 'block' : 'none';
                    }
                    if (stats.allow_downloads !== undefined) {
                        allowDownloads = !!stats.allow_downloads;
                        applyDrmProtections();
                    }
                }
            } catch(e) {
                console.log("Stats update error:", e);
            }
        }

        async function openDuplicateModal() {
            closeModal('admin-modal');
            const res = await authFetch('/api/admin/duplicates?limit=all');
            if(!res) return;
            duplicateData = await res.json();

            safeSetText('dup-summary-text', `Found ${duplicateData.groups_count.toLocaleString()} duplicate groups (${duplicateData.potential_waste_mb} redundant data).`);

            const listDiv = document.getElementById('dup-groups-list');
            if(!listDiv) return;
            listDiv.innerHTML = '';
            selectedDupIds.clear();

            duplicateData.duplicate_groups.forEach((g, gIdx) => {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'dup-group';
                const header = document.createElement('div');
                header.className = 'dup-hdr';
                const title = document.createElement('span');
                title.textContent = `Group #${gIdx + 1} (${String(g.size_formatted || '')})`;
                const copies = document.createElement('span');
                copies.style.color = '#94a3b8';
                copies.textContent = `${Number(g.copies_count) || 0} Copies`;
                header.append(title, copies);

                const row = document.createElement('div');
                row.className = 'dup-items-row';
                g.items.forEach(it => {
                    const card = document.createElement('div');
                    card.className = 'dup-item-card';
                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'dup-item-cb';
                    checkbox.id = 'dup-cb-' + String(it.enc_id);
                    checkbox.addEventListener('change', () => toggleDupSelection(it.enc_id));
                    const image = document.createElement('img');
                    image.src = '/thumb/' + encodeURIComponent(it.enc_id);
                    const name = document.createElement('div');
                    name.style.cssText = 'margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
                    name.textContent = String(it.name || '');
                    card.append(checkbox, image, name);
                    row.appendChild(card);
                });

                groupDiv.append(header, row);
                listDiv.appendChild(groupDiv);
            });

            const dupM = document.getElementById('dup-modal');
            if(dupM) dupM.classList.add('active');
        }

        function toggleDupSelection(enc_id) {
            if(selectedDupIds.has(enc_id)) selectedDupIds.delete(enc_id);
            else selectedDupIds.add(enc_id);
        }

        function autoSelectDuplicateCopies() {
            if(!duplicateData) return;
            selectedDupIds.clear();
            
            duplicateData.duplicate_groups.forEach(g => {
                for(let i = 1; i < g.items.length; i++) {
                    const enc_id = g.items[i].enc_id;
                    selectedDupIds.add(enc_id);
                    const cb = document.getElementById('dup-cb-' + enc_id);
                    if(cb) cb.checked = true;
                }
            });
            alert(`⚡ Auto-selected ${selectedDupIds.size} redundant duplicate copies for deletion!`);
        }

        async function autoCleanAllVaultDuplicates() {
            if(confirm('⚡ AUTO-CLEAN ALL VAULT DUPLICATES?\\nThis will keep 1 original copy of each file and delete all extra cryptographic duplicate copies to reclaim disk space!')) {
                const confirmText = prompt('Type "CLEAN" to confirm:');
                if (confirmText === "CLEAN") {
                    const res = await authFetch('/api/admin/auto_clean_all_duplicates', { method: 'POST' });
                    if(!res) return;
                    const data = await res.json();
                    if(data.success) {
                        alert(`✨ SUCCESS!\\nDeleted ${data.deleted_count} duplicate files and reclaimed ${data.freed_mb} (${data.freed_gb}) of disk space!`);
                        closeModal('dup-modal');
                        loadFiles(currentSubfolder);
                    }
                }
            }
        }

        async function submitDeleteSelectedDuplicates() {
            if(selectedDupIds.size === 0) {
                alert("Please select at least one duplicate file to delete.");
                return;
            }

            if(confirm('⚠️ PERMANENTLY DELETE DUPLICATES?\\nRemove selected duplicate file(s) from encrypted vault?')) {
                const res = await authFetch('/api/files/bulk_delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ enc_ids: Array.from(selectedDupIds) })
                });
                if(!res) return;
                const data = await res.json();
                if(data.success) {
                    alert(`✨ Successfully deleted ${data.count} duplicate file(s)!`);
                    closeModal('dup-modal');
                    loadFiles(currentSubfolder);
                }
            }
        }
        
        function openItemOptionsModal() {
            const f = files[currentIndex];
            if(!f) return;
            safeSetText('opt-item-name', f.name);
            const sel = document.getElementById('opt-move-folder-select');
            if(sel) sel.value = f.subfolder || '';
            const el = document.getElementById('item-options-modal');
            if(el) el.classList.add('active');
        }

        function closeModal(id) { const el = document.getElementById(id); if(el) el.classList.remove('active'); }

        async function toggleStarItem() {
            const f = files[currentIndex];
            if(!f) return;
            const res = await authFetch('/api/file/star', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'enc_id=' + encodeURIComponent(f.enc_id)
            });
            if(!res) return;
            const data = await res.json();
            if(data.success) {
                f.starred = data.starred;
                safeSetText('v-star-btn', f.starred ? '★' : '☆');
                renderGrid();
            }
        }

        async function submitBulkMove() {
            const sel = document.getElementById('bulk-target-folder');
            const targetFolder = sel ? sel.value : '';
            const res = await authFetch('/api/files/bulk_move', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ enc_ids: Array.from(selectedEncIds), target_subfolder: targetFolder })
            });
            if(!res) return;
            const data = await res.json();
            if(data.success) {
                closeModal('bulk-move-modal');
                selectedEncIds.clear();
                toggleSelectMode();
                loadFiles(currentSubfolder);
            }
        }

        async function submitBulkStar(starred) {
            const res = await authFetch('/api/files/bulk_star', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ enc_ids: Array.from(selectedEncIds), starred: starred })
            });
            if(!res) return;
            const data = await res.json();
            if(data.success) {
                selectedEncIds.clear();
                toggleSelectMode();
                loadFiles(currentSubfolder);
            }
        }

        async function submitBulkDelete() {
            if(confirm('⚠️ PERMANENT BULK DELETE?\\nDelete selected item(s) forever from encrypted vault?')) {
                const confirmText = prompt('Type "DELETE" to confirm:');
                if (confirmText === "DELETE") {
                    const res = await authFetch('/api/files/bulk_delete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ enc_ids: Array.from(selectedEncIds) })
                    });
                    if(!res) return;
                    const data = await res.json();
                    if(data.success) {
                        selectedEncIds.clear();
                        toggleSelectMode();
                        loadFiles(currentSubfolder);
                    }
                }
            }
        }

        async function submitNewFolder() {
            const parentSel = document.getElementById('create-parent-folder-select');
            const fInput = document.getElementById('new-folder-input');
            const parentFolder = parentSel ? parentSel.value : '';
            const folderInput = fInput ? fInput.value.trim() : '';
            if(!folderInput) return;

            const res = await authFetch('/api/folders/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `parent_folder=${encodeURIComponent(parentFolder)}&folder_name=${encodeURIComponent(folderInput)}`
            });
            if(!res) return;
            const data = await res.json();
            if(data.success) {
                closeModal('folder-modal');
                if(fInput) fInput.value = '';
                await loadFolders();
                const sel = document.getElementById('folder-select');
                if(sel) sel.value = data.folder;
                loadFiles(data.folder);
            } else {
                alert(`❌ Folder Creation Failed:\\n${data.error}`);
            }
        }

        async function submitMoveItem() {
            const f = files[currentIndex];
            if(!f) return;
            const sel = document.getElementById('opt-move-folder-select');
            const targetFolder = sel ? sel.value : '';

            const res = await authFetch('/api/file/move', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `enc_id=${encodeURIComponent(f.enc_id)}&target_subfolder=${encodeURIComponent(targetFolder)}`
            });
            if(!res) return;
            const data = await res.json();
            if(data.success) {
                closeModal('item-options-modal');
                closeViewer();
                await loadFiles(currentSubfolder);
            }
        }

        async function submitDeleteItem() {
            const f = files[currentIndex];
            if(!f) return;

            if (confirm('⚠️ ARE YOU SURE?\\nThis will permanently delete item from your encrypted vault!')) {
                const confirmText = prompt('Type "DELETE" to confirm permanent removal:');
                if (confirmText === "DELETE") {
                    const res = await authFetch('/api/file/delete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: `enc_id=${encodeURIComponent(f.enc_id)}`
                    });
                    if(!res) return;
                    const data = await res.json();
                    if(data.success) {
                        closeModal('item-options-modal');
                        closeViewer();
                        await loadFiles(currentSubfolder);
                    }
                }
            }
        }

        async function submitUpload() {
            const fileInput = document.getElementById('upload-file-input');
            const targetFolder = document.getElementById('upload-target-folder').value;
            const statusDiv = document.getElementById('upload-status');

            if (!fileInput || fileInput.files.length === 0) {
                if(statusDiv) statusDiv.innerText = "Please select a file to upload.";
                return;
            }

            if(statusDiv) statusDiv.innerText = "Encrypting and uploading...";

            for (let file of fileInput.files) {
                const formData = new FormData();
                formData.append('subfolder', targetFolder);
                formData.append('file', file);

                const res = await authFetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                if(!res) return;
                const data = await res.json();
                if(!data.success) {
                    if(statusDiv) statusDiv.innerText = "Upload failed: " + (data.error || 'Unknown error');
                    return;
                }
            }

            if(statusDiv) statusDiv.innerText = "✨ Upload Complete!";
            setTimeout(() => {
                closeModal('upload-modal');
                if(statusDiv) statusDiv.innerText = "";
                if(fileInput) fileInput.value = "";
                loadFiles(currentSubfolder);
            }, 1000);
        }

        async function changePasswordPrompt() {
            const oldPwd = prompt("Enter current master password:");
            if(!oldPwd) return;
            const newPwd = prompt("Enter new master password (minimum 12 characters):");
            if(newPwd) {
                const res = await authFetch('/api/admin/change_password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'old_password=' + encodeURIComponent(oldPwd) + '&new_password=' + encodeURIComponent(newPwd)
                });
                if(!res) return;
                const data = await res.json();
                alert(data.message || data.error);
            }
        }

        async function exportVaultPrompt() {
            if(confirm("Do you want to decrypt ALL vault files into an unencrypted folder on your PC?")) {
                const res = await authFetch('/api/admin/export_vault', { method: 'POST' });
                if(!res) return;
                const data = await res.json();
                alert(`Decrypted ${data.count} files to:\\n${data.path}`);
            }
        }

        async function checkLegacyStatus() {
            try {
                const res = await authFetch('/api/admin/stats');
                if(!res) return;
                const stats = await res.json();
                if(stats && stats.migration_available) {
                    const banner = document.getElementById('legacy-banner');
                    if(banner) banner.style.display = 'block';
                    const btn = document.getElementById('admin-migrate-btn');
                    if(btn) btn.style.display = 'block';
                }
            } catch(e) {}
        }

        async function migrateVaultPrompt() {
            if (!confirm("Migrate this v1/v2 vault to context-bound v3 encryption?\\n\\nCryptHaven will stage and verify every replacement before committing, and automatically roll back an interrupted migration. Keep an independent backup before any bulk cryptographic migration.")) {
                return;
            }
            const pwd = prompt("Enter master password to authorize migration:");
            if (!pwd) return;

            alert("⏳ Migration started... Please wait while your files are being re-encrypted.");

            const res = await authFetch('/api/admin/migrate_vault', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'password=' + encodeURIComponent(pwd)
            });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                alert("✅ " + (data.message || "Vault migrated successfully!"));
                location.reload();
            } else {
                alert("❌ Migration failed: " + (data.error || "Unknown error"));
            }
        }

        async function lockVaultNow() {
            await authFetch('/logout', { method: 'POST' });
            window.location.href = '/login';
        }

        function resetZoom() {
            scale = 1; pointX = 0; pointY = 0; isMultiTouch = false;
            updateTransform(true);
        }

        function updateTransform(animate = false) {
            const media = document.querySelector('.v-full-media');
            if (media) { 
                media.style.transition = animate ? 'transform 0.2s cubic-bezier(0,0,0.2,1)' : 'none';
                media.style.transform = `translate3d(${pointX}px, ${pointY}px, 0px) scale(${scale})`; 
            }
        }

        function preloadMediaUrl(enc_id, isVideo) {
            if (!enc_id || isVideo || preloadedCache[enc_id]) return;
            const img = new Image();
            img.src = '/media/' + encodeURIComponent(enc_id);
            preloadedCache[enc_id] = img;
        }

        function preloadAdjacentMedia(idx) {
            const offsets = [-2, -1, 1, 2];
            offsets.forEach(offset => {
                const targetIdx = idx + offset;
                if (targetIdx >= 0 && targetIdx < files.length) {
                    const f = files[targetIdx];
                    if (f && !f.is_video && !f.is_live_photo) {
                        preloadMediaUrl(f.enc_id, false);
                    }
                }
            });
        }

        function openViewer(idx) {
            if (idx < 0 || idx >= files.length) return;
            currentIndex = idx;
            const f = files[currentIndex];
            if(!f) return;
            
            safeSetText('v-title', f.name + ' (' + f.size + ')');
            safeSetText('v-star-btn', f.starred ? '★' : '☆');
            
            const body = document.getElementById('v-body');
            if(!body) return;
            const thumbUrl = '/thumb/' + encodeURIComponent(f.enc_id);
            const mediaUrl = '/media/' + encodeURIComponent(f.enc_id);
            
            if(f.is_live_photo) {
                body.innerHTML = `
                    <div class="v-media-container">
                        <img class="v-thumb-placeholder" src="${thumbUrl}">
                        <video class="v-full-media" src="${mediaUrl}" autoplay loop muted playsinline webkit-playsinline oncanplay="this.style.opacity=1; const ph = document.querySelector('.v-thumb-placeholder'); if(ph) ph.style.opacity=0;"></video>
                    </div>
                `;
            } else if(f.is_video) {
                body.innerHTML = `
                    <div class="v-media-container">
                        <img class="v-thumb-placeholder" src="${thumbUrl}">
                        <video class="v-full-media" src="${mediaUrl}" controls autoplay playsinline webkit-playsinline oncanplay="this.style.opacity=1; const ph = document.querySelector('.v-thumb-placeholder'); if(ph) ph.style.opacity=0;"></video>
                    </div>
                `;
            } else {
                body.innerHTML = `
                    <div class="v-media-container">
                        <img class="v-thumb-placeholder" id="v-thumb-placeholder" src="${thumbUrl}">
                        <img class="v-full-media" id="v-full-img" src="${mediaUrl}" onload="this.style.opacity=1; const ph = document.getElementById('v-thumb-placeholder'); if(ph) ph.style.opacity=0;">
                    </div>
                `;
            }
            resetZoom();
            preloadAdjacentMedia(idx);

            const viewer = document.getElementById('viewer');
            if(viewer) viewer.classList.add('active');
            applyDrmProtections();
            resetNavFadeTimer();
        }

        let navFadeTimer = null;
        let lastNavTime = 0;

        function resetNavFadeTimer() {
            const prevArrow = document.getElementById('v-prev-arrow');
            const nextArrow = document.getElementById('v-next-arrow');

            if (scale > 1.05) {
                if (prevArrow) prevArrow.classList.add('faded');
                if (nextArrow) nextArrow.classList.add('faded');
                if (navFadeTimer) clearTimeout(navFadeTimer);
                return;
            }

            if (prevArrow) prevArrow.classList.remove('faded');
            if (nextArrow) nextArrow.classList.remove('faded');

            if (navFadeTimer) clearTimeout(navFadeTimer);
            navFadeTimer = setTimeout(() => {
                const viewer = document.getElementById('viewer');
                if (viewer && viewer.classList.contains('active')) {
                    if (prevArrow) prevArrow.classList.add('faded');
                    if (nextArrow) nextArrow.classList.add('faded');
                }
            }, 1000);
        }

        function closeViewer() {
            const viewer = document.getElementById('viewer');
            if(viewer) viewer.classList.remove('active');
            const body = document.getElementById('v-body');
            if(body) body.innerHTML = '';
            if (navFadeTimer) clearTimeout(navFadeTimer);
            resetZoom();
        }

        function nextItem(e) {
            if(e) e.preventDefault();
            lastNavTime = Date.now();
            lastTapTime = 0;
            resetNavFadeTimer();
            if(currentIndex < files.length - 1) openViewer(currentIndex + 1);
        }

        function prevItem(e) {
            if(e) e.preventDefault();
            lastNavTime = Date.now();
            lastTapTime = 0;
            resetNavFadeTimer();
            if(currentIndex > 0) openViewer(currentIndex - 1);
        }

        function downloadCurrentItem(e) {
            if (e && e.preventDefault) e.preventDefault();
            if (!allowDownloads) {
                alert("🔒 Media downloading is disabled for this vault session.");
                return;
            }
            if (currentIndex < 0 || currentIndex >= files.length) return;
            const f = files[currentIndex];
            if (!f || !f.enc_id) return;

            const downloadUrl = '/download/' + encodeURIComponent(f.enc_id);

            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = f.name || 'download';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        document.addEventListener('keydown', (e) => {
            const viewer = document.getElementById('viewer');
            if (viewer && viewer.classList.contains('active')) {
                resetNavFadeTimer();
                if (e.key === 'ArrowLeft') prevItem(e);
                else if (e.key === 'ArrowRight') nextItem(e);
                else if (e.key === 'Escape') closeViewer();
                else if (e.key === 'd' || e.key === 'D') downloadCurrentItem(e);
            }
        });

        async function shutdownPC() {
            if (confirm("Are you sure you want to SHUT DOWN your PC right now?")) {
                const res = await authFetch('/shutdown', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    alert("🔴 PC is shutting down!");
                } else {
                    alert(data.error || 'Shutdown failed');
                }
            }
        }

        const vBody = document.getElementById('v-body');
        let touchStartX = 0, touchStartY = 0;
        let totalTouchMove = 0;
        let touchStartTime = 0;

        if(vBody) {
            vBody.addEventListener('touchstart', e => {
                resetNavFadeTimer();
                touchStartTime = Date.now();
                totalTouchMove = 0;

                if (e.touches.length > 1) {
                    isMultiTouch = true;
                }

                let touchX = 0;
                if (e.touches.length === 1) {
                    touchX = e.touches[0].clientX;
                    touchStartX = e.touches[0].clientX;
                    touchStartY = e.touches[0].clientY;
                    startX = e.touches[0].clientX - pointX;
                    startY = e.touches[0].clientY - pointY;
                    if (scale === 1) isMultiTouch = false;
                }

                const now = Date.now();
                const screenWidth = window.innerWidth;
                const isSideTapZone = touchX < screenWidth * 0.3 || touchX > screenWidth * 0.7;
                const recentNav = (now - lastNavTime) < 400;

                // Double tap zoom triggers ONLY in central area when no recent side navigation occurred
                if (e.touches.length === 1 && !isSideTapZone && !recentNav && (now - lastTapTime < 300)) {
                    if (scale > 1) resetZoom();
                    else {
                        scale = 2.5; pointX = 0; pointY = 0;
                        updateTransform(true);
                    }
                    lastTapTime = 0;
                    return;
                }

                if (isSideTapZone || recentNav) {
                    lastTapTime = 0;
                } else {
                    lastTapTime = now;
                }
            }, {passive: true});

            vBody.addEventListener('touchmove', e => {
                resetNavFadeTimer();
                if (e.touches.length === 2) {
                    isMultiTouch = true;
                    const dist = Math.hypot(
                        e.touches[0].pageX - e.touches[1].pageX,
                        e.touches[0].pageY - e.touches[1].pageY
                    );
                    scale = Math.min(Math.max(1, initialScale * (dist / initialPinchDist)), 4);
                    requestAnimationFrame(() => updateTransform(false));
                } else if (e.touches.length === 1) {
                    const dx = e.touches[0].clientX - touchStartX;
                    const dy = e.touches[0].clientY - touchStartY;
                    totalTouchMove = Math.hypot(dx, dy);

                    if (scale > 1) {
                        pointX = e.touches[0].clientX - startX;
                        pointY = e.touches[0].clientY - startY;
                        requestAnimationFrame(() => updateTransform(false));
                    }
                }
            }, {passive: true});

            vBody.addEventListener('touchend', e => {
                if (e.touches.length === 0) {
                    const touchDuration = Date.now() - touchStartTime;

                    // Clean side-tap navigation on mobile/touch:
                    // Only trigger if scale <= 1.05 (not zoomed), no pinch gesture occurred,
                    // touch movement was minimal (<15px), and touch duration was brief (<400ms).
                    if (scale <= 1.05 && !isMultiTouch && totalTouchMove < 15 && touchDuration < 400) {
                        const screenWidth = window.innerWidth;
                        if (touchStartX < screenWidth * 0.3) {
                            prevItem();
                        } else if (touchStartX > screenWidth * 0.7) {
                            nextItem();
                        }
                    } else if (scale === 1 && !isMultiTouch && totalTouchMove > 50) {
                        const diffX = pointX;
                        if (diffX < -60) nextItem();
                        else if (diffX > 60) prevItem();
                    }

                    if (scale <= 1.05) resetZoom();
                    isMultiTouch = false;
                }
            }, {passive: true});
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    </script>
</body>
</html>"""

def create_tray_icon_image():
    image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((4, 4, 60, 60), fill=(2, 132, 199, 255))
    draw.arc((20, 14, 44, 38), 180, 0, fill=(255, 255, 255, 255), width=5)
    draw.rounded_rectangle((16, 30, 48, 52), radius=4, fill=(255, 255, 255, 255))
    draw.ellipse((29, 36, 35, 42), fill=(2, 132, 199, 255))
    draw.rectangle((31, 40, 33, 46), fill=(2, 132, 199, 255))
    return image

RESTART_REQUESTED = False


def open_vault_browser():
    target_port = HTTPS_PORT if HTTPS_PORT else PORT
    webbrowser.open(f"https://127.0.0.1:{target_port}")

def on_open_browser(icon, item):
    open_vault_browser()


def on_cloud_backup_action(icon, item):
    success, msg, path, count, copied_mb = perform_google_drive_backup()
    if success:
        print(f"--- SYSTEM TRAY CLOUD BACKUP SUCCESSFUL ---\n{msg}")
    else:
        print(f"--- SYSTEM TRAY CLOUD BACKUP ERROR ---\n{msg}")


def on_switch_vault(icon, item):
    global RESTART_REQUESTED
    print("--- SWITCHING VAULT FROM SYSTEM TRAY ---")
    RESTART_REQUESTED = True
    stop_servers()
    if TRAY_ICON:
        TRAY_ICON.stop()


def on_exit_server(icon, item):
    global RESTART_REQUESTED
    RESTART_REQUESTED = False
    print("--- EXITING ENCRYPTED VAULT SERVER FROM SYSTEM TRAY ---")
    stop_servers()
    if TRAY_ICON:
        TRAY_ICON.stop()
    sys.exit(0)


def stop_servers():
    global SERVER_HTTPD, SERVER_HTTPS
    lock_vault()
    if SERVER_HTTPD:
        try:
            SERVER_HTTPD.shutdown()
            SERVER_HTTPD.server_close()
        except Exception:
            pass
        SERVER_HTTPD = None
    if SERVER_HTTPS:
        try:
            SERVER_HTTPS.shutdown()
            SERVER_HTTPS.server_close()
        except Exception:
            pass
        SERVER_HTTPS = None


class ThreadedHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class HTTPRedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to HTTPS."""

    def log_message(self, format, *args):
        if sys.stderr is not None and hasattr(sys.stderr, 'write'):
            try:
                sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format % args))
            except Exception:
                pass

    def do_GET(self):
        requested_host = self.headers.get('Host', '').split(':', 1)[0].strip().lower()
        allowed_hosts = {'localhost', '127.0.0.1', LOCAL_IP.lower()}
        host = requested_host if requested_host in allowed_hosts else LOCAL_IP
        target = f"https://{host}:{HTTPS_PORT}{self.path}"
        self.send_response(307)
        self.send_header('Location', target)
        self.end_headers()

    def do_POST(self):
        self.do_GET()


def bind_http_server(start_port):
    """Bind HTTP listeners across both 127.0.0.1 and LOCAL_IP that redirect to HTTPS."""
    servers = []
    actual_port = None

    for p in range(start_port, start_port + 20):
        try:
            s1 = ThreadedHTTPServer(('127.0.0.1', p), HTTPRedirectHandler)
            servers.append(s1)
            actual_port = p

            if LOCAL_IP and LOCAL_IP != '127.0.0.1' and LOCAL_IP != str(ipaddress.IPv4Address(0)):
                try:
                    s2 = ThreadedHTTPServer((LOCAL_IP, p), HTTPRedirectHandler)
                    servers.append(s2)
                except Exception as e:
                    print(f"LAN Listener Notice for {LOCAL_IP}:{p}: {e}")
            break
        except OSError:
            servers.clear()
            continue

    return servers, actual_port


def bind_https_server(start_port):
    """Bind HTTPS listeners across loopback and LAN IP."""
    if not generate_self_signed_ssl_certificate():
        return [], None

    servers = []
    actual_port = None

    for p in range(start_port, start_port + 20):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)

            s1 = ThreadedHTTPServer(('127.0.0.1', p), VaultGalleryHandler)
            s1.socket = ctx.wrap_socket(s1.socket, server_side=True)
            servers.append(s1)
            actual_port = p

            if LOCAL_IP and LOCAL_IP != '127.0.0.1' and LOCAL_IP != str(ipaddress.IPv4Address(0)):
                try:
                    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx2.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
                    s2 = ThreadedHTTPServer((LOCAL_IP, p), VaultGalleryHandler)
                    s2.socket = ctx2.wrap_socket(s2.socket, server_side=True)
                    servers.append(s2)
                except Exception:
                    pass
            break
        except Exception:
            servers.clear()
            continue

    return servers, actual_port


def start_servers():
    global SERVER_HTTPD, SERVER_HTTPS, PORT, HTTPS_PORT

    http_servers, actual_http_port = bind_http_server(PORT)
    if not http_servers:
        return False, f"Could not bind HTTP server to any port between {PORT}-{PORT + 20}. Check if another application or CryptHaven instance is already running."

    PORT = actual_http_port
    SERVER_HTTPD = http_servers[0]

    https_servers, actual_https_port = bind_https_server(HTTPS_PORT)
    if https_servers:
        HTTPS_PORT = actual_https_port
        SERVER_HTTPS = https_servers[0]

    def run_server_instance(srv):
        try:
            srv.serve_forever()
        except Exception:
            pass

    for srv in http_servers:
        threading.Thread(target=run_server_instance, args=(srv,), daemon=True).start()

    for srv in https_servers:
        threading.Thread(target=run_server_instance, args=(srv,), daemon=True).start()

    return True, "Servers started successfully"

    def run_http():
        try:
            SERVER_HTTPD.serve_forever()
        except Exception as e:
            print(f"HTTP Server notice: {e}")

    def run_https():
        if SERVER_HTTPS:
            try:
                SERVER_HTTPS.serve_forever()
            except Exception as e:
                print(f"HTTPS Server notice: {e}")

    threading.Thread(target=run_http, daemon=True).start()
    if SERVER_HTTPS:
        threading.Thread(target=run_https, daemon=True).start()

    return True, "Servers started successfully"


def setup_system_tray():
    global TRAY_ICON
    try:
        icon_image = create_tray_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("🌐 Open Web Gallery", on_open_browser),
            pystray.MenuItem("🔄 Switch Vault", on_switch_vault),
            pystray.MenuItem("☁️ Cloud Backup to Google Drive", on_cloud_backup_action),
            pystray.MenuItem("🔒 Exit Server", on_exit_server)
        )
        TRAY_ICON = pystray.Icon("CryptHaven", icon_image, f"CryptHaven Server (HTTP:{PORT} HTTPS:{HTTPS_PORT})", menu)
        TRAY_ICON.run()
    except Exception as e:
        print(f"System Tray Notice: {e}")


def run_vault_cycle(selected_vault_dir=None):
    """Run one cycle of vault selection -> server start -> tray icon loop."""
    if not selected_vault_dir:
        selected_vault_dir = launch_vault_selector_ui()

    if not selected_vault_dir:
        print("No vault selected. Exiting CryptHaven.")
        return False

    set_vault_folder(selected_vault_dir)
    add_to_vault_history(selected_vault_dir)

    success, msg = start_servers()
    if not success:
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("CryptHaven Server Error", msg)
            root.destroy()
        except Exception:
            print(f"Server Startup Error: {msg}")
        return False

    print(f"=======================================================================")
    print(f"🔒 CryptHaven — Encrypted Media Vault Server")
    print(f"  HTTP Access:  http://{LOCAL_IP}:{PORT} (or http://127.0.0.1:{PORT})")
    print(f"  HTTPS Access: https://{LOCAL_IP}:{HTTPS_PORT} (or https://127.0.0.1:{HTTPS_PORT})")
    print(f"  Vault Directory: {VAULT_FOLDER}")
    print(f"  Remote Shutdown: {'ENABLED' if ENABLE_REMOTE_SHUTDOWN else 'disabled'}")
    print(f"=======================================================================")

    # Automatically open default browser to the bound HTTP/HTTPS port
    def auto_open_browser():
        time.sleep(0.5)
        open_vault_browser()

    threading.Thread(target=auto_open_browser, daemon=True).start()

    global RESTART_REQUESTED
    RESTART_REQUESTED = False

    try:
        setup_system_tray()
    except Exception as e:
        print(f"System Tray exception: {e}")

    if not RESTART_REQUESTED and SERVER_HTTPD is not None:
        try:
            while SERVER_HTTPD is not None and not RESTART_REQUESTED:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            print("Server shutdown gracefully.")
            stop_servers()
            return False

    stop_servers()
    return RESTART_REQUESTED


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="CryptHaven — Encrypted Media Vault Server")
    parser.add_argument("--vault-dir", type=str, help="Path to vault folder (bypasses launcher UI)")
    parser.add_argument("--headless", action="store_true", help="Run in headless mode without GUI launcher")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.self_test:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        assert root.tk.eval('info patchlevel').startswith('8.6.')
        root.update_idletasks()
        root.destroy()
        test_dek = generate_dek()
        test_context = 'packaged-self-test'
        test_payload = vault_encrypt(b'CryptHaven self-test', test_dek, test_context)
        assert vault_decrypt(test_payload, test_dek, context=test_context) == b'CryptHaven self-test'
        tampered_payload = test_payload[:-1] + bytes([test_payload[-1] ^ 1])
        try:
            vault_decrypt(tampered_payload, test_dek, context=test_context)
        except Exception:
            pass
        else:
            raise AssertionError("AES-GCM tamper detection failed")
        raise SystemExit(0)

    ensure_single_instance()

    cli_vault = args.vault_dir
    if not cli_vault and args.headless:
        cli_vault = default_vault_dir()

    target_vault = cli_vault
    while True:
        restart = run_vault_cycle(target_vault)
        target_vault = None
        if not restart:
            break

