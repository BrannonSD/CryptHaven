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
import argparse
import ipaddress
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

pillow_heif.register_heif_opener()
if sys.stdout is not None and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# ---------------------------------------------------------------------------
#  CryptHaven — Encrypted Media Vault Server
#  https://github.com/BrannonSD/CryptHaven
# ---------------------------------------------------------------------------

# ── Configuration ──────────────────────────────────────────────────────────
PORT = int(os.environ.get('CRYPTHAVEN_PORT', 8080))
HTTPS_PORT = int(os.environ.get('CRYPTHAVEN_HTTPS_PORT', 8443))
ALLOW_DOWNLOADS = os.environ.get('CRYPTHAVEN_ALLOW_DOWNLOADS', 'false').lower() == 'true'
ENABLE_REMOTE_SHUTDOWN = os.environ.get('CRYPTHAVEN_ENABLE_SHUTDOWN', 'false').lower() == 'true'
MAX_UPLOAD_BYTES = int(os.environ.get('CRYPTHAVEN_MAX_UPLOAD_MB', 500)) * 1024 * 1024


def detect_local_ip():
    """Detect the primary LAN IP address of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'


LOCAL_IP = detect_local_ip()

# ── Vault Path Management & Dynamic Resolution ──────────────────────────────
VAULT_FOLDER = ""
DATA_DIR = ""
SALT_PATH = ""
INDEX_PATH = ""
CERT_PATH = ""
KEY_PATH = ""


def set_vault_folder(folder_path: str):
    """Dynamically set the active vault folder and resolve associated paths."""
    global VAULT_FOLDER, DATA_DIR, SALT_PATH, INDEX_PATH, CERT_PATH, KEY_PATH
    VAULT_FOLDER = os.path.abspath(folder_path)
    DATA_DIR = os.path.join(VAULT_FOLDER, "data")
    SALT_PATH = os.path.join(VAULT_FOLDER, "vault_salt.bin")
    INDEX_PATH = os.path.join(VAULT_FOLDER, "vault_index.json")
    CERT_PATH = os.path.join(VAULT_FOLDER, "vault_cert.pem")
    KEY_PATH = os.path.join(VAULT_FOLDER, "vault_key.pem")
    os.makedirs(DATA_DIR, exist_ok=True)


def is_valid_vault(folder_path: str) -> bool:
    """Check if a directory contains existing CryptHaven vault metadata."""
    if not folder_path or not os.path.isdir(folder_path):
        return False
    salt_exists = os.path.exists(os.path.join(folder_path, "vault_salt.bin"))
    idx_exists = os.path.exists(os.path.join(folder_path, "vault_index.json"))
    return salt_exists and idx_exists


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

    if not history:
        default_dir = os.environ.get(
            'CRYPTHAVEN_VAULT_DIR',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault')
        )
        initialize_vault_folder(default_dir)
        history = [default_dir]
        save_vault_history(history)

    return history


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
        default_dir = os.environ.get(
            'CRYPTHAVEN_VAULT_DIR',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault')
        )
        initialize_vault_folder(default_dir)
        return default_dir

    selected_path = {"val": None}

    root = tk.Tk()
    root.title("CryptHaven — Vault Launcher")
    root.geometry("640x480")
    root.minsize(580, 420)
    root.configure(bg="#0f172a")

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
        text="🛡️ CryptHaven Vault Launcher",
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
ACTIVE_SESSIONS = set()
ACTIVE_FERNET = None
DECRYPTED_INDEX = []
ENC_ID_LOOKUP = {}  # enc_id -> item dict for O(1) lookups
LAST_ACTIVITY_TIME = time.time()
INACTIVITY_TIMEOUT_SECONDS = 900  # 15 minutes auto-lock
FAILED_LOGINS = {}  # IP -> {'count': int, 'lockout_until': float}
FAILED_LOGINS_LOCK = threading.Lock()

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

        with open(KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("🔒 Auto-generated 2048-bit RSA Self-Signed TLS Certificate & Key.")
        return True
    except Exception as e:
        print(f"SSL Generation Warning: {e}")
        return False

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def save_index():
    if ACTIVE_FERNET and DECRYPTED_INDEX is not None:
        new_json_bytes = json.dumps(DECRYPTED_INDEX, indent=2).encode('utf-8')
        ciphertext = ACTIVE_FERNET.encrypt(new_json_bytes)
        with open(INDEX_PATH, 'wb') as idx_f:
            idx_f.write(ciphertext)

def load_vault(password: str):
    global ACTIVE_FERNET, DECRYPTED_INDEX, ENC_ID_LOOKUP, LAST_ACTIVITY_TIME
    
    if not os.path.exists(SALT_PATH) or not os.path.exists(INDEX_PATH):
        salt = secrets.token_bytes(16)
        with open(SALT_PATH, 'wb') as sf: sf.write(salt)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        DECRYPTED_INDEX = []
        ENC_ID_LOOKUP = {}
        ciphertext = fernet.encrypt(json.dumps(DECRYPTED_INDEX).encode('utf-8'))
        with open(INDEX_PATH, 'wb') as idx_f: idx_f.write(ciphertext)
        
        ACTIVE_FERNET = fernet
        LAST_ACTIVITY_TIME = time.time()
        return True, "Vault initialized & unlocked"

    with open(SALT_PATH, 'rb') as sf:
        salt = sf.read()
        
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    try:
        with open(INDEX_PATH, 'rb') as idx_f:
            ciphertext = idx_f.read()
        plaintext = fernet.decrypt(ciphertext)
        DECRYPTED_INDEX = json.loads(plaintext.decode('utf-8'))
        
        for item in DECRYPTED_INDEX:
            if 'starred' not in item: item['starred'] = False
            if 'enc_thumb_id' not in item: item['enc_thumb_id'] = None
            if 'is_live_photo' not in item: item['is_live_photo'] = False

        ENC_ID_LOOKUP = {item['enc_id']: item for item in DECRYPTED_INDEX}
        ACTIVE_FERNET = fernet
        LAST_ACTIVITY_TIME = time.time()
        return True, "Vault unlocked successfully"
    except Exception as e:
        return False, f"Invalid Password ({e})"

def lock_vault():
    global ACTIVE_FERNET, DECRYPTED_INDEX, ENC_ID_LOOKUP
    ACTIVE_FERNET = None
    DECRYPTED_INDEX = []
    ENC_ID_LOOKUP = {}
    ACTIVE_SESSIONS.clear()

def find_google_drive_folder():
    """Detect Google Drive mounted folder on Windows."""
    candidates = []
    for letter in string.ascii_uppercase:
        candidates.append(f"{letter}:\\My Drive")
        candidates.append(f"{letter}:\\Google Drive")
    
    user_home = os.path.expanduser('~')
    candidates.append(os.path.join(user_home, "Google Drive", "My Drive"))
    candidates.append(os.path.join(user_home, "Google Drive"))
    candidates.append(os.path.join(user_home, "My Drive"))

    for path in candidates:
        if os.path.exists(path) and os.path.isdir(path):
            return path
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

    for main_file in [SALT_PATH, INDEX_PATH]:
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
    return True, f"✨ Cloud Backup Complete!\nSynced to: {target_backup_dir}", target_backup_dir, copied_files_count, copied_mb

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
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data: blob:")

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

    def check_auth(self):
        global LAST_ACTIVITY_TIME
        now = time.time()
        
        if now - LAST_ACTIVITY_TIME > INACTIVITY_TIMEOUT_SECONDS:
            lock_vault()
            return False

        if ACTIVE_FERNET is None:
            return False

        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookies = dict(c.strip().split('=', 1) for c in cookie_header.split(';') if '=' in c)
            session_cookie = cookies.get('auth_session')
            if session_cookie and session_cookie in ACTIVE_SESSIONS:
                LAST_ACTIVITY_TIME = now
                return True

        auth_hdr = self.headers.get('X-Auth-Token')
        if auth_hdr and auth_hdr in ACTIVE_SESSIONS:
            LAST_ACTIVITY_TIME = now
            return True

        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        url_token = query.get('token', [''])[0]
        if url_token and url_token in ACTIVE_SESSIONS:
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
            self.send_header('Cache-Control', 'private, max-age=86400')
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def do_POST(self):
        global ACTIVE_FERNET
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/login':
            allowed, remaining_sec = self.check_rate_limit(client_ip)
            if not allowed:
                self.send_json({'success': False, 'error': f'Too many failed attempts. Locked out for {remaining_sec} seconds.'}, status=429)
                return

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            pwd = params.get('password', [''])[0]
            success, msg = load_vault(pwd)
            if success:
                if client_ip in FAILED_LOGINS: FAILED_LOGINS[client_ip] = {'count': 0, 'lockout_until': 0}
                
                new_session_token = secrets.token_hex(16)
                ACTIVE_SESSIONS.add(new_session_token)

                self.send_response(200)
                self.inject_security_headers()
                self.send_header('Set-Cookie', f'auth_session={new_session_token}; Path=/; HttpOnly; SameSite=Strict')
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'token': new_session_token}).encode('utf-8'))
            else:
                self.record_failed_login(client_ip)
                self.send_json({'success': False, 'error': 'Access denied'}, status=401)
            return

        if parsed.path == '/logout':
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                cookies = dict(c.strip().split('=', 1) for c in cookie_header.split(';') if '=' in c)
                st = cookies.get('auth_session')
                if st in ACTIVE_SESSIONS: ACTIVE_SESSIONS.remove(st)
            
            auth_hdr = self.headers.get('X-Auth-Token')
            if auth_hdr in ACTIVE_SESSIONS: ACTIVE_SESSIONS.remove(auth_hdr)

            self.send_json({'success': True, 'message': 'Logged out!'})
            return

        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, status=401)
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

            placeholder_id = f"enc_folder_{int(time.time())}.enc"
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
                for item in items_to_modify:
                    enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                    if os.path.exists(enc_fpath):
                        try: os.remove(enc_fpath)
                        except Exception: pass

                    if item.get('enc_thumb_id'):
                        thumb_fpath = os.path.join(DATA_DIR, item['enc_thumb_id'])
                        if os.path.exists(thumb_fpath):
                            try: os.remove(thumb_fpath)
                            except Exception: pass

                    if item in DECRYPTED_INDEX:
                        DECRYPTED_INDEX.remove(item)
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
                enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                if os.path.exists(enc_fpath):
                    try: os.remove(enc_fpath)
                    except Exception: pass

                if item.get('enc_thumb_id'):
                    thumb_fpath = os.path.join(DATA_DIR, item['enc_thumb_id'])
                    if os.path.exists(thumb_fpath):
                        try: os.remove(thumb_fpath)
                        except Exception: pass

                DECRYPTED_INDEX.remove(item)
                save_index()
                self.send_json({'success': True, 'enc_id': enc_id})
                return
            self.send_json({'success': False, 'error': 'File not found'}, status=404)
            return

        # 1-Click Cryptographic SHA-256 Hash Duplicate Cleaner (Zero False-Positives Guarantee!)
        if parsed.path == '/api/admin/auto_clean_all_duplicates':
            if not ACTIVE_FERNET:
                self.send_json({'success': False, 'error': 'Vault locked'}, status=401)
                return

            hash_map = defaultdict(list)
            for item in DECRYPTED_INDEX:
                if item['name'].startswith('.'): continue
                enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                if os.path.exists(enc_fpath):
                    try:
                        with open(enc_fpath, 'rb') as ef: ciphertext = ef.read()
                        plaintext = ACTIVE_FERNET.decrypt(ciphertext)
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
                        enc_fpath = os.path.join(DATA_DIR, extra_item['enc_id'])
                        if os.path.exists(enc_fpath):
                            try: os.remove(enc_fpath)
                            except Exception: pass

                        if extra_item.get('enc_thumb_id'):
                            thumb_fpath = os.path.join(DATA_DIR, extra_item['enc_thumb_id'])
                            if os.path.exists(thumb_fpath):
                                try: os.remove(thumb_fpath)
                                except Exception: pass

                        to_remove.append(extra_item)
                        deleted_count += 1
                        freed_bytes += extra_item['size']

            for item in to_remove:
                if item in DECRYPTED_INDEX:
                    DECRYPTED_INDEX.remove(item)

            if deleted_count > 0:
                save_index()

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

            deleted_count = 0
            to_remove = []
            for item in DECRYPTED_INDEX:
                if item['enc_id'] in enc_ids:
                    enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                    if os.path.exists(enc_fpath):
                        try: os.remove(enc_fpath)
                        except Exception: pass

                    if item.get('enc_thumb_id'):
                        thumb_fpath = os.path.join(DATA_DIR, item['enc_thumb_id'])
                        if os.path.exists(thumb_fpath):
                            try: os.remove(thumb_fpath)
                            except Exception: pass

                    to_remove.append(item)
                    deleted_count += 1

            for item in to_remove: DECRYPTED_INDEX.remove(item)
            if deleted_count > 0: save_index()
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
            
            if 'multipart/form-data' in content_type and length > 0:
                boundary = content_type.split("boundary=")[1].encode('utf-8')
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

                if filename and file_bytes and ACTIVE_FERNET:
                    enc_id = f"enc_{len(DECRYPTED_INDEX):06d}_{int(time.time())}.enc"
                    enc_fpath = os.path.join(DATA_DIR, enc_id)

                    ciphertext = ACTIVE_FERNET.encrypt(file_bytes)
                    with open(enc_fpath, 'wb') as ef:
                        ef.write(ciphertext)

                    ext = os.path.splitext(filename)[1].lower()
                    is_video = ext in ['.mov', '.mp4', '.m4v', '.avi']
                    clean_sub = subfolder.strip().replace('\\', '/').strip('/')
                    if clean_sub in ['.', '..', '__UNCATEGORIZED__', '__ALL__']: clean_sub = ''

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

                    DECRYPTED_INDEX.append(item_meta)
                    save_index()

                    self.send_json({'success': True, 'name': filename, 'enc_id': enc_id})
                    return

            self.send_json({'success': False, 'error': 'Invalid upload payload'}, status=400)
            return

        if parsed.path == '/api/admin/change_password':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else ""
            params = urllib.parse.parse_qs(body)
            new_pwd = params.get('new_password', [''])[0]

            if new_pwd and ACTIVE_FERNET:
                with open(SALT_PATH, 'rb') as sf: salt = sf.read()
                new_key = derive_key(new_pwd, salt)
                new_fernet = Fernet(new_key)
                
                new_json_bytes = json.dumps(DECRYPTED_INDEX, indent=2).encode('utf-8')
                with open(INDEX_PATH, 'wb') as idx_f:
                    idx_f.write(new_fernet.encrypt(new_json_bytes))
                
                ACTIVE_FERNET = new_fernet
                self.send_json({'success': True, 'message': 'Master password changed successfully!'})
                return

            self.send_json({'success': False, 'error': 'Invalid new password'}, status=400)
            return

        if parsed.path == '/api/admin/export_vault':
            if not ALLOW_DOWNLOADS:
                self.send_json({'success': False, 'error': 'Decrypted media export is disabled for this vault session.'}, status=403)
                return

            export_dir = os.path.join(VAULT_FOLDER, "Exported_Decrypted_Media")
            os.makedirs(export_dir, exist_ok=True)

            exported_count = 0
            if ACTIVE_FERNET and DECRYPTED_INDEX:
                for item in DECRYPTED_INDEX:
                    if item['name'].startswith('.'): continue
                    enc_fpath = os.path.join(DATA_DIR, item['enc_id'])
                    if os.path.exists(enc_fpath):
                        try:
                            with open(enc_fpath, 'rb') as ef: ciphertext = ef.read()
                            plaintext = ACTIVE_FERNET.decrypt(ciphertext)

                            sub_dir = os.path.join(export_dir, item['subfolder']) if item['subfolder'] else export_dir
                            os.makedirs(sub_dir, exist_ok=True)
                            out_p = os.path.join(sub_dir, item['name'])

                            with open(out_p, 'wb') as out_f:
                                out_f.write(plaintext)
                            exported_count += 1
                        except Exception as e:
                            print(f"Export error for {item['name']}: {e}")

            self.send_json({'success': True, 'count': exported_count, 'path': export_dir})
            return

        if parsed.path == '/shutdown':
            if not ENABLE_REMOTE_SHUTDOWN:
                self.send_json({'success': False, 'error': 'Remote shutdown is disabled. Set CRYPTHAVEN_ENABLE_SHUTDOWN=true to enable.'}, status=403)
                return
            self.send_json({'success': True, 'message': 'PC shutting down in 5 seconds...'})
            print("--- RECEIVED REMOTE SHUTDOWN COMMAND ---")
            os.system("shutdown /s /t 5")
            return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/login':
            self.send_html(HTML_LOGIN)
            return

        if parsed.path == '/api/vault_status':
            is_init = is_valid_vault(VAULT_FOLDER)
            self.send_json({
                'initialized': is_init,
                'vault_name': os.path.basename(VAULT_FOLDER) or "Default Vault",
                'allow_downloads': ALLOW_DOWNLOADS
            })
            return

        if not self.check_auth():
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
            if not ACTIVE_FERNET:
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
                        plaintext = ACTIVE_FERNET.decrypt(ciphertext)
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
                'enable_remote_shutdown': ENABLE_REMOTE_SHUTDOWN
            })
            return

        if parsed.path.startswith('/thumb/'):
            enc_id = urllib.parse.unquote(parsed.path[7:])
            if '?' in enc_id: enc_id = enc_id.split('?')[0]
            
            item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
            
            if item and item.get('enc_thumb_id'):
                enc_thumb_path = os.path.join(DATA_DIR, item['enc_thumb_id'])
                if os.path.exists(enc_thumb_path) and ACTIVE_FERNET:
                    try:
                        with open(enc_thumb_path, 'rb') as ef: ciphertext = ef.read()
                        thumb_bytes = ACTIVE_FERNET.decrypt(ciphertext)
                        self.send_bytes(thumb_bytes, 'image/jpeg')
                        return
                    except Exception: pass

            enc_file_path = os.path.join(DATA_DIR, enc_id)
            if os.path.exists(enc_file_path) and ACTIVE_FERNET:
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = ACTIVE_FERNET.decrypt(ciphertext)
                    
                    with Image.open(io.BytesIO(plaintext)) as img:
                        img.thumbnail((200, 200))
                        if img.mode != 'RGB': img = img.convert('RGB')
                        thumb_io = io.BytesIO()
                        img.save(thumb_io, 'JPEG', quality=75)
                        thumb_bytes = thumb_io.getvalue()

                        enc_thumb_id = f"enc_t_{secrets.token_hex(8)}.enc"
                        enc_thumb_fpath = os.path.join(DATA_DIR, enc_thumb_id)
                        enc_thumb_bytes = ACTIVE_FERNET.encrypt(thumb_bytes)
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
            enc_file_path = os.path.join(DATA_DIR, enc_id)

            if os.path.exists(enc_file_path) and ACTIVE_FERNET:
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = ACTIVE_FERNET.decrypt(ciphertext)

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
                                self.send_header('Cache-Control', 'public, max-age=86400')
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
            enc_file_path = os.path.join(DATA_DIR, enc_id)

            if os.path.exists(enc_file_path) and ACTIVE_FERNET:
                try:
                    with open(enc_file_path, 'rb') as ef: ciphertext = ef.read()
                    plaintext = ACTIVE_FERNET.decrypt(ciphertext)

                    item = next((x for x in DECRYPTED_INDEX if x['enc_id'] == enc_id), None)
                    filename = item['name'] if item else 'download'
                    mime_type, _ = mimetypes.guess_type(filename)
                    if not mime_type:
                        mime_type = 'application/octet-stream'

                    safe_filename = urllib.parse.quote(filename)

                    self.send_response(200)
                    self.inject_security_headers()
                    self.send_header('Content-Type', mime_type)
                    self.send_header('Content-Length', str(len(plaintext)))
                    self.send_header('Content-Disposition', f'attachment; filename="{filename}"; filename*=UTF-8\'\'{safe_filename}')
                    self.send_header('Cache-Control', 'private, no-cache')
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
        <div class="badge" id="vaultBadge">Loading Vault...</div>
        <h2 id="cardTitle">Sign In</h2>
        <p class="sub" id="cardSub">Enter passcode to unlock vault</p>
        
        <input type="password" id="pwd" placeholder="Passcode" autofocus>
        <input type="password" id="pwd_confirm" placeholder="Confirm Passcode" style="display: none;">
        <button id="submitBtn" onclick="login()">Unlock Vault</button>
        <div id="err" class="err"></div>
    </div>
    <script>
        let isInitialized = true;

        async function checkStatus() {
            try {
                const res = await fetch('/api/vault_status');
                const data = await res.json();
                isInitialized = data.initialized;
                document.getElementById('vaultBadge').innerText = '📁 ' + (data.vault_name || 'CryptHaven');

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

        async function login() {
            const pwd = document.getElementById('pwd').value;
            const errEl = document.getElementById('err');
            errEl.innerText = '';

            if (!pwd) {
                errEl.innerText = 'Please enter a passcode.';
                return;
            }

            if (!isInitialized) {
                const confirmPwd = document.getElementById('pwd_confirm').value;
                if (pwd.length < 4) {
                    errEl.innerText = 'Passcode must be at least 4 characters long.';
                    return;
                }
                if (pwd !== confirmPwd) {
                    errEl.innerText = 'Passcodes do not match! Please re-check.';
                    return;
                }
            }

            const res = await fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'password=' + encodeURIComponent(pwd)
            });
            const data = await res.json();
            if (data.success) { 
                if (data.token) sessionStorage.setItem('vault_token', data.token);
                window.location.href = '/';
            } else { 
                errEl.innerText = data.error || 'Access denied'; 
            }
        }

        document.getElementById('pwd').addEventListener('keypress', (e) => { 
            if (e.key === 'Enter') {
                if (!isInitialized) document.getElementById('pwd_confirm').focus();
                else login();
            }
        });
        document.getElementById('pwd_confirm').addEventListener('keypress', (e) => { 
            if (e.key === 'Enter') login(); 
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

        /* DRM Anti-Save & Anti-Screenshot Protection */
        .no-save img, .no-save video, .no-save .v-full-media, .no-save .v-thumb-placeholder {
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -khtml-user-select: none !important;
            -moz-user-select: none !important;
            -ms-user-select: none !important;
            user-select: none !important;
            -webkit-user-drag: none !important;
            user-drag: none !important;
        }
        @media print {
            body { display: none !important; }
        }
    </style>
</head>
<body>
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

        function getTokenParam() {
            const urlParams = new URLSearchParams(window.location.search);
            let token = urlParams.get('token');
            if(!token) token = sessionStorage.getItem('vault_token') || localStorage.getItem('vault_token');
            return token ? '?token=' + encodeURIComponent(token) : '';
        }

        async function authFetch(url, options = {}) {
            options.headers = options.headers || {};
            const urlParams = new URLSearchParams(window.location.search);
            let token = urlParams.get('token');
            if(!token) token = sessionStorage.getItem('vault_token');
            
            if (token) {
                options.headers['X-Auth-Token'] = token;
            }
            options.credentials = 'same-origin';
            
            try {
                const res = await fetch(url, options);
                if (res && res.status === 401) {
                    sessionStorage.removeItem('vault_token');
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

        // Anti-Save & Anti-Screenshot Event Interceptors
        document.addEventListener('contextmenu', (e) => {
            if (!allowDownloads && (e.target.tagName === 'IMG' || e.target.tagName === 'VIDEO' || e.target.closest('#viewer'))) {
                e.preventDefault();
                return false;
            }
        }, { capture: true });

        document.addEventListener('dragstart', (e) => {
            if (!allowDownloads && (e.target.tagName === 'IMG' || e.target.tagName === 'VIDEO')) {
                e.preventDefault();
                return false;
            }
        }, { capture: true });

        // Screenshot Key Interception (PrintScreen, Ctrl+P, Ctrl+S, Cmd+Shift+3/4/5)
        document.addEventListener('keydown', (e) => {
            if (!allowDownloads) {
                if (e.key === 'PrintScreen' || e.code === 'PrintScreen' || 
                    (e.ctrlKey && (e.key === 'p' || e.key === 's')) ||
                    (e.metaKey && (e.key === 'p' || e.key === 's'))) {
                    e.preventDefault();
                    blurViewerOnCapture();
                    return false;
                }
            }
        });

        document.addEventListener('keyup', (e) => {
            if (!allowDownloads && (e.key === 'PrintScreen' || e.code === 'PrintScreen')) {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText('');
                }
                blurViewerOnCapture();
            }
        });

        function blurViewerOnCapture() {
            const vBody = document.getElementById('v-body');
            if (vBody) {
                vBody.style.filter = 'blur(60px) opacity(0)';
                setTimeout(() => { if (scale <= 1.05) vBody.style.filter = 'none'; }, 1500);
            }
        }

        // Mobile App-Switcher & Screenshot Blur Interception (Visibility / Blur Events)
        document.addEventListener('visibilitychange', () => {
            const vBody = document.getElementById('v-body');
            if (document.visibilityState === 'hidden' && !allowDownloads) {
                if (vBody) vBody.style.filter = 'blur(60px) opacity(0)';
            } else {
                if (vBody && scale <= 1.05) vBody.style.filter = 'none';
            }
        });

        window.addEventListener('blur', () => {
            if (!allowDownloads) {
                const vBody = document.getElementById('v-body');
                if (vBody) vBody.style.filter = 'blur(60px) opacity(0)';
            }
        });

        window.addEventListener('focus', () => {
            const vBody = document.getElementById('v-body');
            if (vBody && scale <= 1.05) vBody.style.filter = 'none';
        });

        async function init() {
            checkVaultConfig().catch(e => console.error("checkVaultConfig error:", e));
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
                    fDiv.innerHTML = `
                        <div>
                            <div class="f-info">📂 ${f.name}</div>
                            <div class="f-subcount">${f.count} item(s)</div>
                        </div>
                        <div class="f-actions">
                            <button class="btn-f-act" style="background:#0284c7; color:#fff;" onclick="promptCreateSubfolder('${f.path}')">➕ Sub</button>
                            <button class="btn-f-act" style="background:#f59e0b; color:#fff;" onclick="promptRenameFolder('${f.path}')">✏️ Rename</button>
                            <button class="btn-f-act" style="background:#ef4444; color:#fff;" onclick="promptDeleteFolder('${f.path}', ${f.count})">🗑️ Delete</button>
                        </div>
                    `;
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

            const tokenParam = getTokenParam();

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
                    
                    const thumbUrl = '/thumb/' + encodeURIComponent(f.enc_id) + tokenParam;
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

            const tokenParam = getTokenParam();

            duplicateData.duplicate_groups.forEach((g, gIdx) => {
                const groupDiv = document.createElement('div');
                groupDiv.className = 'dup-group';
                
                let cardsHtml = '';
                g.items.forEach((it, iIdx) => {
                    const thumbUrl = '/thumb/' + encodeURIComponent(it.enc_id) + tokenParam;
                    cardsHtml += `
                        <div class="dup-item-card">
                            <input type="checkbox" class="dup-item-cb" id="dup-cb-${it.enc_id}" onchange="toggleDupSelection('${it.enc_id}')">
                            <img src="${thumbUrl}">
                            <div style="margin-top:2px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${it.name}</div>
                        </div>
                    `;
                });

                groupDiv.innerHTML = `
                    <div class="dup-hdr">
                        <span>Group #${gIdx+1} (${g.size_formatted})</span>
                        <span style="color:#94a3b8;">${g.copies_count} Copies</span>
                    </div>
                    <div class="dup-items-row">${cardsHtml}</div>
                `;
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
            const newPwd = prompt("Enter new password:");
            if(newPwd) {
                const res = await authFetch('/api/admin/change_password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'new_password=' + encodeURIComponent(newPwd)
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

        async function lockVaultNow() {
            await authFetch('/logout', { method: 'POST' });
            sessionStorage.removeItem('vault_token');
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
            const tokenParam = getTokenParam();
            img.src = '/media/' + encodeURIComponent(enc_id) + tokenParam;
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
            const tokenParam = getTokenParam();
            const thumbUrl = '/thumb/' + encodeURIComponent(f.enc_id) + tokenParam;
            const mediaUrl = '/media/' + encodeURIComponent(f.enc_id) + tokenParam;
            
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

            const tokenParam = getTokenParam();
            const downloadUrl = '/download/' + encodeURIComponent(f.enc_id) + tokenParam;

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


def on_open_browser(icon, item):
    webbrowser.open(f"http://127.0.0.1:{PORT}")


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


def bind_http_server(start_port):
    """Bind HTTP listeners across both 127.0.0.1 (for local firewall bypass) and LOCAL_IP (for LAN/mobile access)."""
    servers = []
    actual_port = None

    for p in range(start_port, start_port + 20):
        try:
            s1 = ThreadedHTTPServer(('127.0.0.1', p), VaultGalleryHandler)
            servers.append(s1)
            actual_port = p

            if LOCAL_IP and LOCAL_IP not in ('127.0.0.1', '0.0.0.0'):
                try:
                    s2 = ThreadedHTTPServer((LOCAL_IP, p), VaultGalleryHandler)
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
            ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)

            s1 = ThreadedHTTPServer(('127.0.0.1', p), VaultGalleryHandler)
            s1.socket = ctx.wrap_socket(s1.socket, server_side=True)
            servers.append(s1)
            actual_port = p

            if LOCAL_IP and LOCAL_IP not in ('127.0.0.1', '0.0.0.0'):
                try:
                    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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

    # Automatically open default browser to the bound HTTP port
    def auto_open_browser():
        time.sleep(0.5)
        webbrowser.open(f"http://127.0.0.1:{PORT}")

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
    args = parser.parse_args()

    cli_vault = args.vault_dir
    if not cli_vault and args.headless:
        cli_vault = os.environ.get(
            'CRYPTHAVEN_VAULT_DIR',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault')
        )

    target_vault = cli_vault
    while True:
        restart = run_vault_cycle(target_vault)
        target_vault = None
        if not restart:
            break

