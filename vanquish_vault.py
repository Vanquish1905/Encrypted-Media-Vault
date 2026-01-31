import os
import sys
import json
import shutil
import base64
import hashlib
import secrets
import threading
import datetime
import tempfile
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import defaultdict
from io import BytesIO

try:
    import customtkinter as ctk
    from PIL import Image, ImageTk
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.backends import default_backend
    import argon2
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install customtkinter pillow cryptography argon2-cffi")
    sys.exit(1)

PEPPER = "V4nQu1sH_S3cR3t_P3pp3r_2024_X9kL7mN2pQ8rT5wY"
CHUNK_SIZE = 65536

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

THEMES = {
    "Rainforest": {
        "bg": "#1a2f1a",
        "fg": "#2d4a2d",
        "accent": "#4a7c4a",
        "text": "#e8f5e8",
        "highlight": "#6b9b6b",
        "card": "#243824",
        "wallpaper": "rainforest"
    },
    "Ocean": {
        "bg": "#0a1628",
        "fg": "#1a3a5c",
        "accent": "#2980b9",
        "text": "#e8f4fc",
        "highlight": "#3498db",
        "card": "#0f2744",
        "wallpaper": "ocean"
    },
    "Sunset": {
        "bg": "#2d1b2d",
        "fg": "#4a2c4a",
        "accent": "#c0392b",
        "text": "#fce8e8",
        "highlight": "#e74c3c",
        "card": "#3d243d",
        "wallpaper": "sunset"
    },
    "Midnight": {
        "bg": "#0d0d1a",
        "fg": "#1a1a2e",
        "accent": "#4a4aff",
        "text": "#e8e8fc",
        "highlight": "#6b6bff",
        "card": "#12122a",
        "wallpaper": "midnight"
    },
    "Arctic": {
        "bg": "#e8f4f8",
        "fg": "#d0e8f0",
        "accent": "#0984e3",
        "text": "#1a1a2e",
        "highlight": "#74b9ff",
        "card": "#f0f8fc",
        "wallpaper": "arctic"
    },
    "Volcano": {
        "bg": "#1a0a0a",
        "fg": "#2d1515",
        "accent": "#d63031",
        "text": "#fce8e8",
        "highlight": "#ff6b6b",
        "card": "#241010",
        "wallpaper": "volcano"
    },
    "Cyber": {
        "bg": "#0a0a14",
        "fg": "#141428",
        "accent": "#00ff88",
        "text": "#e8fcf0",
        "highlight": "#00cc6a",
        "card": "#0f0f1e",
        "wallpaper": "cyber"
    },
    "Sakura": {
        "bg": "#2d1a24",
        "fg": "#3d2434",
        "accent": "#ff69b4",
        "text": "#fce8f4",
        "highlight": "#ff85c8",
        "card": "#382030",
        "wallpaper": "sakura"
    },
    "Desert": {
        "bg": "#2d2418",
        "fg": "#3d3420",
        "accent": "#d4a574",
        "text": "#fcf4e8",
        "highlight": "#e8c090",
        "card": "#382c1e",
        "wallpaper": "desert"
    },
    "Classic Dark": {
        "bg": "#1a1a1a",
        "fg": "#2d2d2d",
        "accent": "#3498db",
        "text": "#ffffff",
        "highlight": "#5dade2",
        "card": "#242424",
        "wallpaper": None
    }
}

ICONS = {
    "folder": "\U0001F4C1",
    "folder_open": "\U0001F4C2",
    "file": "\U0001F4C4",
    "image": "\U0001F5BC",
    "video": "\U0001F3AC",
    "audio": "\U0001F3B5",
    "document": "\U0001F4DD",
    "pdf": "\U0001F4D5",
    "archive": "\U0001F4E6",
    "code": "\U0001F4BB",
    "settings": "\u2699",
    "lock": "\U0001F512",
    "unlock": "\U0001F513",
    "upload": "\U0001F4E4",
    "download": "\U0001F4E5",
    "delete": "\U0001F5D1",
    "search": "\U0001F50D",
    "back": "\u2B05",
    "forward": "\u27A1",
    "home": "\U0001F3E0",
    "refresh": "\U0001F504",
    "warning": "\u26A0",
    "success": "\u2705",
    "error": "\u274C",
    "info": "\u2139",
    "shield": "\U0001F6E1",
    "key": "\U0001F511",
    "chart": "\U0001F4CA",
    "clock": "\U0001F551",
    "trash": "\U0001F5D1",
    "cut": "\u2702",
    "copy": "\U0001F4CB",
    "paste": "\U0001F4CB",
    "rename": "\u270F",
    "shred": "\U0001F525",
    "diagnostics": "\U0001F527",
    "text": "\U0001F4C3",
    "secure": "\U0001F510"
}

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.tiff'}
VIDEO_EXTENSIONS = {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'}
AUDIO_EXTENSIONS = {'.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.wma'}
DOCUMENT_EXTENSIONS = {'.txt', '.doc', '.docx', '.rtf', '.odt', '.md'}
PDF_EXTENSIONS = {'.pdf'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
CODE_EXTENSIONS = {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.h', '.json', '.xml', '.yaml', '.yml'}

def get_file_icon(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in IMAGE_EXTENSIONS:
        return ICONS["image"]
    elif ext in VIDEO_EXTENSIONS:
        return ICONS["video"]
    elif ext in AUDIO_EXTENSIONS:
        return ICONS["audio"]
    elif ext in DOCUMENT_EXTENSIONS:
        return ICONS["document"]
    elif ext in PDF_EXTENSIONS:
        return ICONS["pdf"]
    elif ext in ARCHIVE_EXTENSIONS:
        return ICONS["archive"]
    elif ext in CODE_EXTENSIONS:
        return ICONS["code"]
    else:
        return ICONS["file"]

def get_file_category(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in IMAGE_EXTENSIONS:
        return "Images"
    elif ext in VIDEO_EXTENSIONS:
        return "Videos"
    elif ext in AUDIO_EXTENSIONS:
        return "Audio"
    elif ext in DOCUMENT_EXTENSIONS or ext in PDF_EXTENSIONS:
        return "Documents"
    elif ext in ARCHIVE_EXTENSIONS:
        return "Archives"
    elif ext in CODE_EXTENSIONS:
        return "Code"
    else:
        return "Other"

class ErrorLogger:
    def __init__(self, base_path, enabled=False):
        self.base_path = base_path
        self.enabled = enabled
        self.log_path = os.path.join(base_path, "vault_debug.log")
        self.logs = []
        self._load_logs()

    def _load_logs(self):
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    self.logs = json.load(f)
            except:
                self.logs = []

    def _save_logs(self):
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(self.logs[-1000:], f, indent=2)
        except:
            pass

    def log(self, level, message, details=None):
        if not self.enabled and level != "CRITICAL":
            return
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "level": level,
            "message": message,
            "details": str(details) if details else None
        }
        self.logs.append(entry)
        self._save_logs()

    def get_logs(self, level=None, limit=100):
        filtered = self.logs if not level else [l for l in self.logs if l["level"] == level]
        return filtered[-limit:]

    def clear_logs(self):
        self.logs = []
        self._save_logs()

class SecurityManager:
    def __init__(self, base_path, logger=None):
        self.base_path = base_path
        self.config_path = os.path.join(base_path, "vault_config.dat")
        self.data_path = os.path.join(base_path, "vault_data")
        self.meta_path = os.path.join(base_path, "vault_meta.dat")
        self.lockout_path = os.path.join(base_path, "lockout.dat")
        self.master_key = None
        self.user_key = None
        self.config = {}
        self.failed_attempts = 0
        self.lockout_until = None
        self.logger = logger
        self.metadata_cache = None
        self._ensure_dirs()
        self._load_config()
        self._load_lockout()

    def _ensure_dirs(self):
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)
        if not os.path.exists(self.data_path):
            os.makedirs(self.data_path)

    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    self.config = json.load(f)
            except:
                self.config = {}

    def _save_config(self):
        with open(self.config_path, "w") as f:
            json.dump(self.config, f)

    def _load_lockout(self):
        if os.path.exists(self.lockout_path):
            try:
                with open(self.lockout_path, "r") as f:
                    data = json.load(f)
                    self.failed_attempts = data.get("attempts", 0)
                    lockout_str = data.get("lockout_until")
                    if lockout_str:
                        self.lockout_until = datetime.datetime.fromisoformat(lockout_str)
            except:
                pass

    def _save_lockout(self):
        data = {
            "attempts": self.failed_attempts,
            "lockout_until": self.lockout_until.isoformat() if self.lockout_until else None
        }
        with open(self.lockout_path, "w") as f:
            json.dump(data, f)

    def is_setup(self):
        return "enc_master_key" in self.config

    def _derive_key_argon2(self, password, salt):
        peppered = password + PEPPER
        key = hash_secret_raw(
            peppered.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        return key

    def setup_vault(self, password, use_password=True):
        self.master_key = AESGCM.generate_key(bit_length=256)
        salt = os.urandom(32)
        self.config["salt"] = base64.b64encode(salt).decode('utf-8')
        self.config["use_password"] = use_password
        self.config["uuid"] = secrets.token_hex(8)
        self.config["created"] = datetime.datetime.now().isoformat()

        if use_password:
            self.user_key = self._derive_key_argon2(password, salt)
        else:
            self.user_key = salt[:32]

        aesgcm = AESGCM(self.user_key)
        nonce = os.urandom(12)
        enc_master_key = aesgcm.encrypt(nonce, self.master_key, None)
        self.config["enc_master_key"] = base64.b64encode(nonce + enc_master_key).decode('utf-8')
        self._save_config()
        self._init_metadata()
        if self.logger:
            self.logger.log("INFO", "Vault created successfully")

    def unlock_vault(self, password):
        if self.lockout_until and datetime.datetime.now() < self.lockout_until:
            remaining = (self.lockout_until - datetime.datetime.now()).seconds
            if self.logger:
                self.logger.log("WARNING", f"Vault locked, {remaining}s remaining")
            return False, "LOCKED", remaining

        try:
            salt = base64.b64decode(self.config["salt"])
            encrypted_bundle = base64.b64decode(self.config["enc_master_key"])
            nonce = encrypted_bundle[:12]
            ciphertext = encrypted_bundle[12:]

            if self.config.get("use_password", True):
                user_key = self._derive_key_argon2(password, salt)
            else:
                user_key = salt[:32]

            aesgcm = AESGCM(user_key)
            self.master_key = aesgcm.decrypt(nonce, ciphertext, None)
            self.user_key = user_key
            self.failed_attempts = 0
            self.lockout_until = None
            self._save_lockout()
            if self.logger:
                self.logger.log("INFO", "Vault unlocked successfully")
            return True, "SUCCESS", 0
        except Exception as e:
            self.failed_attempts += 1
            if self.logger:
                self.logger.log("WARNING", f"Failed unlock attempt #{self.failed_attempts}", str(e))
            
            if self.failed_attempts >= 3:
                lockout_minutes = min(5 * (2 ** (self.failed_attempts - 3)), 60)
                self.lockout_until = datetime.datetime.now() + datetime.timedelta(minutes=lockout_minutes)
                self._save_lockout()
                if self.logger:
                    self.logger.log("CRITICAL", f"Brute force detected, locked for {lockout_minutes} minutes")
                return False, "LOCKED", lockout_minutes * 60
            
            self._save_lockout()
            return False, "INVALID", 0

    def change_password(self, new_password, enable_password):
        if not self.master_key:
            return False

        salt = os.urandom(32)
        self.config["salt"] = base64.b64encode(salt).decode('utf-8')
        self.config["use_password"] = enable_password

        if enable_password:
            new_user_key = self._derive_key_argon2(new_password, salt)
        else:
            new_user_key = salt[:32]

        aesgcm = AESGCM(new_user_key)
        nonce = os.urandom(12)
        enc_master_key = aesgcm.encrypt(nonce, self.master_key, None)
        self.config["enc_master_key"] = base64.b64encode(nonce + enc_master_key).decode('utf-8')
        self.user_key = new_user_key
        self._save_config()
        if self.logger:
            self.logger.log("INFO", "Password changed successfully")
        return True

    def encrypt_file(self, file_path, dest_folder_id, progress_callback=None):
        if not self.master_key:
            return None
        try:
            filename = os.path.basename(file_path)
            file_id = secrets.token_hex(16)
            enc_filename = file_id + ".enc"
            dest_path = os.path.join(self.data_path, enc_filename)
            file_size = os.path.getsize(file_path)

            nonce = os.urandom(12)
            key = self.master_key[:32]
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce + b'\x00' * 4), backend=default_backend())
            encryptor = cipher.encryptor()

            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

            with open(file_path, "rb") as f_in, open(dest_path, "wb") as f_out:
                f_out.write(nonce)
                processed = 0
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    h.update(encrypted_chunk)
                    f_out.write(encrypted_chunk)
                    processed += len(chunk)
                    if progress_callback:
                        progress_callback(processed / file_size)

                f_out.write(encryptor.finalize())
                mac = h.finalize()
                f_out.write(mac)

            if self.logger:
                self.logger.log("INFO", f"File encrypted: {filename}")

            return {
                "id": file_id,
                "name": filename,
                "type": "file",
                "parent_id": dest_folder_id,
                "size": file_size,
                "created": datetime.datetime.now().isoformat(),
                "modified": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            if self.logger:
                self.logger.log("ERROR", f"Encryption failed: {filename}", str(e))
            return None

    def decrypt_file_to_temp(self, file_id, temp_dir, progress_callback=None):
        try:
            enc_path = os.path.join(self.data_path, file_id + ".enc")
            if not os.path.exists(enc_path):
                return None

            file_size = os.path.getsize(enc_path)
            key = self.master_key[:32]

            with open(enc_path, "rb") as f_in:
                nonce = f_in.read(12)
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce + b'\x00' * 4), backend=default_backend())
                decryptor = cipher.decryptor()

                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                
                temp_path = os.path.join(temp_dir, file_id)
                
                encrypted_data = f_in.read()
                stored_mac = encrypted_data[-32:]
                encrypted_data = encrypted_data[:-32]

                h.update(encrypted_data)
                try:
                    h.verify(stored_mac)
                except:
                    if self.logger:
                        self.logger.log("ERROR", f"MAC verification failed for {file_id}")
                    return None

                with open(temp_path, "wb") as f_out:
                    chunk_start = 0
                    while chunk_start < len(encrypted_data):
                        chunk = encrypted_data[chunk_start:chunk_start + CHUNK_SIZE]
                        decrypted_chunk = decryptor.update(chunk)
                        f_out.write(decrypted_chunk)
                        chunk_start += CHUNK_SIZE
                        if progress_callback:
                            progress_callback(chunk_start / len(encrypted_data))
                    f_out.write(decryptor.finalize())

                return temp_path
        except Exception as e:
            if self.logger:
                self.logger.log("ERROR", f"Decryption failed: {file_id}", str(e))
            return None

    def decrypt_file_to_bytes(self, file_id, progress_callback=None):
        try:
            enc_path = os.path.join(self.data_path, file_id + ".enc")
            if not os.path.exists(enc_path):
                return None

            key = self.master_key[:32]

            with open(enc_path, "rb") as f_in:
                nonce = f_in.read(12)
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce + b'\x00' * 4), backend=default_backend())
                decryptor = cipher.decryptor()

                h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                
                encrypted_data = f_in.read()
                stored_mac = encrypted_data[-32:]
                encrypted_data = encrypted_data[:-32]

                h.update(encrypted_data)
                try:
                    h.verify(stored_mac)
                except:
                    return None

                result = BytesIO()
                chunk_start = 0
                while chunk_start < len(encrypted_data):
                    chunk = encrypted_data[chunk_start:chunk_start + CHUNK_SIZE]
                    decrypted_chunk = decryptor.update(chunk)
                    result.write(decrypted_chunk)
                    chunk_start += CHUNK_SIZE
                    if progress_callback:
                        progress_callback(chunk_start / len(encrypted_data))
                result.write(decryptor.finalize())
                result.seek(0)
                return result.read()
        except Exception as e:
            if self.logger:
                self.logger.log("ERROR", f"Decryption to bytes failed: {file_id}", str(e))
            return None

    def delete_file(self, file_id, secure_delete=False):
        path = os.path.join(self.data_path, file_id + ".enc")
        if os.path.exists(path):
            if secure_delete:
                self.secure_shred(path)
            else:
                os.remove(path)
            if self.logger:
                self.logger.log("INFO", f"File deleted: {file_id}, secure={secure_delete}")

    def secure_shred(self, file_path, passes=3):
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(CHUNK_SIZE, remaining)
                        f.write(os.urandom(chunk_size))
                        remaining -= chunk_size
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)
            if self.logger:
                self.logger.log("INFO", f"File securely shredded: {file_path}")
        except Exception as e:
            if self.logger:
                self.logger.log("ERROR", f"Secure shred failed: {file_path}", str(e))
            if os.path.exists(file_path):
                os.remove(file_path)

    def _init_metadata(self):
        meta = {"root": {"id": "root", "name": "Root", "type": "folder", "children": []}}
        self.metadata_cache = meta
        self.save_metadata(meta)

    def load_metadata(self):
        if self.metadata_cache:
            return self.metadata_cache

        if not os.path.exists(self.meta_path):
            self._init_metadata()
            return self.metadata_cache

        with open(self.meta_path, "rb") as f:
            content = f.read()

        try:
            nonce = content[:12]
            ciphertext = content[12:]
            aesgcm = AESGCM(self.master_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.metadata_cache = json.loads(plaintext.decode('utf-8'))
            return self.metadata_cache
        except:
            self.metadata_cache = {"root": {"id": "root", "name": "Root", "type": "folder", "children": []}}
            return self.metadata_cache

    def save_metadata(self, meta):
        self.metadata_cache = meta
        data = json.dumps(meta).encode('utf-8')
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        with open(self.meta_path, "wb") as f:
            f.write(nonce + encrypted_data)

    def get_vault_stats(self):
        meta = self.load_metadata()
        stats = {
            "total_files": 0,
            "total_folders": 0,
            "total_size": 0,
            "categories": defaultdict(lambda: {"count": 0, "size": 0}),
            "last_modified": None
        }

        def traverse(node):
            if node["type"] == "folder":
                stats["total_folders"] += 1
                for child in node.get("children", []):
                    traverse(child)
            else:
                stats["total_files"] += 1
                size = node.get("size", 0)
                stats["total_size"] += size
                category = get_file_category(node["name"])
                stats["categories"][category]["count"] += 1
                stats["categories"][category]["size"] += size
                mod_time = node.get("modified")
                if mod_time:
                    if not stats["last_modified"] or mod_time > stats["last_modified"]:
                        stats["last_modified"] = mod_time

        traverse(meta["root"])
        return stats

class PasswordStrengthChecker:
    @staticmethod
    def check(password):
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("At least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        if len(password) >= 16:
            score += 1
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        common = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
        if password.lower() in common:
            score = 0
            feedback = ["Password is too common"]
        
        if score <= 2:
            strength = "Weak"
            color = "#e74c3c"
        elif score <= 4:
            strength = "Fair"
            color = "#f39c12"
        elif score <= 6:
            strength = "Good"
            color = "#3498db"
        else:
            strength = "Strong"
            color = "#27ae60"
        
        return strength, color, score / 7, feedback

class ClipboardManager:
    def __init__(self, root):
        self.root = root
        self.clear_timer = None

    def copy_and_clear(self, text, delay=30000):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        
        if self.clear_timer:
            self.root.after_cancel(self.clear_timer)
        
        self.clear_timer = self.root.after(delay, self._clear_clipboard)

    def _clear_clipboard(self):
        try:
            self.root.clipboard_clear()
        except:
            pass

class Localization:
    LANGUAGES = {
        "English": {
            "welcome": "Welcome", "password": "Password", "login": "Login", "setup": "Initial Setup",
            "create_pw": "Create Password", "confirm_pw": "Confirm Password", "use_pw": "Enable Password Protection",
            "security_warn": "Warning: Without a password, anyone with access to this computer can open your vault.",
            "match_err": "Passwords do not match", "setup_done": "Setup Complete", "error": "Error",
            "upload": "Upload", "new_folder": "New Folder", "settings": "Settings", "back": "Back",
            "items": "items", "delete": "Delete", "move": "Move", "rename": "Rename", "logout": "Logout",
            "change_pw": "Change Password", "theme": "Theme", "language": "Language", "apply": "Apply",
            "save": "Save", "delete_confirm": "Are you sure you want to delete this?", "yes": "Yes", "no": "No",
            "current_pw": "Current Password", "new_pw": "New Password", "pw_req": "Password Required",
            "decryption_err": "Decryption Failed", "vault_location": "Vault Location", "browse": "Browse",
            "diagnostics": "Diagnostics", "debug_mode": "Debug Mode", "clear_logs": "Clear Logs",
            "analytics": "Analytics", "total_files": "Total Files", "total_size": "Total Size",
            "file_types": "File Types", "last_modified": "Last Modified", "search": "Search...",
            "select_all": "Select All", "deselect": "Deselect All", "batch_delete": "Delete Selected",
            "batch_move": "Move Selected", "shred": "Secure Shred", "preview": "Preview",
            "strength": "Password Strength", "weak": "Weak", "fair": "Fair", "good": "Good", "strong": "Strong",
            "locked_msg": "Vault locked due to too many attempts", "remaining": "Time remaining",
            "vault_stats": "Vault Statistics", "security_settings": "Security Settings",
            "appearance": "Appearance", "files": "Files", "folders": "Folders", "export": "Export",
            "import": "Import", "about": "About"
        },
        "German": {
            "welcome": "Willkommen", "password": "Passwort", "login": "Anmelden", "setup": "Einrichtung",
            "create_pw": "Passwort erstellen", "confirm_pw": "Bestätigen", "use_pw": "Passwortschutz aktivieren",
            "security_warn": "Warnung: Ohne Passwort kann jeder auf diesen Tresor zugreifen.",
            "match_err": "Passwörter stimmen nicht überein", "setup_done": "Fertig", "error": "Fehler",
            "upload": "Hochladen", "new_folder": "Neuer Ordner", "settings": "Einstellungen", "back": "Zurück",
            "items": "Elemente", "delete": "Löschen", "move": "Verschieben", "rename": "Umbenennen",
            "logout": "Abmelden", "change_pw": "Passwort ändern", "theme": "Thema", "language": "Sprache",
            "apply": "Anwenden", "save": "Speichern", "delete_confirm": "Wirklich löschen?", "yes": "Ja",
            "no": "Nein", "current_pw": "Aktuelles Passwort", "new_pw": "Neues Passwort",
            "pw_req": "Passwort erforderlich", "decryption_err": "Entschlüsselung fehlgeschlagen",
            "vault_location": "Tresor-Speicherort", "browse": "Durchsuchen", "diagnostics": "Diagnose",
            "debug_mode": "Debug-Modus", "clear_logs": "Protokolle löschen", "analytics": "Analytik",
            "total_files": "Dateien gesamt", "total_size": "Gesamtgröße", "file_types": "Dateitypen",
            "last_modified": "Zuletzt geändert", "search": "Suchen...", "select_all": "Alle auswählen",
            "deselect": "Auswahl aufheben", "batch_delete": "Ausgewählte löschen",
            "batch_move": "Ausgewählte verschieben", "shred": "Sicher löschen", "preview": "Vorschau",
            "strength": "Passwortstärke", "weak": "Schwach", "fair": "Mittel", "good": "Gut", "strong": "Stark",
            "locked_msg": "Tresor wegen zu vieler Versuche gesperrt", "remaining": "Verbleibende Zeit",
            "vault_stats": "Tresor-Statistiken", "security_settings": "Sicherheitseinstellungen",
            "appearance": "Aussehen", "files": "Dateien", "folders": "Ordner", "export": "Exportieren",
            "import": "Importieren", "about": "Über"
        },
        "Spanish": {
            "welcome": "Bienvenido", "password": "Contraseña", "login": "Entrar", "setup": "Configuración",
            "create_pw": "Crear Contraseña", "confirm_pw": "Confirmar", "use_pw": "Usar contraseña",
            "security_warn": "Advertencia: Sin contraseña es menos seguro.", "match_err": "No coinciden",
            "setup_done": "Listo", "error": "Error", "upload": "Subir", "new_folder": "Nueva Carpeta",
            "settings": "Ajustes", "back": "Atrás", "items": "elementos", "delete": "Borrar",
            "move": "Mover", "rename": "Renombrar", "logout": "Salir", "change_pw": "Cambiar Contraseña",
            "theme": "Tema", "language": "Idioma", "apply": "Aplicar", "save": "Guardar",
            "delete_confirm": "¿Seguro?", "yes": "Sí", "no": "No", "current_pw": "Contraseña actual",
            "new_pw": "Nueva contraseña", "pw_req": "Contraseña requerida",
            "decryption_err": "Error de descifrado", "vault_location": "Ubicación de la bóveda",
            "browse": "Explorar", "diagnostics": "Diagnósticos", "debug_mode": "Modo depuración",
            "clear_logs": "Borrar registros", "analytics": "Analítica", "total_files": "Total archivos",
            "total_size": "Tamaño total", "file_types": "Tipos de archivo", "last_modified": "Última modificación",
            "search": "Buscar...", "select_all": "Seleccionar todo", "deselect": "Deseleccionar",
            "batch_delete": "Eliminar seleccionados", "batch_move": "Mover seleccionados",
            "shred": "Destruir seguro", "preview": "Vista previa", "strength": "Fortaleza de contraseña",
            "weak": "Débil", "fair": "Regular", "good": "Buena", "strong": "Fuerte",
            "locked_msg": "Bóveda bloqueada por demasiados intentos", "remaining": "Tiempo restante",
            "vault_stats": "Estadísticas", "security_settings": "Seguridad", "appearance": "Apariencia",
            "files": "Archivos", "folders": "Carpetas", "export": "Exportar", "import": "Importar", "about": "Acerca de"
        },
        "French": {
            "welcome": "Bienvenue", "password": "Mot de passe", "login": "Connexion", "setup": "Installation",
            "create_pw": "Créer mot de passe", "confirm_pw": "Confirmer", "use_pw": "Activer protection",
            "security_warn": "Attention: Moins sécurisé sans mot de passe.", "match_err": "Les mots de passe ne correspondent pas",
            "setup_done": "Terminé", "error": "Erreur", "upload": "Téléverser", "new_folder": "Nouveau dossier",
            "settings": "Paramètres", "back": "Retour", "items": "articles", "delete": "Supprimer",
            "move": "Déplacer", "rename": "Renommer", "logout": "Déconnexion", "change_pw": "Changer mot de passe",
            "theme": "Thème", "language": "Langue", "apply": "Appliquer", "save": "Sauvegarder",
            "delete_confirm": "Êtes-vous sûr?", "yes": "Oui", "no": "Non", "current_pw": "Mot de passe actuel",
            "new_pw": "Nouveau mot de passe", "pw_req": "Mot de passe requis",
            "decryption_err": "Échec du déchiffrement", "vault_location": "Emplacement du coffre",
            "browse": "Parcourir", "diagnostics": "Diagnostics", "debug_mode": "Mode débogage",
            "clear_logs": "Effacer les journaux", "analytics": "Analytique", "total_files": "Total fichiers",
            "total_size": "Taille totale", "file_types": "Types de fichiers", "last_modified": "Dernière modification",
            "search": "Rechercher...", "select_all": "Tout sélectionner", "deselect": "Désélectionner",
            "batch_delete": "Supprimer sélection", "batch_move": "Déplacer sélection",
            "shred": "Destruction sécurisée", "preview": "Aperçu", "strength": "Force du mot de passe",
            "weak": "Faible", "fair": "Moyen", "good": "Bon", "strong": "Fort",
            "locked_msg": "Coffre verrouillé pour trop de tentatives", "remaining": "Temps restant",
            "vault_stats": "Statistiques", "security_settings": "Sécurité", "appearance": "Apparence",
            "files": "Fichiers", "folders": "Dossiers", "export": "Exporter", "import": "Importer", "about": "À propos"
        }
    }

    for lang in ["Italian", "Portuguese", "Russian", "Japanese", "Chinese", "Korean", "Dutch", "Polish", "Swedish", "Turkish", "Arabic", "Hindi"]:
        LANGUAGES[lang] = LANGUAGES["English"].copy()

    @staticmethod
    def get(lang, key):
        return Localization.LANGUAGES.get(lang, Localization.LANGUAGES["English"]).get(key, key)

class WallpaperGenerator:
    @staticmethod
    def create_gradient(width, height, colors):
        img = Image.new('RGB', (width, height))
        for y in range(height):
            ratio = y / height
            r = int(colors[0][0] * (1 - ratio) + colors[1][0] * ratio)
            g = int(colors[0][1] * (1 - ratio) + colors[1][1] * ratio)
            b = int(colors[0][2] * (1 - ratio) + colors[1][2] * ratio)
            for x in range(width):
                img.putpixel((x, y), (r, g, b))
        return img

    @staticmethod
    def get_wallpaper(theme_name, width, height):
        wallpapers = {
            "rainforest": [(10, 50, 25), (20, 80, 40)],
            "ocean": [(10, 30, 60), (20, 60, 100)],
            "sunset": [(60, 30, 50), (100, 50, 30)],
            "midnight": [(10, 10, 30), (20, 20, 60)],
            "arctic": [(200, 220, 240), (230, 240, 250)],
            "volcano": [(40, 15, 10), (80, 25, 15)],
            "cyber": [(10, 15, 25), (15, 25, 40)],
            "sakura": [(50, 30, 45), (80, 50, 70)],
            "desert": [(60, 50, 35), (100, 85, 60)]
        }
        colors = wallpapers.get(theme_name, [(30, 30, 30), (50, 50, 50)])
        return WallpaperGenerator.create_gradient(width, height, colors)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Vanquish's Vault")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        default_path = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'VanquishVault')
        
        self.logger = ErrorLogger(default_path, enabled=False)
        self.security = SecurityManager(default_path, self.logger)
        self.current_lang = self.security.config.get("language", "English")
        self.current_theme = self.security.config.get("theme", "Classic Dark")
        self.clipboard_manager = ClipboardManager(self)
        
        self.logger.enabled = self.security.config.get("debug_mode", False)
        
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        self.current_frame = None
        self.temp_dir = os.path.join(self.security.base_path, "temp_view")
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)
        
        self.wallpaper_label = None
        self.apply_theme(self.current_theme)

        if not self.security.is_setup():
            self.show_frame(SetupFrame)
        else:
            self.show_frame(LoginFrame)

    def apply_theme(self, theme_name):
        theme = THEMES.get(theme_name, THEMES["Classic Dark"])
        self.current_theme = theme_name
        self.configure(fg_color=theme["bg"])
        
        if theme.get("wallpaper"):
            self.update_idletasks()
            width = self.winfo_width() or 1200
            height = self.winfo_height() or 800
            img = WallpaperGenerator.get_wallpaper(theme["wallpaper"], width, height)
            self.wallpaper_image = ImageTk.PhotoImage(img)
            
            if self.wallpaper_label:
                self.wallpaper_label.destroy()
            self.wallpaper_label = tk.Label(self, image=self.wallpaper_image)
            self.wallpaper_label.place(x=0, y=0, relwidth=1, relheight=1)
            self.wallpaper_label.lower()
        else:
            if self.wallpaper_label:
                self.wallpaper_label.destroy()
                self.wallpaper_label = None

    def show_frame(self, frame_class, **kwargs):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.container, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def tr(self, key):
        return Localization.get(self.current_lang, key)

    def get_theme_colors(self):
        return THEMES.get(self.current_theme, THEMES["Classic Dark"])

    def on_close(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.destroy()

class SetupFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        theme = controller.get_theme_colors()
        super().__init__(parent, fg_color=theme["bg"])
        self.controller = controller
        self.use_password = tk.BooleanVar(value=True)

        center_frame = ctk.CTkFrame(self, fg_color=theme["card"], corner_radius=20)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center_frame, text=f"{ICONS['shield']} Vanquish's Vault", 
                     font=("Segoe UI", 32, "bold"), text_color=theme["text"]).pack(pady=(40, 10))
        ctk.CTkLabel(center_frame, text=self.controller.tr("setup"), 
                     font=("Segoe UI", 18), text_color=theme["highlight"]).pack(pady=(0, 30))

        self.pw_entry = ctk.CTkEntry(center_frame, placeholder_text=self.controller.tr("create_pw"), 
                                      show="*", width=350, height=45, font=("Segoe UI", 14))
        self.pw_entry.pack(pady=10, padx=40)
        self.pw_entry.bind("<KeyRelease>", self.check_strength)

        self.strength_frame = ctk.CTkFrame(center_frame, fg_color="transparent")
        self.strength_frame.pack(pady=5, padx=40, fill="x")
        
        self.strength_bar = ctk.CTkProgressBar(self.strength_frame, width=250, height=8)
        self.strength_bar.pack(side="left", padx=(0, 10))
        self.strength_bar.set(0)
        
        self.strength_label = ctk.CTkLabel(self.strength_frame, text="", font=("Segoe UI", 12))
        self.strength_label.pack(side="left")

        self.pw_confirm = ctk.CTkEntry(center_frame, placeholder_text=self.controller.tr("confirm_pw"), 
                                        show="*", width=350, height=45, font=("Segoe UI", 14))
        self.pw_confirm.pack(pady=10, padx=40)

        self.check = ctk.CTkCheckBox(center_frame, text=self.controller.tr("use_pw"), 
                                      variable=self.use_password, command=self.toggle_pw,
                                      font=("Segoe UI", 14))
        self.check.pack(pady=15)
        self.check.select()

        self.warn_label = ctk.CTkLabel(center_frame, text="", text_color="#f39c12", 
                                        font=("Segoe UI", 12), wraplength=300)
        self.warn_label.pack(pady=5)

        ctk.CTkButton(center_frame, text=f"{ICONS['secure']} {self.controller.tr('save')}", 
                      command=self.finish_setup, width=200, height=45, font=("Segoe UI", 14, "bold"),
                      fg_color=theme["accent"], hover_color=theme["highlight"]).pack(pady=(20, 40))

    def check_strength(self, event=None):
        password = self.pw_entry.get()
        if password:
            strength, color, progress, feedback = PasswordStrengthChecker.check(password)
            self.strength_bar.set(progress)
            self.strength_label.configure(text=strength, text_color=color)
        else:
            self.strength_bar.set(0)
            self.strength_label.configure(text="")

    def toggle_pw(self):
        if not self.use_password.get():
            self.warn_label.configure(text=self.controller.tr("security_warn"))
            self.pw_entry.configure(state="disabled")
            self.pw_confirm.configure(state="disabled")
        else:
            self.warn_label.configure(text="")
            self.pw_entry.configure(state="normal")
            self.pw_confirm.configure(state="normal")

    def finish_setup(self):
        p1 = self.pw_entry.get()
        p2 = self.pw_confirm.get()

        if self.use_password.get():
            if not p1:
                self.warn_label.configure(text="Please enter a password", text_color="#e74c3c")
                return
            if p1 != p2:
                self.warn_label.configure(text=self.controller.tr("match_err"), text_color="#e74c3c")
                return

        self.controller.security.setup_vault(p1, self.use_password.get())
        self.controller.show_frame(MainVaultFrame)

class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        theme = controller.get_theme_colors()
        super().__init__(parent, fg_color=theme["bg"])
        self.controller = controller

        if not controller.security.config.get("use_password", True):
            controller.security.unlock_vault("")
            controller.show_frame(MainVaultFrame)
            return

        center_frame = ctk.CTkFrame(self, fg_color=theme["card"], corner_radius=20)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center_frame, text=f"{ICONS['lock']} Vanquish's Vault", 
                     font=("Segoe UI", 32, "bold"), text_color=theme["text"]).pack(pady=(40, 30))

        self.pw_entry = ctk.CTkEntry(center_frame, placeholder_text=self.controller.tr("password"), 
                                      show="*", width=350, height=45, font=("Segoe UI", 14))
        self.pw_entry.pack(pady=10, padx=40)
        self.pw_entry.bind("<Return>", lambda e: self.login())
        self.pw_entry.focus()

        self.login_btn = ctk.CTkButton(center_frame, text=f"{ICONS['unlock']} {self.controller.tr('login')}", 
                                        command=self.login, width=200, height=45, font=("Segoe UI", 14, "bold"),
                                        fg_color=theme["accent"], hover_color=theme["highlight"])
        self.login_btn.pack(pady=20)

        self.msg_label = ctk.CTkLabel(center_frame, text="", text_color="#e74c3c", 
                                       font=("Segoe UI", 12), wraplength=300)
        self.msg_label.pack(pady=(0, 40))

        self.lockout_label = ctk.CTkLabel(center_frame, text="", text_color="#f39c12", 
                                           font=("Segoe UI", 12))
        self.lockout_label.pack(pady=(0, 20))

    def login(self):
        pw = self.pw_entry.get()
        success, msg, remaining = self.controller.security.unlock_vault(pw)
        if success:
            self.controller.show_frame(MainVaultFrame)
        else:
            if msg == "LOCKED":
                self.msg_label.configure(text=self.controller.tr("locked_msg"))
                self.update_lockout_timer(remaining)
            else:
                attempts_left = 3 - self.controller.security.failed_attempts
                if attempts_left > 0:
                    self.msg_label.configure(text=f"Invalid Password ({attempts_left} attempts remaining)")
                else:
                    self.msg_label.configure(text="Invalid Password")

    def update_lockout_timer(self, remaining):
        if remaining > 0:
            mins, secs = divmod(remaining, 60)
            self.lockout_label.configure(text=f"{self.controller.tr('remaining')}: {mins:02d}:{secs:02d}")
            self.after(1000, lambda: self.update_lockout_timer(remaining - 1))
        else:
            self.lockout_label.configure(text="")
            self.msg_label.configure(text="")

class MainVaultFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        self.theme = controller.get_theme_colors()
        super().__init__(parent, fg_color="transparent")
        self.controller = controller
        self.metadata = self.controller.security.load_metadata()
        self.current_folder_id = "root"
        self.path_history = []
        self.forward_history = []
        self.selected_items = set()
        self.clipboard = []
        self.clipboard_mode = None
        self.search_query = ""
        self.current_tab = "files"

        self.create_sidebar()
        self.create_main_area()
        self.refresh_view()

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, fg_color=self.theme["card"], corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=0, pady=0)
        self.sidebar.pack_propagate(False)

        header = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=20)
        
        ctk.CTkLabel(header, text=f"{ICONS['shield']} Vanquish's Vault", 
                     font=("Segoe UI", 16, "bold"), text_color=self.theme["text"]).pack(anchor="w")

        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="x", padx=10, pady=10)

        self.nav_buttons = {}
        nav_items = [
            ("files", f"{ICONS['folder']} Files", self.show_files),
            ("analytics", f"{ICONS['chart']} Analytics", self.show_analytics),
            ("settings", f"{ICONS['settings']} Settings", self.show_settings),
            ("diagnostics", f"{ICONS['diagnostics']} Diagnostics", self.show_diagnostics),
        ]

        for key, text, command in nav_items:
            btn = ctk.CTkButton(nav_frame, text=text, command=command, anchor="w",
                               fg_color="transparent", text_color=self.theme["text"],
                               hover_color=self.theme["fg"], height=40, font=("Segoe UI", 13))
            btn.pack(fill="x", pady=2)
            self.nav_buttons[key] = btn

        self.nav_buttons["files"].configure(fg_color=self.theme["accent"])

        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        logout_btn = ctk.CTkButton(self.sidebar, text=f"{ICONS['lock']} {self.controller.tr('logout')}", 
                                   command=self.logout, fg_color="#c0392b", hover_color="#e74c3c",
                                   height=40, font=("Segoe UI", 13))
        logout_btn.pack(fill="x", padx=10, pady=20)

    def create_main_area(self):
        self.main_area = ctk.CTkFrame(self, fg_color=self.theme["bg"])
        self.main_area.pack(side="right", fill="both", expand=True)

        self.content_frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)

    def switch_nav(self, active_key):
        for key, btn in self.nav_buttons.items():
            if key == active_key:
                btn.configure(fg_color=self.theme["accent"])
            else:
                btn.configure(fg_color="transparent")

    def show_files(self):
        self.current_tab = "files"
        self.switch_nav("files")
        self.refresh_view()

    def show_analytics(self):
        self.current_tab = "analytics"
        self.switch_nav("analytics")
        self.show_analytics_view()

    def show_settings(self):
        self.current_tab = "settings"
        self.switch_nav("settings")
        self.show_settings_view()

    def show_diagnostics(self):
        self.current_tab = "diagnostics"
        self.switch_nav("diagnostics")
        self.show_diagnostics_view()

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def refresh_view(self):
        self.clear_content()
        
        toolbar = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=60, corner_radius=0)
        toolbar.pack(fill="x", padx=0, pady=0)
        toolbar.pack_propagate(False)

        nav_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        nav_frame.pack(side="left", padx=10, pady=10)

        ctk.CTkButton(nav_frame, text=ICONS["back"], width=35, height=35, 
                      command=self.go_back, fg_color=self.theme["fg"],
                      hover_color=self.theme["accent"]).pack(side="left", padx=2)
        ctk.CTkButton(nav_frame, text=ICONS["forward"], width=35, height=35,
                      command=self.go_forward, fg_color=self.theme["fg"],
                      hover_color=self.theme["accent"]).pack(side="left", padx=2)
        ctk.CTkButton(nav_frame, text=ICONS["home"], width=35, height=35,
                      command=self.go_home, fg_color=self.theme["fg"],
                      hover_color=self.theme["accent"]).pack(side="left", padx=2)
        ctk.CTkButton(nav_frame, text=ICONS["refresh"], width=35, height=35,
                      command=self.refresh_view, fg_color=self.theme["fg"],
                      hover_color=self.theme["accent"]).pack(side="left", padx=2)

        path_frame = ctk.CTkFrame(toolbar, fg_color=self.theme["fg"], corner_radius=5)
        path_frame.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        
        self.path_label = ctk.CTkLabel(path_frame, text=self.get_current_path(), 
                                        font=("Segoe UI", 12), text_color=self.theme["text"])
        self.path_label.pack(side="left", padx=10, pady=5)

        search_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        search_frame.pack(side="right", padx=10, pady=10)

        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text=self.controller.tr("search"),
                                          width=200, height=35, font=("Segoe UI", 12))
        self.search_entry.pack(side="left", padx=5)
        self.search_entry.bind("<KeyRelease>", self.on_search)
        
        ctk.CTkButton(search_frame, text=ICONS["search"], width=35, height=35,
                      command=self.perform_search, fg_color=self.theme["accent"]).pack(side="left")

        action_bar = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=50, corner_radius=0)
        action_bar.pack(fill="x", padx=0, pady=0)
        action_bar.pack_propagate(False)

        left_actions = ctk.CTkFrame(action_bar, fg_color="transparent")
        left_actions.pack(side="left", padx=10, pady=8)

        ctk.CTkButton(left_actions, text=f"{ICONS['upload']} {self.controller.tr('upload')}", 
                      command=self.upload_files, height=35, fg_color=self.theme["accent"],
                      hover_color=self.theme["highlight"], font=("Segoe UI", 12)).pack(side="left", padx=3)
        ctk.CTkButton(left_actions, text=f"{ICONS['folder']} {self.controller.tr('new_folder')}", 
                      command=self.create_folder, height=35, fg_color=self.theme["fg"],
                      hover_color=self.theme["accent"], font=("Segoe UI", 12)).pack(side="left", padx=3)

        right_actions = ctk.CTkFrame(action_bar, fg_color="transparent")
        right_actions.pack(side="right", padx=10, pady=8)

        self.select_all_btn = ctk.CTkButton(right_actions, text=self.controller.tr("select_all"), 
                                            command=self.select_all, height=35, fg_color=self.theme["fg"],
                                            hover_color=self.theme["accent"], font=("Segoe UI", 12))
        self.select_all_btn.pack(side="left", padx=3)

        if self.selected_items:
            ctk.CTkButton(right_actions, text=f"{ICONS['delete']} Delete ({len(self.selected_items)})", 
                          command=self.batch_delete, height=35, fg_color="#c0392b",
                          hover_color="#e74c3c", font=("Segoe UI", 12)).pack(side="left", padx=3)
            ctk.CTkButton(right_actions, text=f"{ICONS['move']} Move", 
                          command=self.batch_move, height=35, fg_color=self.theme["fg"],
                          hover_color=self.theme["accent"], font=("Segoe UI", 12)).pack(side="left", padx=3)

        if self.clipboard:
            ctk.CTkButton(right_actions, text=f"{ICONS['paste']} Paste ({len(self.clipboard)})", 
                          command=self.paste_items, height=35, fg_color="#27ae60",
                          hover_color="#2ecc71", font=("Segoe UI", 12)).pack(side="left", padx=3)

        self.file_list = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        self.file_list.pack(fill="both", expand=True, padx=10, pady=10)

        folder = self.get_node(self.current_folder_id)
        if not folder:
            return

        items = folder.get("children", [])
        
        if self.search_query:
            items = self.search_items(items, self.search_query)

        folders = [i for i in items if i["type"] == "folder"]
        files = [i for i in items if i["type"] == "file"]
        
        for item in folders + files:
            self.create_item_widget(item)

        self.status_bar = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=30, corner_radius=0)
        self.status_bar.pack(fill="x", padx=0, pady=0)
        
        folder_count = len(folders)
        file_count = len(files)
        ctk.CTkLabel(self.status_bar, text=f"{folder_count} {self.controller.tr('folders')}, {file_count} {self.controller.tr('files')}", 
                     font=("Segoe UI", 11), text_color=self.theme["text"]).pack(side="left", padx=10, pady=5)

    def create_item_widget(self, item):
        is_selected = item["id"] in self.selected_items
        card_color = self.theme["accent"] if is_selected else self.theme["card"]
        
        card = ctk.CTkFrame(self.file_list, fg_color=card_color, corner_radius=8, height=50)
        card.pack(fill="x", pady=3, padx=5)
        card.pack_propagate(False)

        check_var = tk.BooleanVar(value=is_selected)
        check = ctk.CTkCheckBox(card, text="", variable=check_var, width=20,
                                command=lambda i=item, v=check_var: self.toggle_selection(i, v))
        check.pack(side="left", padx=10)

        if item["type"] == "folder":
            icon = ICONS["folder"]
        else:
            icon = get_file_icon(item["name"])

        icon_label = ctk.CTkLabel(card, text=icon, font=("Segoe UI", 20), width=40)
        icon_label.pack(side="left", padx=5)

        name_label = ctk.CTkLabel(card, text=item["name"], font=("Segoe UI", 13), 
                                   text_color=self.theme["text"], anchor="w")
        name_label.pack(side="left", padx=10, fill="x", expand=True)
        
        if item["type"] == "folder":
            name_label.bind("<Double-Button-1>", lambda e, i=item: self.enter_folder(i))
            card.bind("<Double-Button-1>", lambda e, i=item: self.enter_folder(i))
        else:
            name_label.bind("<Double-Button-1>", lambda e, i=item: self.open_file(i))
            card.bind("<Double-Button-1>", lambda e, i=item: self.open_file(i))

        if item["type"] == "file":
            size_str = self.format_size(item.get("size", 0))
            ctk.CTkLabel(card, text=size_str, font=("Segoe UI", 11), 
                         text_color=self.theme["highlight"], width=80).pack(side="left", padx=5)

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)

        if item["type"] == "folder":
            ctk.CTkButton(btn_frame, text="Open", width=50, height=30, font=("Segoe UI", 11),
                          command=lambda i=item: self.enter_folder(i),
                          fg_color=self.theme["fg"], hover_color=self.theme["accent"]).pack(side="left", padx=2)
        else:
            ctk.CTkButton(btn_frame, text=ICONS["preview"], width=35, height=30,
                          command=lambda i=item: self.preview_file(i),
                          fg_color=self.theme["fg"], hover_color=self.theme["accent"]).pack(side="left", padx=2)
            ctk.CTkButton(btn_frame, text=ICONS["download"], width=35, height=30,
                          command=lambda i=item: self.export_file(i),
                          fg_color=self.theme["fg"], hover_color=self.theme["accent"]).pack(side="left", padx=2)

        ctk.CTkButton(btn_frame, text=ICONS["rename"], width=35, height=30,
                      command=lambda i=item: self.rename_item(i),
                      fg_color=self.theme["fg"], hover_color=self.theme["accent"]).pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text=ICONS["delete"], width=35, height=30,
                      command=lambda i=item: self.delete_item(i),
                      fg_color="#c0392b", hover_color="#e74c3c").pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text=ICONS["shred"], width=35, height=30,
                      command=lambda i=item: self.shred_item(i),
                      fg_color="#d35400", hover_color="#e67e22").pack(side="left", padx=2)

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def get_current_path(self):
        path_parts = []
        node_id = self.current_folder_id
        while node_id:
            node = self.get_node(node_id)
            if node:
                path_parts.insert(0, node["name"])
                parent = self.get_parent(node_id)
                node_id = parent["id"] if parent else None
            else:
                break
        return "/" + "/".join(path_parts) if path_parts else "/"

    def get_node(self, node_id, current_node=None):
        if current_node is None:
            current_node = self.metadata["root"]
        if current_node["id"] == node_id:
            return current_node
        if current_node["type"] == "folder":
            for child in current_node.get("children", []):
                res = self.get_node(node_id, child)
                if res:
                    return res
        return None

    def get_parent(self, node_id, current_node=None):
        if current_node is None:
            current_node = self.metadata["root"]
        if current_node["type"] == "folder":
            for child in current_node.get("children", []):
                if child["id"] == node_id:
                    return current_node
                res = self.get_parent(node_id, child)
                if res:
                    return res
        return None

    def save_meta(self):
        self.controller.security.save_metadata(self.metadata)

    def toggle_selection(self, item, var):
        if var.get():
            self.selected_items.add(item["id"])
        else:
            self.selected_items.discard(item["id"])
        self.refresh_view()

    def select_all(self):
        folder = self.get_node(self.current_folder_id)
        if folder:
            for item in folder.get("children", []):
                self.selected_items.add(item["id"])
        self.refresh_view()

    def deselect_all(self):
        self.selected_items.clear()
        self.refresh_view()

    def on_search(self, event):
        self.search_query = self.search_entry.get()
        self.refresh_view()

    def perform_search(self):
        self.search_query = self.search_entry.get()
        self.refresh_view()

    def search_items(self, items, query):
        query = query.lower()
        results = []
        for item in items:
            if query in item["name"].lower():
                results.append(item)
        return results

    def enter_folder(self, item):
        self.path_history.append(self.current_folder_id)
        self.forward_history.clear()
        self.current_folder_id = item["id"]
        self.selected_items.clear()
        self.search_query = ""
        self.refresh_view()

    def go_back(self):
        if self.path_history:
            self.forward_history.append(self.current_folder_id)
            self.current_folder_id = self.path_history.pop()
            self.selected_items.clear()
            self.refresh_view()

    def go_forward(self):
        if self.forward_history:
            self.path_history.append(self.current_folder_id)
            self.current_folder_id = self.forward_history.pop()
            self.selected_items.clear()
            self.refresh_view()

    def go_home(self):
        if self.current_folder_id != "root":
            self.path_history.append(self.current_folder_id)
            self.forward_history.clear()
        self.current_folder_id = "root"
        self.selected_items.clear()
        self.refresh_view()

    def upload_files(self):
        paths = filedialog.askopenfilenames()
        if not paths:
            return
        
        self.show_progress_dialog("Encrypting files...", len(paths))
        
        def do_upload():
            folder = self.get_node(self.current_folder_id)
            for idx, p in enumerate(paths):
                def progress_cb(prog):
                    self.update_progress(idx + prog, len(paths))
                
                meta = self.controller.security.encrypt_file(p, self.current_folder_id, progress_cb)
                if meta:
                    base_name = meta["name"]
                    cnt = 1
                    while any(c["name"] == meta["name"] for c in folder.get("children", [])):
                        name, ext = os.path.splitext(base_name)
                        meta["name"] = f"{name}_{cnt}{ext}"
                        cnt += 1
                    folder["children"].append(meta)
            
            self.save_meta()
            self.after(0, self.close_progress_dialog)
            self.after(0, self.refresh_view)
        
        threading.Thread(target=do_upload, daemon=True).start()

    def show_progress_dialog(self, title, total):
        self.progress_window = ctk.CTkToplevel(self)
        self.progress_window.title(title)
        self.progress_window.geometry("400x150")
        self.progress_window.transient(self)
        self.progress_window.grab_set()
        
        ctk.CTkLabel(self.progress_window, text=title, font=("Segoe UI", 14)).pack(pady=20)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_window, width=350)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(self.progress_window, text="0%", font=("Segoe UI", 12))
        self.progress_label.pack(pady=10)

    def update_progress(self, current, total):
        progress = current / total if total > 0 else 0
        self.progress_bar.set(progress)
        self.progress_label.configure(text=f"{int(progress * 100)}%")
        self.progress_window.update()

    def close_progress_dialog(self):
        if hasattr(self, 'progress_window') and self.progress_window:
            self.progress_window.destroy()

    def create_folder(self):
        dialog = ctk.CTkInputDialog(text="Folder name:", title=self.controller.tr("new_folder"))
        name = dialog.get_input()
        if name:
            new_folder = {
                "id": secrets.token_hex(8),
                "name": name,
                "type": "folder",
                "children": [],
                "created": datetime.datetime.now().isoformat()
            }
            self.get_node(self.current_folder_id)["children"].append(new_folder)
            self.save_meta()
            self.refresh_view()

    def delete_item(self, item):
        if not messagebox.askyesno("Confirm", self.controller.tr("delete_confirm")):
            return
        
        parent = self.get_parent(item["id"])
        if not parent:
            return

        def recursive_delete(node, secure=False):
            if node["type"] == "file":
                self.controller.security.delete_file(node["id"], secure)
            else:
                for child in node.get("children", []):
                    recursive_delete(child, secure)

        recursive_delete(item)
        parent["children"] = [c for c in parent["children"] if c["id"] != item["id"]]
        self.selected_items.discard(item["id"])
        self.save_meta()
        self.refresh_view()

    def shred_item(self, item):
        if not messagebox.askyesno("Secure Shred", "This will permanently destroy the file with multiple overwrite passes. Continue?"):
            return
        
        parent = self.get_parent(item["id"])
        if not parent:
            return

        def recursive_delete(node):
            if node["type"] == "file":
                self.controller.security.delete_file(node["id"], secure_delete=True)
            else:
                for child in node.get("children", []):
                    recursive_delete(child)

        recursive_delete(item)
        parent["children"] = [c for c in parent["children"] if c["id"] != item["id"]]
        self.selected_items.discard(item["id"])
        self.save_meta()
        self.refresh_view()

    def batch_delete(self):
        if not self.selected_items:
            return
        if not messagebox.askyesno("Confirm", f"Delete {len(self.selected_items)} items?"):
            return
        
        for item_id in list(self.selected_items):
            item = self.get_node(item_id)
            if item:
                parent = self.get_parent(item_id)
                if parent:
                    def recursive_delete(node):
                        if node["type"] == "file":
                            self.controller.security.delete_file(node["id"])
                        else:
                            for child in node.get("children", []):
                                recursive_delete(child)
                    recursive_delete(item)
                    parent["children"] = [c for c in parent["children"] if c["id"] != item_id]
        
        self.selected_items.clear()
        self.save_meta()
        self.refresh_view()

    def batch_move(self):
        if not self.selected_items:
            return
        self.clipboard = list(self.selected_items)
        self.clipboard_mode = "move"
        self.selected_items.clear()
        self.refresh_view()

    def paste_items(self):
        if not self.clipboard:
            return
        
        for item_id in self.clipboard:
            item = self.get_node(item_id)
            if item:
                old_parent = self.get_parent(item_id)
                new_parent = self.get_node(self.current_folder_id)
                
                if old_parent and new_parent and old_parent["id"] != new_parent["id"]:
                    old_parent["children"] = [c for c in old_parent["children"] if c["id"] != item_id]
                    new_parent["children"].append(item)
        
        self.clipboard = []
        self.clipboard_mode = None
        self.save_meta()
        self.refresh_view()

    def rename_item(self, item):
        dialog = ctk.CTkInputDialog(text="New name:", title=self.controller.tr("rename"))
        name = dialog.get_input()
        if name:
            item["name"] = name
            item["modified"] = datetime.datetime.now().isoformat()
            self.save_meta()
            self.refresh_view()

    def open_file(self, item):
        def do_open():
            path = self.controller.security.decrypt_file_to_temp(item["id"], self.controller.temp_dir)
            if path:
                ext = os.path.splitext(item["name"])[1].lower()
                final_path = path + ext
                if os.path.exists(final_path):
                    os.remove(final_path)
                os.rename(path, final_path)
                
                if sys.platform == "win32":
                    os.startfile(final_path)
                else:
                    import subprocess
                    opener = "open" if sys.platform == "darwin" else "xdg-open"
                    subprocess.call([opener, final_path])
        
        threading.Thread(target=do_open, daemon=True).start()

    def preview_file(self, item):
        ext = os.path.splitext(item["name"])[1].lower()
        
        if ext in IMAGE_EXTENSIONS:
            self.preview_image(item)
        elif ext in DOCUMENT_EXTENSIONS or ext in CODE_EXTENSIONS:
            self.preview_text(item)
        else:
            self.open_file(item)

    def preview_image(self, item):
        preview_window = ctk.CTkToplevel(self)
        preview_window.title(f"Preview: {item['name']}")
        preview_window.geometry("800x600")
        preview_window.transient(self)
        
        data = self.controller.security.decrypt_file_to_bytes(item["id"])
        if data:
            try:
                img = Image.open(BytesIO(data))
                img.thumbnail((750, 550), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                
                label = ctk.CTkLabel(preview_window, text="", image=photo)
                label.image = photo
                label.pack(expand=True, fill="both", padx=20, pady=20)
            except Exception as e:
                ctk.CTkLabel(preview_window, text=f"Cannot preview image: {e}").pack(pady=50)

    def preview_text(self, item):
        preview_window = ctk.CTkToplevel(self)
        preview_window.title(f"Preview: {item['name']}")
        preview_window.geometry("800x600")
        preview_window.transient(self)
        
        data = self.controller.security.decrypt_file_to_bytes(item["id"])
        if data:
            try:
                text = data.decode('utf-8')
            except:
                try:
                    text = data.decode('latin-1')
                except:
                    text = "Cannot decode file content"
            
            text_widget = ctk.CTkTextbox(preview_window, font=("Consolas", 12))
            text_widget.pack(expand=True, fill="both", padx=10, pady=10)
            text_widget.insert("1.0", text)
            text_widget.configure(state="disabled")

    def export_file(self, item):
        dest = filedialog.asksaveasfilename(defaultextension="", initialfile=item["name"])
        if dest:
            def do_export():
                path = self.controller.security.decrypt_file_to_temp(item["id"], self.controller.temp_dir)
                if path:
                    shutil.copy2(path, dest)
                    os.remove(path)
            threading.Thread(target=do_export, daemon=True).start()

    def show_analytics_view(self):
        self.clear_content()
        
        stats = self.controller.security.get_vault_stats()
        
        header = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=60, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"{ICONS['chart']} {self.controller.tr('vault_stats')}", 
                     font=("Segoe UI", 20, "bold"), text_color=self.theme["text"]).pack(side="left", padx=20, pady=15)

        content = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        stats_grid = ctk.CTkFrame(content, fg_color="transparent")
        stats_grid.pack(fill="x", pady=10)

        stat_cards = [
            (self.controller.tr("total_files"), str(stats["total_files"]), ICONS["file"]),
            (self.controller.tr("folders"), str(stats["total_folders"]), ICONS["folder"]),
            (self.controller.tr("total_size"), self.format_size(stats["total_size"]), ICONS["chart"]),
            (self.controller.tr("last_modified"), stats["last_modified"][:10] if stats["last_modified"] else "N/A", ICONS["clock"]),
        ]

        for i, (title, value, icon) in enumerate(stat_cards):
            card = ctk.CTkFrame(stats_grid, fg_color=self.theme["card"], corner_radius=10)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            stats_grid.grid_columnconfigure(i, weight=1)
            
            ctk.CTkLabel(card, text=icon, font=("Segoe UI", 30)).pack(pady=(20, 5))
            ctk.CTkLabel(card, text=value, font=("Segoe UI", 24, "bold"), 
                         text_color=self.theme["accent"]).pack(pady=5)
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 12), 
                         text_color=self.theme["highlight"]).pack(pady=(0, 20))

        if stats["categories"]:
            cat_frame = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
            cat_frame.pack(fill="x", pady=20, padx=10)
            
            ctk.CTkLabel(cat_frame, text=self.controller.tr("file_types"), 
                         font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")
            
            total = stats["total_files"] or 1
            for category, data in stats["categories"].items():
                row = ctk.CTkFrame(cat_frame, fg_color="transparent")
                row.pack(fill="x", padx=20, pady=5)
                
                percentage = (data["count"] / total) * 100
                ctk.CTkLabel(row, text=f"{category}", font=("Segoe UI", 12), width=100, anchor="w").pack(side="left")
                
                bar_frame = ctk.CTkFrame(row, fg_color=self.theme["fg"], height=20, corner_radius=5)
                bar_frame.pack(side="left", fill="x", expand=True, padx=10)
                
                if percentage > 0:
                    fill = ctk.CTkFrame(bar_frame, fg_color=self.theme["accent"], corner_radius=5)
                    fill.place(relx=0, rely=0, relwidth=percentage/100, relheight=1)
                
                ctk.CTkLabel(row, text=f"{data['count']} ({percentage:.1f}%)", 
                             font=("Segoe UI", 11), width=100).pack(side="right")

    def show_settings_view(self):
        self.clear_content()
        
        header = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=60, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"{ICONS['settings']} {self.controller.tr('settings')}", 
                     font=("Segoe UI", 20, "bold"), text_color=self.theme["text"]).pack(side="left", padx=20, pady=15)

        content = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        appearance_card = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
        appearance_card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(appearance_card, text=f"{ICONS['settings']} {self.controller.tr('appearance')}", 
                     font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")
        
        theme_frame = ctk.CTkFrame(appearance_card, fg_color="transparent")
        theme_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(theme_frame, text=self.controller.tr("theme"), font=("Segoe UI", 13)).pack(side="left")
        self.theme_var = ctk.StringVar(value=self.controller.current_theme)
        theme_menu = ctk.CTkOptionMenu(theme_frame, variable=self.theme_var, values=list(THEMES.keys()), width=200)
        theme_menu.pack(side="right")

        lang_frame = ctk.CTkFrame(appearance_card, fg_color="transparent")
        lang_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(lang_frame, text=self.controller.tr("language"), font=("Segoe UI", 13)).pack(side="left")
        self.lang_var = ctk.StringVar(value=self.controller.current_lang)
        lang_menu = ctk.CTkOptionMenu(lang_frame, variable=self.lang_var, values=list(Localization.LANGUAGES.keys()), width=200)
        lang_menu.pack(side="right", pady=(0, 15))

        security_card = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
        security_card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(security_card, text=f"{ICONS['shield']} {self.controller.tr('security_settings')}", 
                     font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")

        pw_frame = ctk.CTkFrame(security_card, fg_color="transparent")
        pw_frame.pack(fill="x", padx=20, pady=5)
        
        ctk.CTkLabel(pw_frame, text=self.controller.tr("current_pw"), font=("Segoe UI", 13)).pack(anchor="w")
        self.curr_pw_entry = ctk.CTkEntry(pw_frame, show="*", width=300)
        self.curr_pw_entry.pack(anchor="w", pady=5)

        new_pw_frame = ctk.CTkFrame(security_card, fg_color="transparent")
        new_pw_frame.pack(fill="x", padx=20, pady=5)
        
        ctk.CTkLabel(new_pw_frame, text=self.controller.tr("new_pw"), font=("Segoe UI", 13)).pack(anchor="w")
        self.new_pw_entry = ctk.CTkEntry(new_pw_frame, show="*", width=300)
        self.new_pw_entry.pack(anchor="w", pady=5)
        self.new_pw_entry.bind("<KeyRelease>", self.check_new_pw_strength)
        
        self.new_pw_strength = ctk.CTkLabel(new_pw_frame, text="", font=("Segoe UI", 11))
        self.new_pw_strength.pack(anchor="w")

        self.use_pw_var = tk.BooleanVar(value=self.controller.security.config.get("use_password", True))
        ctk.CTkCheckBox(security_card, text=self.controller.tr("use_pw"), variable=self.use_pw_var,
                        font=("Segoe UI", 13)).pack(padx=20, pady=15, anchor="w")

        storage_card = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
        storage_card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(storage_card, text=f"{ICONS['folder']} {self.controller.tr('vault_location')}", 
                     font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")
        
        loc_frame = ctk.CTkFrame(storage_card, fg_color="transparent")
        loc_frame.pack(fill="x", padx=20, pady=10)
        
        self.location_var = ctk.StringVar(value=self.controller.security.base_path)
        loc_entry = ctk.CTkEntry(loc_frame, textvariable=self.location_var, width=400)
        loc_entry.pack(side="left", padx=(0, 10))
        ctk.CTkButton(loc_frame, text=self.controller.tr("browse"), command=self.browse_location,
                      width=100).pack(side="left", pady=(0, 15))

        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", pady=20)
        
        ctk.CTkButton(btn_frame, text=f"{ICONS['success']} {self.controller.tr('apply')}", 
                      command=self.apply_settings, width=150, height=40,
                      fg_color=self.theme["accent"], font=("Segoe UI", 14)).pack(side="left", padx=10)

    def check_new_pw_strength(self, event=None):
        password = self.new_pw_entry.get()
        if password:
            strength, color, _, _ = PasswordStrengthChecker.check(password)
            self.new_pw_strength.configure(text=f"Strength: {strength}", text_color=color)
        else:
            self.new_pw_strength.configure(text="")

    def browse_location(self):
        path = filedialog.askdirectory()
        if path:
            self.location_var.set(path)

    def apply_settings(self):
        self.controller.current_lang = self.lang_var.get()
        self.controller.security.config["language"] = self.lang_var.get()
        
        new_theme = self.theme_var.get()
        if new_theme != self.controller.current_theme:
            self.controller.security.config["theme"] = new_theme
            self.controller.apply_theme(new_theme)
            self.theme = self.controller.get_theme_colors()

        curr_pw = self.curr_pw_entry.get()
        new_pw = self.new_pw_entry.get()
        use_pw = self.use_pw_var.get()

        if curr_pw or new_pw or (not use_pw and self.controller.security.config.get("use_password", True)):
            if self.controller.security.config.get("use_password", True) and not curr_pw:
                messagebox.showerror("Error", self.controller.tr("pw_req"))
                return
            
            if self.controller.security.config.get("use_password", True):
                valid, _, _ = self.controller.security.unlock_vault(curr_pw)
                if not valid:
                    messagebox.showerror("Error", "Invalid current password")
                    return
            
            target_pw = new_pw if new_pw else curr_pw
            if use_pw and not target_pw:
                messagebox.showerror("Error", "Password required when protection is enabled")
                return
            
            self.controller.security.change_password(target_pw, use_pw)

        self.controller.security._save_config()
        messagebox.showinfo("Success", self.controller.tr("save"))
        self.show_settings_view()

    def show_diagnostics_view(self):
        self.clear_content()
        
        header = ctk.CTkFrame(self.content_frame, fg_color=self.theme["card"], height=60, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"{ICONS['diagnostics']} {self.controller.tr('diagnostics')}", 
                     font=("Segoe UI", 20, "bold"), text_color=self.theme["text"]).pack(side="left", padx=20, pady=15)

        content = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        debug_card = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
        debug_card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(debug_card, text=f"{ICONS['settings']} Debug Settings", 
                     font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")
        
        debug_frame = ctk.CTkFrame(debug_card, fg_color="transparent")
        debug_frame.pack(fill="x", padx=20, pady=10)
        
        self.debug_var = tk.BooleanVar(value=self.controller.logger.enabled)
        debug_check = ctk.CTkCheckBox(debug_frame, text=self.controller.tr("debug_mode"), 
                                       variable=self.debug_var, command=self.toggle_debug,
                                       font=("Segoe UI", 13))
        debug_check.pack(side="left")
        
        ctk.CTkButton(debug_frame, text=self.controller.tr("clear_logs"), 
                      command=self.clear_logs, fg_color="#c0392b", width=120).pack(side="right", pady=(0, 15))

        logs_card = ctk.CTkFrame(content, fg_color=self.theme["card"], corner_radius=10)
        logs_card.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(logs_card, text="Error Logs", font=("Segoe UI", 16, "bold")).pack(pady=15, padx=20, anchor="w")
        
        logs_text = ctk.CTkTextbox(logs_card, font=("Consolas", 11), height=300)
        logs_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        logs = self.controller.logger.get_logs(limit=100)
        for log in logs:
            level_colors = {"INFO": "#27ae60", "WARNING": "#f39c12", "ERROR": "#e74c3c", "CRITICAL": "#c0392b"}
            color = level_colors.get(log["level"], "#ffffff")
            log_text = f"[{log['timestamp']}] [{log['level']}] {log['message']}"
            if log["details"]:
                log_text += f"\n    Details: {log['details']}"
            logs_text.insert("end", log_text + "\n")
        
        logs_text.configure(state="disabled")

    def toggle_debug(self):
        self.controller.logger.enabled = self.debug_var.get()
        self.controller.security.config["debug_mode"] = self.debug_var.get()
        self.controller.security._save_config()

    def clear_logs(self):
        self.controller.logger.clear_logs()
        self.show_diagnostics_view()

    def logout(self):
        self.controller.security.master_key = None
        self.controller.security.metadata_cache = None
        self.controller.show_frame(LoginFrame)

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
