import os
import sys
import json
import shutil
import base64
import hashlib
import secrets
import threading
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SecurityManager:
    def __init__(self, base_path):
        self.base_path = base_path
        self.config_path = os.path.join(base_path, "vault_config.dat")
        self.data_path = os.path.join(base_path, "vault_data")
        self.meta_path = os.path.join(base_path, "vault_meta.dat")
        self.master_key = None
        self.user_key = None
        self.config = {}
        self.failed_attempts = 0
        self.lockout_until = None
        self._ensure_dirs()
        self._load_config()

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

    def is_setup(self):
        return "enc_master_key" in self.config

    def setup_vault(self, password, use_password=True):
        self.master_key = AESGCM.generate_key(bit_length=256)
        salt = os.urandom(16)
        self.config["salt"] = base64.b64encode(salt).decode('utf-8')
        self.config["use_password"] = use_password
        self.config["uuid"] = secrets.token_hex(8)
        
        if use_password:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
            self.user_key = kdf.derive(password.encode())
        else:
            self.user_key = base64.b64decode(self.config["salt"]) 

        aesgcm = AESGCM(self.user_key)
        nonce = os.urandom(12)
        enc_master_key = aesgcm.encrypt(nonce, self.master_key, None)
        self.config["enc_master_key"] = base64.b64encode(nonce + enc_master_key).decode('utf-8')
        self._save_config()
        self._init_metadata()

    def unlock_vault(self, password):
        if self.lockout_until and datetime.datetime.now() < self.lockout_until:
            return False, "LOCKED"
        
        try:
            salt = base64.b64decode(self.config["salt"])
            encrypted_bundle = base64.b64decode(self.config["enc_master_key"])
            nonce = encrypted_bundle[:12]
            ciphertext = encrypted_bundle[12:]

            if self.config.get("use_password", True):
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
                user_key = kdf.derive(password.encode())
            else:
                user_key = salt

            aesgcm = AESGCM(user_key)
            self.master_key = aesgcm.decrypt(nonce, ciphertext, None)
            self.user_key = user_key
            self.failed_attempts = 0
            return True, "SUCCESS"
        except Exception:
            self.failed_attempts += 1
            if self.failed_attempts >= 5:
                self.lockout_until = datetime.datetime.now() + datetime.timedelta(minutes=5)
                return False, "LOCKED"
            return False, "INVALID"

    def change_password(self, new_password, enable_password):
        if not self.master_key:
            return False
        
        salt = os.urandom(16)
        self.config["salt"] = base64.b64encode(salt).decode('utf-8')
        self.config["use_password"] = enable_password

        if enable_password:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
            new_user_key = kdf.derive(new_password.encode())
        else:
            new_user_key = salt

        aesgcm = AESGCM(new_user_key)
        nonce = os.urandom(12)
        enc_master_key = aesgcm.encrypt(nonce, self.master_key, None)
        self.config["enc_master_key"] = base64.b64encode(nonce + enc_master_key).decode('utf-8')
        self.user_key = new_user_key
        self._save_config()
        return True

    def encrypt_file(self, file_path, dest_folder_id):
        if not self.master_key: return None
        try:
            filename = os.path.basename(file_path)
            file_id = secrets.token_hex(16)
            enc_filename = file_id + ".enc"
            dest_path = os.path.join(self.data_path, enc_filename)

            with open(file_path, "rb") as f:
                data = f.read()

            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(12)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            with open(dest_path, "wb") as f:
                f.write(nonce + encrypted_data)

            return {
                "id": file_id,
                "name": filename,
                "type": "file",
                "parent_id": dest_folder_id,
                "size": len(data)
            }
        except Exception as e:
            return None

    def decrypt_file_to_temp(self, file_id, temp_dir):
        try:
            enc_path = os.path.join(self.data_path, file_id + ".enc")
            if not os.path.exists(enc_path): return None
            
            with open(enc_path, "rb") as f:
                content = f.read()
            
            nonce = content[:12]
            ciphertext = content[12:]
            aesgcm = AESGCM(self.master_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            temp_path = os.path.join(temp_dir, file_id)
            with open(temp_path, "wb") as f:
                f.write(plaintext)
            return temp_path
        except Exception:
            return None

    def delete_file(self, file_id):
        path = os.path.join(self.data_path, file_id + ".enc")
        if os.path.exists(path):
            os.remove(path)

    def _init_metadata(self):
        meta = {"root": {"id": "root", "name": "Root", "type": "folder", "children": []}}
        self.save_metadata(meta)

    def load_metadata(self):
        if not os.path.exists(self.meta_path):
            self._init_metadata()
        
        with open(self.meta_path, "rb") as f:
            content = f.read()
        
        try:
            nonce = content[:12]
            ciphertext = content[12:]
            aesgcm = AESGCM(self.master_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except:
            return {"root": {"id": "root", "name": "Root", "type": "folder", "children": []}}

    def save_metadata(self, meta):
        data = json.dumps(meta).encode('utf-8')
        aesgcm = AESGCM(self.master_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        with open(self.meta_path, "wb") as f:
            f.write(nonce + encrypted_data)

class Localization:
    LANGUAGES = {
        "English": {"welcome": "Welcome", "password": "Password", "login": "Login", "setup": "Initial Setup", "create_pw": "Create Password", "confirm_pw": "Confirm Password", "use_pw": "Enable Password Protection", "security_warn": "Warning: Without a password, anyone with access to this computer can open your vault.", "match_err": "Passwords do not match", "setup_done": "Setup Complete", "error": "Error", "upload": "Upload Files", "new_folder": "New Folder", "settings": "Settings", "back": "Back", "items": "items", "delete": "Delete", "move": "Move", "rename": "Rename", "logout": "Logout", "change_pw": "Change Password", "theme_color": "Theme Color", "language": "Language", "apply": "Apply", "save": "Save", "delete_confirm": "Are you sure you want to delete this?", "yes": "Yes", "no": "No", "current_pw": "Current Password", "new_pw": "New Password", "pw_req": "Password Required", "decryption_err": "Decryption Failed"},
        "German": {"welcome": "Willkommen", "password": "Passwort", "login": "Anmelden", "setup": "Einrichtung", "create_pw": "Passwort erstellen", "confirm_pw": "Bestätigen", "use_pw": "Passwortschutz aktivieren", "security_warn": "Warnung: Ohne Passwort kann jeder auf diesen Tresor zugreifen.", "match_err": "Passwörter stimmen nicht überein", "setup_done": "Fertig", "error": "Fehler", "upload": "Hochladen", "new_folder": "Neuer Ordner", "settings": "Einstellungen", "back": "Zurück", "items": "Elemente", "delete": "Löschen", "move": "Verschieben", "rename": "Umbenennen", "logout": "Abmelden", "change_pw": "Passwort ändern", "theme_color": "Farbschema", "language": "Sprache", "apply": "Anwenden", "save": "Speichern", "delete_confirm": "Wirklich löschen?", "yes": "Ja", "no": "Nein", "current_pw": "Aktuelles Passwort", "new_pw": "Neues Passwort", "pw_req": "Passwort erforderlich", "decryption_err": "Entschlüsselung fehlgeschlagen"},
        "Spanish": {"welcome": "Bienvenido", "password": "Contraseña", "login": "Entrar", "setup": "Configuración", "create_pw": "Crear Contraseña", "confirm_pw": "Confirmar", "use_pw": "Usar contraseña", "security_warn": "Advertencia: Sin contraseña es menos seguro.", "match_err": "No coinciden", "setup_done": "Listo", "error": "Error", "upload": "Subir", "new_folder": "Nueva Carpeta", "settings": "Ajustes", "back": "Atrás", "items": "ítems", "delete": "Borrar", "move": "Mover", "rename": "Renombrar", "logout": "Salir", "change_pw": "Cambiar Contraseña", "theme_color": "Color del tema", "language": "Idioma", "apply": "Aplicar", "save": "Guardar", "delete_confirm": "¿Seguro?", "yes": "Sí", "no": "No", "current_pw": "Contraseña actual", "new_pw": "Nueva contraseña", "pw_req": "Contraseña requerida", "decryption_err": "Error de descifrado"},
        "French": {"welcome": "Bienvenue", "password": "Mot de passe", "login": "Connexion", "setup": "Installation", "create_pw": "Créer mot de passe", "confirm_pw": "Confirmer", "use_pw": "Activer protection", "security_warn": "Attention: Moins sécurisé sans mot de passe.", "match_err": "Les mots de passe ne correspondent pas", "setup_done": "Terminé", "error": "Erreur", "upload": "Téléverser", "new_folder": "Nouveau dossier", "settings": "Paramètres", "back": "Retour", "items": "articles", "delete": "Supprimer", "move": "Déplacer", "rename": "Renommer", "logout": "Déconnexion", "change_pw": "Changer mot de passe", "theme_color": "Couleur", "language": "Langue", "apply": "Appliquer", "save": "Sauvegarder", "delete_confirm": "Êtes-vous sûr?", "yes": "Oui", "no": "Non", "current_pw": "Mot de passe actuel", "new_pw": "Nouveau mot de passe", "pw_req": "Mot de passe requis", "decryption_err": "Échec du déchiffrement"},
        "Italian": {"welcome": "Benvenuto", "password": "Password", "login": "Accedi", "setup": "Configurazione", "create_pw": "Crea Password", "confirm_pw": "Conferma", "use_pw": "Usa Password", "security_warn": "Attenzione: Meno sicuro senza password.", "match_err": "Le password non corrispondono", "setup_done": "Fatto", "error": "Errore", "upload": "Carica", "new_folder": "Nuova Cartella", "settings": "Impostazioni", "back": "Indietro", "items": "elementi", "delete": "Elimina", "move": "Sposta", "rename": "Rinomina", "logout": "Esci", "change_pw": "Cambia Password", "theme_color": "Colore Tema", "language": "Lingua", "apply": "Applica", "save": "Salva", "delete_confirm": "Sei sicuro?", "yes": "Sì", "no": "No", "current_pw": "Password attuale", "new_pw": "Nuova Password", "pw_req": "Password richiesta", "decryption_err": "Decrittazione fallita"},
        "Portuguese": {"welcome": "Bem-vindo", "password": "Senha", "login": "Entrar", "setup": "Configuração", "create_pw": "Criar Senha", "confirm_pw": "Confirmar", "use_pw": "Usar Senha", "security_warn": "Aviso: Menos seguro sem senha.", "match_err": "Senhas não coincidem", "setup_done": "Pronto", "error": "Erro", "upload": "Enviar", "new_folder": "Nova Pasta", "settings": "Configurações", "back": "Voltar", "items": "itens", "delete": "Excluir", "move": "Mover", "rename": "Renomear", "logout": "Sair", "change_pw": "Mudar Senha", "theme_color": "Cor do Tema", "language": "Idioma", "apply": "Aplicar", "save": "Salvar", "delete_confirm": "Tem certeza?", "yes": "Sim", "no": "Não", "current_pw": "Senha atual", "new_pw": "Nova Senha", "pw_req": "Senha necessária", "decryption_err": "Erro de descriptografia"},
        "Russian": {"welcome": "Добро пожаловать", "password": "Пароль", "login": "Войти", "setup": "Установка", "create_pw": "Создать пароль", "confirm_pw": "Подтвердить", "use_pw": "Использовать пароль", "security_warn": "Внимание: Без пароля менее безопасно.", "match_err": "Пароли не совпадают", "setup_done": "Готово", "error": "Ошибка", "upload": "Загрузить", "new_folder": "Новая папка", "settings": "Настройки", "back": "Назад", "items": "элементы", "delete": "Удалить", "move": "Переместить", "rename": "Переименовать", "logout": "Выйти", "change_pw": "Сменить пароль", "theme_color": "Цвет темы", "language": "Язык", "apply": "Применить", "save": "Сохранить", "delete_confirm": "Вы уверены?", "yes": "Да", "no": "Нет", "current_pw": "Текущий пароль", "new_pw": "Новый пароль", "pw_req": "Требуется пароль", "decryption_err": "Ошибка расшифровки"},
        "Japanese": {"welcome": "ようこそ", "password": "パスワード", "login": "ログイン", "setup": "設定", "create_pw": "パスワード作成", "confirm_pw": "確認", "use_pw": "パスワードを使用", "security_warn": "警告：パスワードなしでは安全ではありません。", "match_err": "一致しません", "setup_done": "完了", "error": "エラー", "upload": "アップロード", "new_folder": "新しいフォルダ", "settings": "設定", "back": "戻る", "items": "項目", "delete": "削除", "move": "移動", "rename": "名前変更", "logout": "ログアウト", "change_pw": "パスワード変更", "theme_color": "テーマ色", "language": "言語", "apply": "適用", "save": "保存", "delete_confirm": "よろしいですか？", "yes": "はい", "no": "いいえ", "current_pw": "現在のパスワード", "new_pw": "新しいパスワード", "pw_req": "パスワードが必要です", "decryption_err": "復号化失敗"},
        "Chinese": {"welcome": "欢迎", "password": "密码", "login": "登录", "setup": "设置", "create_pw": "创建密码", "confirm_pw": "确认", "use_pw": "使用密码", "security_warn": "警告：没有密码不安全。", "match_err": "密码不匹配", "setup_done": "完成", "error": "错误", "upload": "上传", "new_folder": "新建文件夹", "settings": "设置", "back": "返回", "items": "项目", "delete": "删除", "move": "移动", "rename": "重命名", "logout": "登出", "change_pw": "更改密码", "theme_color": "主题颜色", "language": "语言", "apply": "应用", "save": "保存", "delete_confirm": "确定吗？", "yes": "是", "no": "否", "current_pw": "当前密码", "new_pw": "新密码", "pw_req": "需要密码", "decryption_err": "解密失败"},
        "Korean": {"welcome": "환영합니다", "password": "비밀번호", "login": "로그인", "setup": "설정", "create_pw": "비밀번호 생성", "confirm_pw": "확인", "use_pw": "비밀번호 사용", "security_warn": "경고: 비밀번호 없이는 보안이 취약합니다.", "match_err": "일치하지 않습니다", "setup_done": "완료", "error": "오류", "upload": "업로드", "new_folder": "새 폴더", "settings": "설정", "back": "뒤로", "items": "항목", "delete": "삭제", "move": "이동", "rename": "이름 변경", "logout": "로그아웃", "change_pw": "비밀번호 변경", "theme_color": "테마 색상", "language": "언어", "apply": "적용", "save": "저장", "delete_confirm": "확실합니까?", "yes": "예", "no": "아니요", "current_pw": "현재 비밀번호", "new_pw": "새 비밀번호", "pw_req": "비밀번호 필요", "decryption_err": "복호화 실패"}
    }
    
    extra_langs = ["Dutch", "Polish", "Swedish", "Turkish", "Arabic", "Hindi", "Bengali", "Vietnamese", "Thai", "Greek"]
    for lang in extra_langs:
        LANGUAGES[lang] = LANGUAGES["English"]

    @staticmethod
    def get(lang, key):
        return Localization.LANGUAGES.get(lang, Localization.LANGUAGES["English"]).get(key, key)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Vanquish's Media Vault")
        self.geometry("1000x700")
        self.security = SecurityManager(os.path.join(os.environ.get('APPDATA', '.'), 'VanquishVault'))
        self.current_lang = self.security.config.get("language", "English")
        self.theme_color = self.security.config.get("theme", "blue")
        ctk.set_default_color_theme(self.theme_color)
        
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)
        self.current_frame = None
        self.temp_dir = os.path.join(self.security.base_path, "temp_view")
        if not os.path.exists(self.temp_dir): os.makedirs(self.temp_dir)

        if not self.security.is_setup():
            self.show_frame(SetupFrame)
        else:
            self.show_frame(LoginFrame)

    def show_frame(self, frame_class, **kwargs):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.container, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def tr(self, key):
        return Localization.get(self.current_lang, key)
    
    def on_close(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        self.destroy()

class SetupFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.use_password = tk.BooleanVar(value=True)

        ctk.CTkLabel(self, text="Vanquish's Media Vault", font=("Roboto", 24, "bold")).pack(pady=30)
        ctk.CTkLabel(self, text=self.controller.tr("setup"), font=("Roboto", 18)).pack(pady=10)

        self.pw_entry = ctk.CTkEntry(self, placeholder_text=self.controller.tr("create_pw"), show="*", width=300)
        self.pw_entry.pack(pady=10)
        self.pw_confirm = ctk.CTkEntry(self, placeholder_text=self.controller.tr("confirm_pw"), show="*", width=300)
        self.pw_confirm.pack(pady=10)

        self.check = ctk.CTkCheckBox(self, text=self.controller.tr("use_pw"), variable=self.use_password, command=self.toggle_pw)
        self.check.pack(pady=10)
        self.check.select()

        self.warn_label = ctk.CTkLabel(self, text="", text_color="orange")
        self.warn_label.pack(pady=5)

        ctk.CTkButton(self, text=self.controller.tr("save"), command=self.finish_setup).pack(pady=20)

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
                return
            if p1 != p2:
                self.warn_label.configure(text=self.controller.tr("match_err"), text_color="red")
                return
        
        self.controller.security.setup_vault(p1, self.use_password.get())
        self.controller.show_frame(MainVaultFrame)

class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        if not controller.security.config.get("use_password", True):
            controller.security.unlock_vault("")
            controller.show_frame(MainVaultFrame)
            return

        ctk.CTkLabel(self, text="Vanquish's Media Vault", font=("Roboto", 24, "bold")).pack(pady=40)
        
        self.pw_entry = ctk.CTkEntry(self, placeholder_text=self.controller.tr("password"), show="*", width=300)
        self.pw_entry.pack(pady=10)
        self.pw_entry.bind("<Return>", lambda e: self.login())

        self.login_btn = ctk.CTkButton(self, text=self.controller.tr("login"), command=self.login)
        self.login_btn.pack(pady=20)
        
        self.msg_label = ctk.CTkLabel(self, text="", text_color="red")
        self.msg_label.pack(pady=10)

    def login(self):
        pw = self.pw_entry.get()
        success, msg = self.controller.security.unlock_vault(pw)
        if success:
            self.controller.show_frame(MainVaultFrame)
        else:
            if msg == "LOCKED":
                self.msg_label.configure(text="System Locked. Wait 5 mins.")
            else:
                self.msg_label.configure(text="Invalid Password")

class MainVaultFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.metadata = self.controller.security.load_metadata()
        self.current_folder_id = "root"
        self.path_history = []
        self.clipboard = None

        top_bar = ctk.CTkFrame(self, height=50)
        top_bar.pack(fill="x", padx=10, pady=5)

        self.path_label = ctk.CTkLabel(top_bar, text="/", font=("Roboto", 14))
        self.path_label.pack(side="left", padx=10)

        ctk.CTkButton(top_bar, text=self.controller.tr("settings"), width=80, command=self.open_settings).pack(side="right", padx=5)
        ctk.CTkButton(top_bar, text=self.controller.tr("logout"), width=80, fg_color="#c0392b", hover_color="#e74c3c", command=self.logout).pack(side="right", padx=5)

        action_bar = ctk.CTkFrame(self, height=50)
        action_bar.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkButton(action_bar, text="< " + self.controller.tr("back"), width=60, command=self.go_back).pack(side="left", padx=5)
        ctk.CTkButton(action_bar, text="+ " + self.controller.tr("upload"), command=self.upload_files).pack(side="left", padx=5)
        ctk.CTkButton(action_bar, text="+ " + self.controller.tr("new_folder"), command=self.create_folder).pack(side="left", padx=5)
        
        self.scroll = ctk.CTkScrollableFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=10, pady=5)

        self.status_bar = ctk.CTkLabel(self, text="", anchor="w")
        self.status_bar.pack(fill="x", padx=10, pady=2)

        self.refresh_view()

    def get_node(self, node_id, current_node=None):
        if current_node is None: current_node = self.metadata["root"]
        if current_node["id"] == node_id: return current_node
        if current_node["type"] == "folder":
            for child in current_node["children"]:
                res = self.get_node(node_id, child)
                if res: return res
        return None

    def get_parent(self, node_id, current_node=None):
        if current_node is None: current_node = self.metadata["root"]
        if current_node["type"] == "folder":
            for child in current_node["children"]:
                if child["id"] == node_id: return current_node
                res = self.get_parent(node_id, child)
                if res: return res
        return None

    def save_meta(self):
        self.controller.security.save_metadata(self.metadata)
        self.refresh_view()

    def refresh_view(self):
        for w in self.scroll.winfo_children(): w.destroy()
        folder = self.get_node(self.current_folder_id)
        if not folder: return
        
        self.path_label.configure(text=f"/{folder['name']}")
        
        for item in folder["children"]:
            self.create_item_widget(item)

    def create_item_widget(self, item):
        card = ctk.CTkFrame(self.scroll, fg_color=("#dfe6e9", "#2d3436"))
        card.pack(fill="x", pady=2, padx=5)
        
        icon = "📁" if item["type"] == "folder" else "📄"
        lbl = ctk.CTkLabel(card, text=f"{icon}  {item['name']}", anchor="w")
        lbl.pack(side="left", padx=10, pady=10, fill="x", expand=True)
        if item["type"] == "file":
            lbl.bind("<Double-Button-1>", lambda e, i=item: self.open_file(i))
        else:
            lbl.bind("<Double-Button-1>", lambda e, i=item: self.enter_folder(i))

        btn_box = ctk.CTkFrame(card, fg_color="transparent")
        btn_box.pack(side="right", padx=5)

        if item["type"] == "folder":
            ctk.CTkButton(btn_box, text="Open", width=50, command=lambda i=item: self.enter_folder(i)).pack(side="left", padx=2)
        else:
            ctk.CTkButton(btn_box, text="View", width=50, command=lambda i=item: self.open_file(i)).pack(side="left", padx=2)

        ctk.CTkButton(btn_box, text="Mov", width=40, command=lambda i=item: self.init_move(i)).pack(side="left", padx=2)
        if self.clipboard and self.clipboard == item["id"]:
             ctk.CTkButton(btn_box, text="Paste Here", width=60, fg_color="green", command=lambda: self.paste_item(self.current_folder_id)).pack(side="left", padx=2)

        ctk.CTkButton(btn_box, text="Del", width=40, fg_color="red", command=lambda i=item: self.delete_item(i)).pack(side="left", padx=2)
        ctk.CTkButton(btn_box, text="Ren", width=40, command=lambda i=item: self.rename_item(i)).pack(side="left", padx=2)

    def enter_folder(self, item):
        self.path_history.append(self.current_folder_id)
        self.current_folder_id = item["id"]
        self.refresh_view()

    def go_back(self):
        if self.path_history:
            self.current_folder_id = self.path_history.pop()
            self.refresh_view()

    def upload_files(self):
        paths = filedialog.askopenfilenames()
        if not paths: return
        folder = self.get_node(self.current_folder_id)
        for p in paths:
            meta = self.controller.security.encrypt_file(p, self.current_folder_id)
            if meta:
                # Rename collision check
                base_name = meta["name"]
                cnt = 1
                while any(c["name"] == meta["name"] for c in folder["children"]):
                    name, ext = os.path.splitext(base_name)
                    meta["name"] = f"{name}_{cnt}{ext}"
                    cnt += 1
                folder["children"].append(meta)
        self.save_meta()

    def create_folder(self):
        dialog = ctk.CTkInputDialog(text=self.controller.tr("new_folder"), title="New Folder")
        name = dialog.get_input()
        if name:
            new_folder = {"id": secrets.token_hex(8), "name": name, "type": "folder", "children": []}
            self.get_node(self.current_folder_id)["children"].append(new_folder)
            self.save_meta()

    def delete_item(self, item):
        if not messagebox.askyesno("Confirm", self.controller.tr("delete_confirm")): return
        
        parent = self.get_parent(item["id"])
        if not parent: return
        
        def recursive_delete(node):
            if node["type"] == "file":
                self.controller.security.delete_file(node["id"])
            else:
                for child in node["children"]:
                    recursive_delete(child)
        
        recursive_delete(item)
        parent["children"] = [c for c in parent["children"] if c["id"] != item["id"]]
        self.save_meta()

    def rename_item(self, item):
        dialog = ctk.CTkInputDialog(text="New Name:", title=self.controller.tr("rename"))
        name = dialog.get_input()
        if name:
            item["name"] = name
            self.save_meta()

    def init_move(self, item):
        self.clipboard = item
        self.status_bar.configure(text=f"Selected {item['name']} to move. Navigate to dest and click 'Paste Here' on any item or header (implied).")
        # For simplicity, add a paste button to action bar when moving
        # Simplified: user must double click folder to enter, then can paste? 
        # Better: Current UI shows "Mov" button. When clicked, we store ID.
        # Then user navigates. A "Paste" button should appear in the action bar.
        self.paste_btn = ctk.CTkButton(self.scroll, text="Paste Selection Here", fg_color="green", command=self.exec_paste)
        self.paste_btn.pack(pady=5)

    def exec_paste(self):
        if not self.clipboard: return
        item = self.clipboard
        old_parent = self.get_parent(item["id"])
        new_parent = self.get_node(self.current_folder_id)
        
        if old_parent and new_parent:
            old_parent["children"] = [c for c in old_parent["children"] if c["id"] != item["id"]]
            new_parent["children"].append(item)
            item["parent_id"] = new_parent["id"]
            self.clipboard = None
            self.save_meta()

    def open_file(self, item):
        path = self.controller.security.decrypt_file_to_temp(item["id"], self.controller.temp_dir)
        if path:
            if sys.platform == "win32":
                os.startfile(path)
            else:
                import subprocess
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.call([opener, path])

    def open_settings(self):
        self.controller.show_frame(SettingsFrame)

    def logout(self):
        self.controller.security.master_key = None
        self.controller.show_frame(LoginFrame)

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ctk.CTkLabel(self, text=self.controller.tr("settings"), font=("Roboto", 20)).pack(pady=20)

        # Language
        ctk.CTkLabel(self, text=self.controller.tr("language")).pack()
        self.lang_var = ctk.StringVar(value=controller.current_lang)
        ctk.CTkOptionMenu(self, variable=self.lang_var, values=list(Localization.LANGUAGES.keys())).pack(pady=5)
        
        # Theme
        ctk.CTkLabel(self, text=self.controller.tr("theme_color")).pack()
        self.theme_var = ctk.StringVar(value=controller.theme_color)
        ctk.CTkOptionMenu(self, variable=self.theme_var, values=["blue", "green", "dark-blue"]).pack(pady=5)

        # Password Management
        ctk.CTkLabel(self, text="Security", font=("Roboto", 16)).pack(pady=15)
        
        self.curr_pw = ctk.CTkEntry(self, placeholder_text=self.controller.tr("current_pw"), show="*")
        self.curr_pw.pack(pady=5)
        self.new_pw = ctk.CTkEntry(self, placeholder_text=self.controller.tr("new_pw"), show="*")
        self.new_pw.pack(pady=5)
        
        self.use_pw_var = tk.BooleanVar(value=controller.security.config.get("use_password", True))
        ctk.CTkCheckBox(self, text=self.controller.tr("use_pw"), variable=self.use_pw_var).pack(pady=5)

        ctk.CTkButton(self, text=self.controller.tr("apply"), command=self.apply_changes).pack(pady=20)
        ctk.CTkButton(self, text=self.controller.tr("back"), fg_color="gray", command=lambda: controller.show_frame(MainVaultFrame)).pack(pady=5)

    def apply_changes(self):
        # Update UI settings
        self.controller.current_lang = self.lang_var.get()
        self.controller.security.config["language"] = self.lang_var.get()
        
        new_theme = self.theme_var.get()
        if new_theme != self.controller.theme_color:
            ctk.set_default_color_theme(new_theme)
            self.controller.security.config["theme"] = new_theme
            messagebox.showinfo("Info", "Restart app to see full theme changes.")

        # Security Updates
        curr = self.curr_pw.get()
        new_p = self.new_pw.get()
        req_pw = self.use_pw_var.get()
        
        # If toggling password requirement or changing password
        if curr or not self.controller.security.config.get("use_password", True):
            # If currently has password, must verify curr
            if self.controller.security.config.get("use_password", True) and not curr:
                 messagebox.showerror("Error", self.controller.tr("pw_req"))
                 return

            # Verify current password logic (try to unlock again)
            valid = True
            if self.controller.security.config.get("use_password", True):
                valid, _ = self.controller.security.unlock_vault(curr)
            
            if valid:
                target_pw = new_p if new_p else curr
                if not req_pw: target_pw = "" # No password
                elif not target_pw: target_pw = "" # User enabled pw but field empty? Disallow.
                
                if req_pw and not target_pw:
                     messagebox.showerror("Error", "Cannot enable password protection with empty password")
                     return

                self.controller.security.change_password(target_pw, req_pw)
                messagebox.showinfo("Success", self.controller.tr("save"))
            else:
                messagebox.showerror("Error", "Invalid Current Password")
        else:
             # Just saving configs
             self.controller.security._save_config()
             messagebox.showinfo("Success", self.controller.tr("save"))

        self.controller.show_frame(MainVaultFrame)

if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()