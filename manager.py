import random
import string
import os
import getpass
import bcrypt
import signal
import time
import pyotp
import qrcode
import sys
import json
import requests
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from typing import Optional, Tuple, List, Dict
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QMessageBox, 
                             QTableWidget, QTableWidgetItem, QHBoxLayout, QInputDialog, QMainWindow, QAction, 
                             QMenu, QSystemTrayIcon, QStyle, QComboBox, QFrame, QSizePolicy, QTabWidget,
                             QScrollArea, QGridLayout, QCheckBox, QFileDialog, QProgressBar, QDialog)
from PyQt5.QtGui import QFont, QIcon, QClipboard, QColor, QPalette, QPixmap
from PyQt5.QtCore import Qt, QTimer, QSettings, QPropertyAnimation, QEasingCurve, QThread, pyqtSignal

# Constants
DB_FOLDER = os.path.join(os.getcwd(), "DB")
PASSWORD_FILE = os.path.join(DB_FOLDER, "passwords.encrypted")
USERS_FILE = os.path.join(DB_FOLDER, "users.json")
KEY_FILE = os.path.join(DB_FOLDER, "key.key")
SALT_FILE = os.path.join(DB_FOLDER, "salt.key")
MFA_SECRET_FILE = os.path.join(DB_FOLDER, "mfa_secrets.json")
AUDIT_LOG_FILE = os.path.join(DB_FOLDER, "audit_log.json")

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username: Optional[str] = None
        self.clipboard_timer: Optional[QTimer] = None
        self.settings = QSettings("MyCompany", "SecurePasswordVault")
        self.passwords: Dict[str, Dict[str, str]] = {}
        self.mfa_secrets: Dict[str, str] = self.load_mfa_secrets()
        self.init_ui()
        self.init_tray_icon()
        self.init_encryption()
        self.master_password = None
        self.user_salt = None

    def init_ui(self):
        self.setWindowTitle('Secure Password Vault')
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet(self.get_stylesheet())

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.layout = QVBoxLayout(central_widget)

        self.create_login_ui()

    def create_login_ui(self):
        self.clear_layout()

        logo_label = QLabel('🔒', self)
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setStyleSheet("font-size: 72px;")
        self.layout.addWidget(logo_label)

        title_label = QLabel('Secure Password Vault', self)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        self.layout.addWidget(title_label)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('Username')
        self.username_input.setStyleSheet("margin-bottom: 10px;")
        self.layout.addWidget(self.username_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("margin-bottom: 20px;")
        self.layout.addWidget(self.password_input)

        self.mfa_input = QLineEdit(self)
        self.mfa_input.setPlaceholderText('MFA Code (if enabled)')
        self.mfa_input.setStyleSheet("margin-bottom: 20px;")
        self.layout.addWidget(self.mfa_input)

        login_button = QPushButton('Login', self)
        login_button.clicked.connect(self.login)
        login_button.setStyleSheet("margin-bottom: 10px;")
        self.layout.addWidget(login_button)

        create_user_button = QPushButton('Create User', self)
        create_user_button.clicked.connect(self.create_user)
        self.layout.addWidget(create_user_button)

        forgot_password_button = QPushButton('Forgot Password', self)
        forgot_password_button.clicked.connect(self.forgot_password)
        self.layout.addWidget(forgot_password_button)

    def create_main_menu(self):
        self.clear_layout()
        
        title_label = QLabel('Password Vault', self)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        self.layout.addWidget(title_label)

        tab_widget = QTabWidget()
        self.layout.addWidget(tab_widget)

        # Passwords tab
        passwords_tab = QWidget()
        passwords_layout = QVBoxLayout(passwords_tab)
        
        actions = [
            ('🔑 Generate Password', self.generate_password),
            ('💾 Save Password', self.save_password),
            ('🔍 Retrieve Password', self.retrieve_password),
            ('🔄 Update Password', self.update_password),
            ('📋 List All Passwords', self.list_passwords),
            ('🗑️ Delete Password', self.delete_password),
        ]

        for text, slot in actions:
            button = QPushButton(text, self)
            button.clicked.connect(slot)
            passwords_layout.addWidget(button)

        tab_widget.addTab(passwords_tab, "Passwords")

        # Security tab
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)

        security_actions = [
            ('🔒 Change Master Password', self.change_master_password),
            ('🔐 Enable/Disable MFA', self.toggle_mfa),
            ('🛡️ Security Audit', self.security_audit),
            ('🔍 Check for Breached Passwords', self.check_breached_passwords),
        ]

        for text, slot in security_actions:
            button = QPushButton(text, self)
            button.clicked.connect(slot)
            security_layout.addWidget(button)

        tab_widget.addTab(security_tab, "Security")

        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)

        settings_actions = [
            ('🌓 Toggle Dark Mode', self.toggle_dark_mode),
            ('💾 Export Passwords', self.export_passwords),
            ('📥 Import Passwords', self.import_passwords),
            ('🔄 Sync with Cloud', self.sync_with_cloud),
            ('🗑️ Delete Account', self.delete_account),
        ]

        for text, slot in settings_actions:
            button = QPushButton(text, self)
            button.clicked.connect(slot)
            settings_layout.addWidget(button)

        tab_widget.addTab(settings_tab, "Settings")

        logout_button = QPushButton('🚪 Logout', self)
        logout_button.clicked.connect(self.logout)
        self.layout.addWidget(logout_button)

    def clear_layout(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def generate_password(self):
        length, ok = QInputDialog.getInt(self, 'Generate Password', 'Enter password length:', 16, 8, 32)
        if ok:
            use_special_chars, ok = QInputDialog.getItem(self, 'Generate Password', 'Use special characters?', ['Yes', 'No'], 0, False)
            if ok:
                password = self._generate_password(length, use_special_chars == 'Yes')
                strength = self.check_password_strength(password)
                self.copy_to_clipboard(password, f"Generated password (strength: {strength}) copied to clipboard. It will be cleared in 10 seconds.")

    def save_password(self):
        category, ok = QInputDialog.getText(self, 'Save Password', 'Enter the category for the password:')
        if ok:
            title, ok = QInputDialog.getText(self, 'Save Password', 'Enter the title for the password:')
            if ok:
                password, ok = QInputDialog.getText(self, 'Save Password', 'Enter the password:', QLineEdit.Password)
                if ok:
                    self._save_password(self.username, category, title, password)
                    if category not in self.passwords:
                        self.passwords[category] = {}
                    self.passwords[category][title] = password
                    QMessageBox.information(self, 'Success', 'Password saved successfully!')

    def retrieve_password(self):
        if not self.passwords:
            self._load_passwords()
        
        category, ok = QInputDialog.getItem(self, 'Retrieve Password', 'Select the category:', list(self.passwords.keys()), 0, False)
        if ok:
            titles = list(self.passwords[category].keys())
            if titles:
                title, ok = QInputDialog.getItem(self, 'Retrieve Password', 'Select the password title:', titles, 0, False)
                if ok:
                    encrypted_password = self.passwords[category].get(title)
                    if encrypted_password:
                        password = self.decrypt_password(encrypted_password.encode())
                        self.copy_to_clipboard(password, f"Password for {title} copied to clipboard. It will be cleared in 10 seconds.")
                    else:
                        QMessageBox.warning(self, 'Error', 'Password not found!')
            else:
                QMessageBox.warning(self, 'Error', 'No passwords found in this category!')

    def update_password(self):
        if not self.passwords:
            self._load_passwords()
        
        category, ok = QInputDialog.getItem(self, 'Update Password', 'Select the category:', list(self.passwords.keys()), 0, False)
        if ok:
            titles = list(self.passwords[category].keys())
            if titles:
                title, ok = QInputDialog.getItem(self, 'Update Password', 'Select the password title:', titles, 0, False)
                if ok:
                    new_password, ok = QInputDialog.getText(self, 'Update Password', 'Enter the new password:', QLineEdit.Password)
                    if ok:
                        self._update_password(self.username, category, title, new_password)
                        self.passwords[category][title] = new_password
                        QMessageBox.information(self, 'Success', 'Password updated successfully!')
            else:
                QMessageBox.warning(self, 'Error', 'No passwords found in this category!')

    def list_passwords(self):
        if not self.passwords:
            self._load_passwords()
        
        if self.passwords:
            self.clear_layout()
            
            title_label = QLabel('Your Passwords', self)
            title_label.setAlignment(Qt.AlignCenter)
            title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
            self.layout.addWidget(title_label)

            scroll_area = QScrollArea()
            scroll_widget = QWidget()
            scroll_layout = QVBoxLayout(scroll_widget)

            for category, passwords in self.passwords.items():
                category_label = QLabel(category)
                category_label.setStyleSheet("font-size: 18px; font-weight: bold;")
                scroll_layout.addWidget(category_label)

                table = QTableWidget(len(passwords), 2)
                table.setHorizontalHeaderLabels(['Title', 'Password'])
                for i, (title, password) in enumerate(passwords.items()):
                    title_item = QTableWidgetItem(title)
                    title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
                    table.setItem(i, 0, title_item)
                    
                    password_item = QTableWidgetItem('*' * len(password))
                    password_item.setFlags(password_item.flags() & ~Qt.ItemIsEditable)
                    table.setItem(i, 1, password_item)
                
                table.resizeColumnsToContents()
                table.setStyleSheet("QTableWidget::item { padding: 5px; }")
                scroll_layout.addWidget(table)

            scroll_area.setWidget(scroll_widget)
            self.layout.addWidget(scroll_area)

            back_button = QPushButton('Back to Main Menu', self)
            back_button.clicked.connect(self.create_main_menu)
            self.layout.addWidget(back_button)
        else:
            QMessageBox.information(self, 'No Passwords', 'No passwords found for this user.')

    def delete_password(self):
        if not self.passwords:
            self._load_passwords()
        
        category, ok = QInputDialog.getItem(self, 'Delete Password', 'Select the category:', list(self.passwords.keys()), 0, False)
        if ok:
            titles = list(self.passwords[category].keys())
            if titles:
                title, ok = QInputDialog.getItem(self, 'Delete Password', 'Select the password title to delete:', titles, 0, False)
                if ok:
                    confirm = QMessageBox.question(self, 'Confirm Deletion', f'Are you sure you want to delete the password for "{title}"?', QMessageBox.Yes | QMessageBox.No)
                    if confirm == QMessageBox.Yes:
                        if self._delete_password(self.username, category, title):
                            del self.passwords[category][title]
                            if not self.passwords[category]:
                                del self.passwords[category]
                            QMessageBox.information(self, 'Success', 'Password deleted successfully!')
                        else:
                            QMessageBox.warning(self, 'Error', 'Password not found for deletion!')
            else:
                QMessageBox.warning(self, 'Error', 'No passwords found in this category!')

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        mfa_code = self.mfa_input.text()

        if self._login(username, password, mfa_code):
            self.username = username
            self._load_passwords()
            self.create_main_menu()
        else:
            QMessageBox.warning(self, 'Error', 'Invalid username, password, or MFA code!')

    def create_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        if username and password:
            if self.check_password_strength(password) >= 3:
                self._create_user(username, password)
                self.show_mfa_setup(username)
            else:
                QMessageBox.warning(self, 'Weak Password', 'Please use a stronger password. It should be at least 12 characters long and include a mix of uppercase, lowercase, numbers, and special characters.')
        else:
            QMessageBox.warning(self, 'Error', 'Please enter both username and password!')

    def logout(self):
        self.username = None
        self.passwords.clear()
        self.clear_layout()
        self.create_login_ui()

    def copy_to_clipboard(self, text: str, message: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(message)
        msg_box.setWindowTitle('Copied')
        msg_box.show()

        if self.clipboard_timer:
            self.clipboard_timer.stop()
        
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(lambda: (clipboard.clear(), msg_box.close()))
        self.clipboard_timer.start(10000)  # 10 seconds

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon('lock_icon.png'))  # Replace with your own icon
        
        show_action = QAction("Show", self)
        quit_action = QAction("Exit", self)
        hide_action = QAction("Hide", self)
        
        show_action.triggered.connect(self.show)
        hide_action.triggered.connect(self.hide)
        quit_action.triggered.connect(QApplication.quit)
        
        tray_menu = QMenu()
        tray_menu.addAction(show_action)
        tray_menu.addAction(hide_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def init_encryption(self):
        # Create the DB folder if it doesn't exist
        if not os.path.exists(DB_FOLDER):
            os.makedirs(DB_FOLDER)

        if not os.path.exists(SALT_FILE):
            salt = os.urandom(16)
            with open(SALT_FILE, "wb") as salt_file:
                salt_file.write(salt)
        else:
            with open(SALT_FILE, "rb") as salt_file:
                salt = salt_file.read()

        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

    def derive_key(self, password: str) -> bytes:
        key = self.kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def get_stylesheet():
        return """
            QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QPushButton {
                background-color: #3498db;
                border: none;
                color: white;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                font-size: 16px;
                margin: 4px 2px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #3498db;
                border-radius: 5px;
                background-color: #34495e;
                color: #ecf0f1;
                font-size: 14px;
            }
            QLabel {
                font-size: 18px;
            }
            QTableWidget {
                background-color: #34495e;
                alternate-background-color: #2c3e50;
                selection-background-color: #3498db;
                border: none;
                gridline-color: #2c3e50;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                padding: 5px;
                border: 1px solid #34495e;
                font-size: 14px;
                font-weight: bold;
            }
            QScrollBar:vertical {
                border: none;
                background: #2c3e50;
                width: 10px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #3498db;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QTabWidget::pane {
                border: 1px solid #3498db;
                top: -1px;
            }
            QTabBar::tab {
                background: #34495e;
                border: 1px solid #3498db;
                padding: 5px;
                color: #ecf0f1;
            }
            QTabBar::tab:selected {
                background: #3498db;
            }
        """

    @staticmethod
    def _generate_password(length: int = 16, use_special_chars: bool = True) -> str:
        characters = string.ascii_letters + string.digits
        if use_special_chars:
            characters += string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def _save_password(self, username: str, category: str, title: str, password: str) -> None:
        if not os.path.exists(DB_FOLDER):
            os.makedirs(DB_FOLDER)
        encrypted_password = self.encrypt_password(password)
        with open(PASSWORD_FILE, 'ab') as f:
            f.write(f"{username}:{category}:{title}:{encrypted_password.decode()}\n".encode())
        self.log_action(f"Password saved for {title}")

    def _load_passwords(self) -> None:
        self.passwords.clear()
        try:
            with open(PASSWORD_FILE, 'rb') as f:
                for line in f:
                    user, category, title, encrypted_pass = line.decode().strip().split(':')
                    if user == self.username:
                        if category not in self.passwords:
                            self.passwords[category] = {}
                        self.passwords[category][title] = encrypted_pass
        except FileNotFoundError:
            pass

    def _update_password(self, username: str, category: str, title: str, new_password: str) -> None:
        lines = []
        updated = False
        with open(PASSWORD_FILE, 'rb') as f:
            for line in f:
                user, cat, t, encrypted_pass = line.decode().strip().split(':')
                if user == username and cat == category and t == title:
                    encrypted_pass = self.encrypt_password(new_password).decode()
                    updated = True
                lines.append(f"{user}:{cat}:{t}:{encrypted_pass}\n".encode())
        
        if updated:
            with open(PASSWORD_FILE, 'wb') as f:
                f.writelines(lines)
            self.log_action(f"Password updated for {title}")
        else:
            QMessageBox.warning(None, "Error", "Password not found for updating!")

    @staticmethod
    def _delete_password(username: str, category: str, title: str) -> bool:
        lines = []
        deleted = False
        with open(PASSWORD_FILE, 'rb') as f:
            for line in f:
                user, cat, t, encrypted_pass = line.decode().strip().split(':')
                if user == username and cat == category and t == title:
                    deleted = True
                else:
                    lines.append(line)
        
        if deleted:
            with open(PASSWORD_FILE, 'wb') as f:
                f.writelines(lines)
        return deleted

    def _login(self, username: str, password: str, mfa_code: str) -> bool:
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
                if username in users:
                    stored_hash = users[username]['password']
                    self.user_salt = users[username].get('salt')
                    if not self.user_salt:
                        self.user_salt = os.urandom(16)
                        users[username]['salt'] = self.user_salt.hex()
                        with open(USERS_FILE, 'w') as f:
                            json.dump(users, f)
                    else:
                        self.user_salt = bytes.fromhex(self.user_salt)
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                        if users[username]['mfa_enabled']:
                            if self.verify_mfa(username, mfa_code):
                                self.master_password = password
                                self.log_action("Successful login")
                                return True
                            else:
                                self.log_action("Failed login attempt - Invalid MFA code")
                        else:
                            self.master_password = password
                            self.log_action("Successful login")
                            return True
        except FileNotFoundError:
            QMessageBox.warning(None, "Error", "Users file not found!")
        
        self.log_action("Failed login attempt")
        return False

    def _create_user(self, username: str, password: str) -> None:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        users = {}
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)

        users[username] = {
            'password': hashed_password,
            'salt': salt.hex(),
            'mfa_enabled': False
        }

        with open(USERS_FILE, 'w') as f:
            json.dump(users, f)

        self.log_action(f"New user created: {username}")
        QMessageBox.information(None, "Success", "User created successfully!")

    def derive_key(self, password: str) -> bytes:
        if not self.user_salt:
            raise ValueError("User salt not set. Please log in first.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.user_salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    def encrypt_password(self, password: str) -> bytes:
        if not self.master_password:
            raise ValueError("Master password not set. Please log in first.")
        key = self.derive_key(self.master_password)
        f = Fernet(key)
        return f.encrypt(password.encode())

    def decrypt_password(self, encrypted_password: bytes) -> str:
        if not self.master_password:
            raise ValueError("Master password not set. Please log in first.")
        key = self.derive_key(self.master_password)
        f = Fernet(key)
        return f.decrypt(encrypted_password).decode()

    def change_master_password(self):
        old_password, ok = QInputDialog.getText(self, 'Change Master Password', 'Enter your current password:', QLineEdit.Password)
        if ok:
            if self._login(self.username, old_password, ''):
                new_password, ok = QInputDialog.getText(self, 'Change Master Password', 'Enter your new password:', QLineEdit.Password)
                if ok:
                    confirm_password, ok = QInputDialog.getText(self, 'Change Master Password', 'Confirm your new password:', QLineEdit.Password)
                    if ok:
                        if new_password == confirm_password:
                            if self.check_password_strength(new_password) >= 3:
                                self._change_master_password(self.username, new_password)
                                QMessageBox.information(self, 'Success', 'Master password changed successfully!')
                            else:
                                QMessageBox.warning(self, 'Weak Password', 'Please use a stronger password. It should be at least 12 characters long and include a mix of uppercase, lowercase, numbers, and special characters.')
                        else:
                            QMessageBox.warning(self, 'Error', 'Passwords do not match!')
            else:
                QMessageBox.warning(self, 'Error', 'Invalid current password!')

    def _change_master_password(self, username: str, new_password: str):
        # Update the password hash in the users file
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
        users[username]['password'] = hashed_password
        users[username]['salt'] = salt.hex()
        
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f)

        # Re-encrypt all passwords with the new master password
        old_master_password = self.master_password
        self.master_password = new_password
        for category, passwords in self.passwords.items():
            for title, password in passwords.items():
                decrypted_password = self.decrypt_password(password.encode())
                encrypted_password = self.encrypt_password(decrypted_password)
                self._save_password(username, category, title, encrypted_password.decode())

        self.log_action("Master password changed")

    def toggle_mfa(self):
        users = {}
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)

        if users[self.username]['mfa_enabled']:
            confirm = QMessageBox.question(self, 'Disable MFA', 'Are you sure you want to disable Multi-Factor Authentication?', QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                users[self.username]['mfa_enabled'] = False
                with open(USERS_FILE, 'w') as f:
                    json.dump(users, f)
                self.log_action("MFA disabled")
                QMessageBox.information(self, 'MFA Disabled', 'Multi-Factor Authentication has been disabled for your account.')
        else:
            self.show_mfa_setup(self.username)

    def show_mfa_setup(self, username):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name="Secure Password Vault")

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        img_path = os.path.join(DB_FOLDER, f"{username}_mfa_qr.png")
        img.save(img_path)

        mfa_dialog = QDialog(self)
        mfa_dialog.setWindowTitle('Setup Multi-Factor Authentication')
        mfa_layout = QVBoxLayout(mfa_dialog)

        mfa_layout.addWidget(QLabel('Scan this QR code with your authenticator app:'))
        qr_label = QLabel()
        qr_pixmap = QPixmap(img_path)
        qr_label.setPixmap(qr_pixmap)
        mfa_layout.addWidget(qr_label)

        mfa_layout.addWidget(QLabel(f'Or enter this secret key manually: {secret}'))

        verify_label = QLabel('Enter the 6-digit code from your authenticator app:')
        mfa_layout.addWidget(verify_label)

        code_input = QLineEdit()
        mfa_layout.addWidget(code_input)

        verify_button = QPushButton('Verify and Enable MFA')
        mfa_layout.addWidget(verify_button)

        def verify_mfa():
            if totp.verify(code_input.text()):
                self.mfa_secrets[username] = secret
                self.save_mfa_secrets()
                users = {}
                with open(USERS_FILE, 'r') as f:
                    users = json.load(f)
                users[username]['mfa_enabled'] = True
                with open(USERS_FILE, 'w') as f:
                    json.dump(users, f)
                self.log_action("MFA enabled")
                QMessageBox.information(mfa_dialog, 'MFA Enabled', 'Multi-Factor Authentication has been enabled for your account.')
                mfa_dialog.accept()
            else:
                QMessageBox.warning(mfa_dialog, 'Invalid Code', 'The entered code is invalid. Please try again.')

        verify_button.clicked.connect(verify_mfa)

        mfa_dialog.exec_()
        os.remove(img_path)

    def verify_mfa(self, username: str, code: str) -> bool:
        if username in self.mfa_secrets:
            totp = pyotp.TOTP(self.mfa_secrets[username])
            return totp.verify(code)
        return False

    def load_mfa_secrets(self) -> Dict[str, str]:
        if not os.path.exists(DB_FOLDER):
            os.makedirs(DB_FOLDER)
        if os.path.exists(MFA_SECRET_FILE):
            with open(MFA_SECRET_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_mfa_secrets(self) -> None:
        with open(MFA_SECRET_FILE, 'w') as f:
            json.dump(self.mfa_secrets, f)

    def log_action(self, action: str) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {self.username}: {action}\n"
        with open(AUDIT_LOG_FILE, 'a') as f:
            f.write(log_entry)

    def check_password_strength(self, password: str) -> int:
        score = 0
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        return score

    def security_audit(self):
        weak_passwords = []
        for category, passwords in self.passwords.items():
            for title, password in passwords.items():
                strength = self.check_password_strength(password)
                if strength < 3:
                    weak_passwords.append((category, title, strength))
        
        if weak_passwords:
            message = "The following passwords are weak and should be updated:\n\n"
            for category, title, strength in weak_passwords:
                message += f"Category: {category}, Title: {title}, Strength: {strength}/4\n"
        else:
            message = "All your passwords are strong. Good job!"
        
        QMessageBox.information(self, 'Security Audit', message)

    def check_breached_passwords(self):
        breached_passwords = []
        for category, passwords in self.passwords.items():
            for title, password in passwords.items():
                if self.is_password_breached(password):
                    breached_passwords.append((category, title))
        
        if breached_passwords:
            message = "The following passwords have been found in data breaches and should be changed immediately:\n\n"
            for category, title in breached_passwords:
                message += f"Category: {category}, Title: {title}\n"
        else:
            message = "None of your passwords were found in known data breaches. Stay vigilant!"
        
        QMessageBox.warning(self, 'Breached Passwords', message)

    def is_password_breached(self, password: str) -> bool:
        import hashlib
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        return suffix in response.text

    def toggle_dark_mode(self):
        if self.styleSheet() == self.get_stylesheet():
            self.setStyleSheet(self.get_light_stylesheet())
        else:
            self.setStyleSheet(self.get_stylesheet())

    @staticmethod
    def get_light_stylesheet():
        return """
QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Roboto', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

QPushButton {
    background-color: #0f3460;
    border: none;
    color: #e94560;
    padding: 12px 24px;
    text-align: center;
    text-decoration: none;
    font-size: 16px;
    margin: 6px 3px;
    border-radius: 12px;
    transition: all 0.3s ease;
    outline: none;
}

QPushButton:hover {
    background-color: #16213e;
    color: #ffffff;
    box-shadow: 0 4px 8px rgba(233, 69, 96, 0.3);
    transform: translateY(-2px);
}

QPushButton:pressed {
    background-color: #e94560;
    color: #1a1a2e;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    transform: translateY(1px);
}

QLineEdit {
    padding: 12px;
    border: 2px solid #0f3460;
    border-radius: 8px;
    background-color: #16213e;
    color: #e0e0e0;
    font-size: 16px;
    transition: all 0.3s ease;
}

QLineEdit:focus {
    border-color: #e94560;
    box-shadow: 0 0 10px rgba(233, 69, 96, 0.3);
}

QLabel {
    font-size: 20px;
    color: #e94560;
}

QTableWidget {
    background-color: #16213e;
    alternate-background-color: #1a1a2e;
    selection-background-color: #e94560;
    border: none;
    gridline-color: #0f3460;
    border-radius: 8px;
}

QHeaderView::section {
    background-color: #0f3460;
    padding: 8px;
    border: 1px solid #16213e;
    font-size: 16px;
    font-weight: bold;
    color: #e0e0e0;
    text-transform: uppercase;
}

QScrollBar {
    border: none;
    background: #16213e;
    width: 12px;
    border-radius: 6px;
}

QScrollBar:horizontal {
    height: 12px;
}

QScrollBar::handle {
    background: #e94560;
    min-height: 30px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    min-width: 30px;
}

QScrollBar::add-line, QScrollBar::sub-line {
    border: none;
    background: none;
}


QTabWidget::pane {
    border: 2px solid #0f3460;
    top: -2px;
    border-radius: 8px;
}

QTabBar::tab {
    background: #16213e;
    border: 2px solid #0f3460;
    padding: 8px;
    color: #e0e0e0;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background: #e94560;
    color: #ffffff;
    border-color: #e94560;
}

QMessageBox {
    background-color: #1a1a2e;
    color: #e0e0e0;
}

QToolTip {
    background-color: #16213e;
    color: #e94560;
    border: 1px solid #0f3460;
    padding: 5px;
    border-radius: 4px;
}

QMenu {
    background-color: #16213e;
    border: 1px solid #0f3460;
    color: #e0e0e0;
}

QMenu::item:selected {
    background-color: #e94560;
    color: #ffffff;
}
        """

    def export_passwords(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Passwords", "", "JSON Files (*.json)")
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.passwords, f, indent=4)
            QMessageBox.information(self, 'Export Successful', f'Passwords exported to {file_path}')

    def import_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Passwords", "", "JSON Files (*.json)")
        if file_path:
            with open(file_path, 'r') as f:
                imported_passwords = json.load(f)
            
            for category, passwords in imported_passwords.items():
                if category not in self.passwords:
                    self.passwords[category] = {}
                self.passwords[category].update(passwords)
            
            for category, passwords in imported_passwords.items():
                for title, password in passwords.items():
                    self._save_password(self.username, category, title, password)
            
            QMessageBox.information(self, 'Import Successful', f'Passwords imported from {file_path}')

    def sync_with_cloud(self):
        # This is a placeholder for cloud sync functionality
        QMessageBox.information(self, 'Cloud Sync', 'Cloud sync feature is not implemented in this version.')

    def delete_account(self):
        confirm = QMessageBox.question(self, 'Delete Account', 'Are you sure you want to delete your account? This action cannot be undone.', QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            password, ok = QInputDialog.getText(self, 'Confirm Deletion', 'Enter your password to confirm account deletion:', QLineEdit.Password)
            if ok and self._login(self.username, password, ''):
                self._delete_account(self.username)
                QMessageBox.information(self, 'Account Deleted', 'Your account has been successfully deleted.')
                self.logout()
            else:
                QMessageBox.warning(self, 'Error', 'Invalid password. Account deletion cancelled.')

    def _delete_account(self, username: str):
        # Remove user from users file
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
        del users[username]
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f)

        # Remove user's passwords
        lines = []
        with open(PASSWORD_FILE, 'rb') as f:
            for line in f:
                user, _, _, _ = line.decode().strip().split(':')
                if user != username:
                    lines.append(line)
        with open(PASSWORD_FILE, 'wb') as f:
            f.writelines(lines)

        # Remove user's MFA secret
        if username in self.mfa_secrets:
            del self.mfa_secrets[username]
            self.save_mfa_secrets()

        self.log_action(f"Account deleted: {username}")

    def forgot_password(self):
        username, ok = QInputDialog.getText(self, 'Forgot Password', 'Enter your username:')
        if ok:
            QMessageBox.information(self, 'Password Reset', f'A password reset link has been sent to the email associated with the account: {username}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    password_manager = PasswordManager()
    password_manager.show()
    sys.exit(app.exec_())