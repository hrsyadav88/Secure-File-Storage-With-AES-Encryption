import os
import sys
import json
import time
import hashlib
import base64
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Tuple
from getpass import getpass

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QFileDialog, QTextEdit, QLabel,
    QProgressBar, QTabWidget, QMessageBox, QInputDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('secure_storage.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CryptoUtils:
    """Utility class for cryptographic operations"""
    
    SALT_SIZE = 16
    IV_SIZE = 16
    KEY_LENGTH = 32
    ITERATIONS = 100000

    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Generate AES key from password using PBKDF2"""
        if not salt:
            salt = os.urandom(CryptoUtils.SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoUtils.KEY_LENGTH,
            salt=salt,
            iterations=CryptoUtils.ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    @staticmethod
    def encrypt_data(key: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-CBC"""
        iv = os.urandom(CryptoUtils.IV_SIZE)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv

    @staticmethod
    def decrypt_data(key: bytes, iv: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-256-CBC"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    @staticmethod
    def calculate_hash(data: bytes) -> str:
        """Calculate SHA-256 hash of data"""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

class SecureFile:
    """Class to handle secure file operations"""
    
    METADATA_EXTENSION = '.meta'
    ENCRYPTED_EXTENSION = '.enc'

    def __init__(self, storage_dir: str):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.fernet = None

    def initialize_fernet(self, password: str):
        """Initialize Fernet with derived key"""
        key, salt = CryptoUtils.generate_key(password)
        self.fernet = Fernet(base64.urlsafe_b64encode(key))
        
        # Store salt for future key derivation
        with open(self.storage_dir / '.salt', 'wb') as f:
            f.write(salt)

    def load_salt(self) -> bytes:
        """Load stored salt"""
        salt_file = self.storage_dir / '.salt'
        if salt_file.exists():
            with open(salt_file, 'rb') as f:
                return f.read()
        raise ValueError("Salt file not found")

    def encrypt_file(self, input_path: str, password: str) -> Tuple[str, str]:
        """Encrypt a file and store metadata"""
        try:
            input_path = Path(input_path)
            if not input_path.exists():
                raise FileNotFoundError(f"File {input_path} not found")

            # Read original file
            with open(input_path, 'rb') as f:
                data = f.read()

            # Calculate original hash
            original_hash = CryptoUtils.calculate_hash(data)

            # Initialize Fernet if not already done
            if not self.fernet:
                self.initialize_fernet(password)

            # Encrypt file content
            encrypted_data = self.fernet.encrypt(data)

            # Create metadata
            metadata = {
                'original_name': input_path.name,
                'timestamp': datetime.now().isoformat(),
                'original_hash': original_hash,
                'file_size': len(data)
            }
            
            # Generate output filenames
            timestamp = int(time.time())
            enc_filename = f"{timestamp}{self.ENCRYPTED_EXTENSION}"
            meta_filename = f"{timestamp}{self.METADATA_EXTENSION}"

            # Save encrypted file
            with open(self.storage_dir / enc_filename, 'wb') as f:
                f.write(encrypted_data)

            # Save encrypted metadata
            encrypted_metadata = self.fernet.encrypt(json.dumps(metadata).encode())
            with open(self.storage_dir / meta_filename, 'wb') as f:
                f.write(encrypted_metadata)

            logger.info(f"Successfully encrypted file: {input_path}")
            return str(self.storage_dir / enc_filename), original_hash

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt_file(self, enc_path: str, password: str, output_dir: str) -> str:
        """Decrypt a file with verification"""
        try:
            enc_path = Path(enc_path)
            meta_path = enc_path.with_suffix(self.METADATA_EXTENSION)
            
            if not enc_path.exists() or not meta_path.exists():
                raise FileNotFoundError("Encrypted file or metadata not found")

            # Initialize Fernet
            if not self.fernet:
                salt = self.load_salt()
                key, _ = CryptoUtils.generate_key(password, salt)
                self.fernet = Fernet(base64.urlsafe_b64encode(key))

            # Read and decrypt metadata
            with open(meta_path, 'rb') as f:
                encrypted_metadata = f.read()
            metadata = json.loads(self.fernet.decrypt(encrypted_metadata).decode())

            # Read and decrypt file
            with open(enc_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)

            # Verify hash
            current_hash = CryptoUtils.calculate_hash(decrypted_data)
            if current_hash != metadata['original_hash']:
                raise ValueError("File integrity check failed")

            # Save decrypted file
            output_path = Path(output_dir) / metadata['original_name']
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            logger.info(f"Successfully decrypted file: {output_path}")
            return str(output_path)

        except InvalidToken:
            logger.error("Invalid password or corrupted data")
            raise ValueError("Invalid password or corrupted data")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise

class EncryptionThread(QThread):
    """Thread for handling encryption/decryption operations"""
    
    progress = pyqtSignal(int)
    completed = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, secure_file: SecureFile, operation: str, **kwargs):
        super().__init__()
        self.secure_file = secure_file
        self.operation = operation
        self.kwargs = kwargs

    def run(self):
        try:
            if self.operation == 'encrypt':
                result, _ = self.secure_file.encrypt_file(**self.kwargs)
                self.completed.emit(f"File encrypted successfully: {result}")
            elif self.operation == 'decrypt':
                result = self.secure_file.decrypt_file(**self.kwargs)
                self.completed.emit(f"File decrypted successfully: {result}")
            
            # Simulate progress
            for i in range(0, 101, 10):
                self.progress.emit(i)
                time.sleep(0.1)
                
        except Exception as e:
            self.error.emit(str(e))

class SecureStorageApp(QMainWindow):
    """Main GUI application for secure file storage"""
    
    def __init__(self):
        super().__init__()
        self.secure_file = SecureFile(os.path.expanduser("~/SecureStorage"))
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Secure File Storage System")
        self.setGeometry(100, 100, 800, 600)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)

        # Encryption Tab
        enc_widget = QWidget()
        enc_layout = QVBoxLayout()
        enc_widget.setLayout(enc_layout)

        # File selection
        file_layout = QHBoxLayout()
        self.enc_file_input = QLineEdit()
        self.enc_file_input.setPlaceholderText("Select file to encrypt...")
        file_btn = QPushButton("Browse")
        file_btn.clicked.connect(self.browse_encrypt_file)
        file_layout.addWidget(self.enc_file_input)
        file_layout.addWidget(file_btn)
        enc_layout.addLayout(file_layout)

        # Password input
        pwd_layout = QHBoxLayout()
        self.enc_pwd_input = QLineEdit()
        self.enc_pwd_input.setEchoMode(QLineEdit.Password)
        self.enc_pwd_input.setPlaceholderText("Enter encryption password...")
        pwd_layout.addWidget(QLabel("Password:"))
        pwd_layout.addWidget(self.enc_pwd_input)
        enc_layout.addLayout(pwd_layout)

        # Encrypt button
        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.clicked.connect(self.start_encryption)
        enc_layout.addWidget(self.encrypt_btn)

        # Progress bar
        self.enc_progress = QProgressBar()
        enc_layout.addWidget(self.enc_progress)

        # Status
        self.enc_status = QTextEdit()
        self.enc_status.setReadOnly(True)
        enc_layout.addWidget(self.enc_status)

        tabs.addTab(enc_widget, "Encrypt")

        # Decryption Tab
        dec_widget = QWidget()
        dec_layout = QVBoxLayout()
        dec_widget.setLayout(dec_layout)

        # File selection
        dec_file_layout = QHBoxLayout()
        self.dec_file_input = QLineEdit()
        self.dec_file_input.setPlaceholderText("Select encrypted file (.enc)...")
        dec_file_btn = QPushButton("Browse")
        dec_file_btn.clicked.connect(self.browse_decrypt_file)
        dec_file_layout.addWidget(self.dec_file_input)
        dec_file_layout.addWidget(dec_file_btn)
        dec_layout.addLayout(dec_file_layout)

        # Output directory
        out_layout = QHBoxLayout()
        self.dec_out_input = QLineEdit()
        self.dec_out_input.setPlaceholderText("Select output directory...")
        out_btn = QPushButton("Browse")
        out_btn.clicked.connect(self.browse_output_dir)
        out_layout.addWidget(self.dec_out_input)
        out_layout.addWidget(out_btn)
        dec_layout.addLayout(out_layout)

        # Password input
        dec_pwd_layout = QHBoxLayout()
        self.dec_pwd_input = QLineEdit()
        self.dec_pwd_input.setEchoMode(QLineEdit.Password)
        self.dec_pwd_input.setPlaceholderText("Enter decryption password...")
        dec_pwd_layout.addWidget(QLabel("Password:"))
        dec_pwd_layout.addWidget(self.dec_pwd_input)
        dec_layout.addLayout(dec_pwd_layout)

        # Decrypt button
        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.clicked.connect(self.start_decryption)
        dec_layout.addWidget(self.decrypt_btn)

        # Progress bar
        self.dec_progress = QProgressBar()
        dec_layout.addWidget(self.dec_progress)

        # Status
        self.dec_status = QTextEdit()
        self.dec_status.setReadOnly(True)
        dec_layout.addWidget(self.dec_status)

        tabs.addTab(dec_widget, "Decrypt")

    def browse_encrypt_file(self):
        """Browse for file to encrypt"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.enc_file_input.setText(file_path)

    def browse_decrypt_file(self):
        """Browse for encrypted file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Encrypted File", filter="Encrypted Files (*.enc)"
        )
        if file_path:
            self.dec_file_input.setText(file_path)

    def browse_output_dir(self):
        """Browse for output directory"""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.dec_out_input.setText(dir_path)

    def start_encryption(self):
        """Start encryption process"""
        file_path = self.enc_file_input.text()
        password = self.enc_pwd_input.text()

        if not file_path or not password:
            QMessageBox.warning(self, "Error", "Please select a file and enter a password")
            return

        self.encrypt_btn.setEnabled(False)
        self.enc_progress.setValue(0)

        self.thread = EncryptionThread(
            self.secure_file,
            'encrypt',
            input_path=file_path,
            password=password
        )
        self.thread.progress.connect(self.enc_progress.setValue)
        self.thread.completed.connect(self.on_encryption_complete)
        self.thread.error.connect(self.on_error)
        self.thread.start()

    def start_decryption(self):
        """Start decryption process"""
        file_path = self.dec_file_input.text()
        output_dir = self.dec_out_input.text()
        password = self.dec_pwd_input.text()

        if not file_path or not output_dir or not password:
            QMessageBox.warning(self, "Error", "Please select a file, output directory, and enter a password")
            return

        self.decrypt_btn.setEnabled(False)
        self.dec_progress.setValue(0)

        self.thread = EncryptionThread(
            self.secure_file,
            'decrypt',
            enc_path=file_path,
            password=password,
            output_dir=output_dir
        )
        self.thread.progress.connect(self.dec_progress.setValue)
        self.thread.completed.connect(self.on_decryption_complete)
        self.thread.error.connect(self.on_error)
        self.thread.start()

    def on_encryption_complete(self, message: str):
        """Handle encryption completion"""
        self.enc_status.append(message)
        self.encrypt_btn.setEnabled(True)
        QMessageBox.information(self, "Success", message)

    def on_decryption_complete(self, message: str):
        """Handle decryption completion"""
        self.dec_status.append(message)
        self.decrypt_btn.setEnabled(True)
        QMessageBox.information(self, "Success", message)

    def on_error(self, error: str):
        """Handle errors"""
        self.enc_status.append(f"Error: {error}")
        self.dec_status.append(f"Error: {error}")
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", error)

def run_gui():
    """Run the GUI application"""
    app = QApplication(sys.argv)
    window = SecureStorageApp()
    window.show()
    sys.exit(app.exec_())

def run_cli():
    """Run the CLI interface"""
    parser = argparse.ArgumentParser(description="Secure File Storage System")
    parser.add_argument('--encrypt', help="Path to file to encrypt")
    parser.add_argument('--decrypt', help="Path to encrypted file (.enc)")
    parser.add_argument('--output', help="Output directory for decrypted file")
    parser.add_argument('--storage', default="~/SecureStorage", 
                       help="Storage directory for encrypted files")
    
    args = parser.parse_args()
    secure_file = SecureFile(os.path.expanduser(args.storage))

    if args.encrypt:
        password = getpass("Enter encryption password: ")
        try:
            enc_path, hash_val = secure_file.encrypt_file(args.encrypt, password)
            print(f"File encrypted successfully: {enc_path}")
            print(f"Original hash: {hash_val}")
        except Exception as e:
            print(f"Encryption failed: {str(e)}")
            sys.exit(1)

    elif args.decrypt and args.output:
        password = getpass("Enter decryption password: ")
        try:
            dec_path = secure_file.decrypt_file(args.decrypt, password, args.output)
            print(f"File decrypted successfully: {dec_path}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_cli()
    else:
        run_gui()