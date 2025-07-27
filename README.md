# 🔐 Secure File Storage with AES Encryption

A secure file storage system with AES-256 encryption, built using Python and PyQt5. This application allows users to encrypt and decrypt files through an intuitive GUI or command-line interface (CLI), ensuring data privacy and integrity.

---

## 🧰 Features

- ✅ AES-256-CBC encryption with password-based key derivation (PBKDF2)
- ✅ Automatic file hashing (SHA-256) for integrity verification
- ✅ Metadata storage and management
- ✅ GUI (PyQt5) with progress indicators and error handling
- ✅ CLI support for scripting and automation
- ✅ Threaded encryption/decryption to keep the UI responsive
- ✅ Logging for operational transparency

---

## 📦 Dependencies

Make sure these packages are installed:

```bash
pip install pyqt5 cryptography
```

---

## 🚀 How to Run

### ▶️ GUI Mode

```bash
python Secure_File_Storage_With_AES_Encryption.py
```

This will launch a full-featured graphical interface to:
- Select files to encrypt or decrypt
- Enter passwords
- Monitor progress and status messages

---

### 🖥️ CLI Mode

Use the app from terminal:

#### 🔒 To Encrypt a File:

```bash
python Secure_File_Storage_With_AES_Encryption.py --encrypt /path/to/input.txt
```

You'll be prompted to enter a password. The encrypted file and metadata will be saved in `~/SecureStorage` by default.

#### 🔓 To Decrypt a File:

```bash
python Secure_File_Storage_With_AES_Encryption.py --decrypt /path/to/encrypted_file.enc --output /path/to/output_folder
```

You'll be prompted for the encryption password.

---

## 📁 File Structure

```
📦 Secure_File_Storage_With_AES_Encryption.py
📂 ~/SecureStorage/
   ┣ 📄 [timestamp].enc        → Encrypted data
   ┣ 📄 [timestamp].meta       → Encrypted metadata (original name, hash, etc.)
   ┗ 📄 .salt                  → Salt for password-based key derivation
```

---

## 🛡️ Security Details

- **Encryption:** AES-256 in CBC mode
- **Key Derivation:** PBKDF2-HMAC-SHA256 with random 16-byte salt
- **Padding:** PKCS7
- **Hashing:** SHA-256 for file integrity
- **Fernet:** Used for securely storing metadata

---

## 🛠️ Logging

All major actions and errors are logged into:

```
secure_storage.log
```

This helps with monitoring, debugging, and auditing.

---

## 📸 Screenshots

> *(Add screenshots of your GUI here if needed)*

---

## 📄 License

This project is intended for educational and research purposes only. Always use strong passwords and avoid storing sensitive data insecurely.

---

## 🙋 Author

**Harsh Yadav**  
 
