import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# ======================================
# SAFETY WARNINGS
# ======================================
print("[!] WARNING: This script is for educational purposes only.")
print("[!] NEVER run this on files without explicit permission and backups.\n")

# ======================================
# KEY GENERATION (Password-Based)
# ======================================
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ======================================
# ENCRYPT/DECRYPT FUNCTIONS
# ======================================
def encrypt_file(file_path: str, key: bytes):
    """Encrypt a file using AES and delete the original."""
    with open(file_path, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(file_path + '.encrypted', 'wb') as f:
        f.write(encrypted)

    os.remove(file_path)  # Delete original (use with caution!)

def decrypt_file(encrypted_path: str, key: bytes):
    """Decrypt a file and restore the original."""
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return

    original_path = encrypted_path.replace('.encrypted', '')
    with open(original_path, 'wb') as f:
        f.write(decrypted)

    os.remove(encrypted_path)

# ======================================
# MAIN (User-Interactive)
# ======================================
def main():
    action = input("Choose action [encrypt/decrypt]: ").strip().lower()
    password = input("Enter password: ").strip()
    salt = os.urandom(16)  # Random salt for key derivation

    # Derive key from password
    key = derive_key(password, salt)

    if action == "encrypt":
        target_files = [f for f in os.listdir() if f.endswith('.bak')]
        if not target_files:
            print("[!] No .bak files found.")
            return

        print(f"Found {len(target_files)} .bak files.")
        confirm = input("Encrypt these files? (y/n): ").strip().lower()

        if confirm == 'y':
            for file in target_files:
                encrypt_file(file, key)
                print(f"Encrypted: {file}")

    elif action == "decrypt":
        target_files = [f for f in os.listdir() if f.endswith('.encrypted')]
        if not target_files:
            print("[!] No encrypted files found.")
            return

        print(f"Found {len(target_files)} encrypted files.")
        confirm = input("Decrypt these files? (y/n): ").strip().lower()

        if confirm == 'y':
            for file in target_files:
                decrypt_file(file, key)
                print(f"Decrypted: {file}")

if __name__ == "__main__":
    main()