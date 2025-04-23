import os
import json
from cryptography.fernet import Fernet

# File to store password-key mappings
PASSWORDS_FILE = "file_passwords.json"

# Load existing mappings or initialize new dictionary
if os.path.exists(PASSWORDS_FILE):
    with open(PASSWORDS_FILE, "r") as f:
        FILE_PASSWORDS = json.load(f)
else:
    FILE_PASSWORDS = {}

def save_passwords():
    """Saves the FILE_PASSWORDS dictionary to disk."""
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(FILE_PASSWORDS, f)

def set_password_for_file(filename, password):
    """
    Encrypts a file using a generated Fernet key.
    Stores the key along with the password for later unlocking.
    """
    key = Fernet.generate_key()
    fernet = Fernet(key)

    # Read original file contents
    with open(filename, 'rb') as file:
        original = file.read()

    # Encrypt file contents
    encrypted = fernet.encrypt(original)

    # Overwrite file with encrypted contents
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    # Save password and key mapping
    FILE_PASSWORDS[filename] = {
        "password": password,
        "key": key.decode()
    }
    save_passwords()
    print(f"[+] File '{filename}' locked with password.")

def unlock_file_with_password(filename, password_attempt):
    """
    Attempts to decrypt a file using the stored key if the password is correct.
    """
    if filename not in FILE_PASSWORDS:
        raise Exception("File is not password protected.")

    record = FILE_PASSWORDS[filename]
    if password_attempt != record["password"]:
        raise Exception("Incorrect password.")

    key = record["key"].encode()
    fernet = Fernet(key)

    # Read encrypted file contents
    with open(filename, 'rb') as enc_file:
        encrypted_data = enc_file.read()

    # Decrypt file contents
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write decrypted data back to file
    with open(filename, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    print(f"[+] File '{filename}' successfully unlocked.")
