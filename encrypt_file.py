from cryptography.fernet import Fernet
import os


class FileEncryptor:
    def __init__(self, key_path="secret.key"):
        self.key_path = key_path
        if not os.path.exists(self.key_path):
            self._generate_key()
        self.key = self._load_key()
        self.fernet = Fernet(self.key)

    def _generate_key(self):
        """Generate and save a new encryption key"""
        key = Fernet.generate_key()
        with open(self.key_path, "wb") as key_file:
            key_file.write(key)

    def _load_key(self):
        """Load the encryption key from file"""
        with open(self.key_path, "rb") as key_file:
            return key_file.read()

    def encrypt_file(self, input_path, output_path=None):
        """Encrypt a file"""
        if output_path is None:
            output_path = input_path + ".enc"

        with open(input_path, "rb") as file:
            original = file.read()

        encrypted = self.fernet.encrypt(original)

        with open(output_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted)

        return output_path

    def decrypt_file(self, input_path, output_path=None):
        """Decrypt a file"""
        if output_path is None:
            output_path = input_path.replace(".enc", "") if input_path.endswith(".enc") else input_path + ".dec"

        with open(input_path, "rb") as file:
            encrypted = file.read()

        decrypted = self.fernet.decrypt(encrypted)

        with open(output_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted)

        return output_path
