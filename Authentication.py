import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from config import KEYS_DIR, TRUSTED_KEYS_DIR



class PeerAuthenticator:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.private_key, self.public_key = self._load_or_generate_keys()

        # DEBUG: Print this peer's public key
        print(f"[DEBUG] {self.peer_id}'s Public Key:\n{self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")
    def _load_or_generate_keys(self):
        os.makedirs(KEYS_DIR, exist_ok=True)
        priv_path = os.path.join(KEYS_DIR, f"{self.peer_id}_priv.pem")
        pub_path = os.path.join(KEYS_DIR, f"{self.peer_id}_pub.pem")

        if os.path.exists(priv_path):
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), None)
            with open(pub_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
        else:
            private_key = rsa.generate_private_key(65537, 2048)
            public_key = private_key.public_key()
            self._save_key(priv_path, private_key)
            self._save_key(pub_path, public_key)

        return private_key, public_key

    def _save_key(self, path, key):
        if isinstance(key, rsa.RSAPrivateKey):
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(path, "wb") as f:
            f.write(key_bytes)

    def sign(self, message):
        # Ensure consistent UTF-8 encoding
        message_bytes = message.encode('utf-8')  # Explicit encoding

        signature = self.private_key.sign(
            message_bytes,  # Use the encoded bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify(self, peer_id, message, signature):
        pubkey_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")
        print(f"[AUTH] Looking for {peer_id}'s key at: {pubkey_path}")
    
        if not os.path.exists(pubkey_path):
            print(f"[AUTH] Key not found!")  # Debug
            return False
    
        with open(pubkey_path, "rb") as f:
            key_data = f.read()  # Read ONCE and store
            print(f"[AUTH] Key content:\n{key_data.decode()}")  # Debug print
            
            try:
                public_key = serialization.load_pem_public_key(key_data)
            except ValueError as e:
                print(f"[AUTH] Invalid key format: {e}")  # Debug
                return False
    
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            print(f"[AUTH] Verification SUCCESS")  # Debug
            return True
        except InvalidSignature:
            print(f"[AUTH] Invalid signature!")  # Debug
            return False
        except Exception as e:
            print(f"[AUTH] Verification error: {e}")  # Debug
            return False

    def add_trusted_peer(self, peer_id, pubkey_bytes):
        os.makedirs(TRUSTED_KEYS_DIR, exist_ok=True)
        trusted_key_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")

        print(f"[DEBUG] Saving trusted key for {peer_id} to {trusted_key_path}")

        with open(trusted_key_path, "wb") as f:
            f.write(pubkey_bytes)

        print(f"[DEBUG] Successfully saved {peer_id}'s public key")