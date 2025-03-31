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
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify(self, peer_id, message, signature):
        pubkey_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")
        if not os.path.exists(pubkey_path):
            return False

        with open(pubkey_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def add_trusted_peer(self, peer_id, pubkey_bytes):
        os.makedirs(TRUSTED_KEYS_DIR, exist_ok=True)
        trusted_key_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")

        print(f"[DEBUG] Saving trusted key for {peer_id} to {trusted_key_path}")

        with open(trusted_key_path, "wb") as f:
            f.write(pubkey_bytes)

        print(f"[DEBUG] Successfully saved {peer_id}'s public key")