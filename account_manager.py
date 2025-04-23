import json
import os
import hashlib

CREDENTIALS_FILE = "user_credentials.json"

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    with open(CREDENTIALS_FILE, "r") as file:
        return json.load(file)

def save_credentials(creds):
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(creds, file)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_peer(peer_id, password):
    creds = load_credentials()
    if peer_id in creds:
        return False  # Peer already exists
    creds[peer_id] = hash_password(password)
    save_credentials(creds)
    return True

def authenticate_peer(peer_id, password):
    creds = load_credentials()
    if peer_id not in creds:
        return False  # Unknown peer
    return creds[peer_id] == hash_password(password)

def peer_exists(peer_id):
    creds = load_credentials()
    return peer_id in creds
