import socket  # Provides network communication capabilities
import threading  # Allows multiple clients to be served concurrently
import os  # Manages file operations
import datetime  # Adds timestamps to logs
import json
from encrypt_file import FileEncryptor
from peer_manager import PeerManager
from inspect import signature
from config import KEYS_DIR, TRUSTED_KEYS_DIR
from cryptography.hazmat.primitives import serialization
from Authentication import PeerAuthenticator
from password_lock import set_password_for_file, unlock_file_with_password

HOST = '0.0.0.0'
PORT = 5001
NOTIFY_PORT = 5002
BUFFER_SIZE = 4096
CHALLENGE_SIZE = 32
FILE_DIR = "shared_files"
LOG_FILE = "sync_log.txt"
os.makedirs(FILE_DIR, exist_ok=True)
connected_peers = set()

def log_event(peer, filename, action):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | {peer} | {filename} | {action}\n"
    with open(LOG_FILE, "a") as log:
        log.write(log_entry)
    print(f"[LOG] {log_entry.strip()}")
    notify_peers(filename, action)

def notify_peers(filename, action):
    timestamp = datetime.datetime.now().isoformat()
    notification = json.dumps({"filename": filename, "action": action, "timestamp": timestamp})
    for peer_ip in list(connected_peers):
        try:
            notify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            notify_socket.connect((peer_ip, NOTIFY_PORT))
            notify_socket.send(notification.encode())
            notify_socket.close()
        except Exception:
            print(f"[-] Failed to notify {peer_ip}, removing from peer list.")
            connected_peers.remove(peer_ip)

def handle_client(conn, addr, authenticator):
    print(f"[+] Connection from {addr}")
    try:
        peer_id = conn.recv(BUFFER_SIZE).decode()
        pubkey_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")
        if not os.path.exists(pubkey_path):
            conn.send(b'AUTH_FAILED')
            print(f"[-] Unknown peer: {peer_id}")
            return
        challenge = os.urandom(CHALLENGE_SIZE).hex()
        conn.send(challenge.encode('utf-8'))
        signature = conn.recv(BUFFER_SIZE).decode()
        if not authenticator.verify(peer_id, challenge, signature):
            conn.send(b'AUTH_FAILED')
            print(f"[-] Authentication failed for {peer_id}@{addr}")
            log_event(addr[0], "AUTH", "FAILED")
            return
        conn.send(b'AUTH_SUCCESS')
        print(f"[+] Authenticated {peer_id}@{addr}")
        log_event(addr[0], "AUTH", "SUCCESS")
        peer_manager.add_peer(peer_id, addr[0])
        connected_peers.add(addr[0])
        filename = conn.recv(BUFFER_SIZE).decode()
        filepath = os.path.join(FILE_DIR, filename)
        if os.path.exists(filepath):
            try:
                conn.send(b'OK')
                encrypted_temp = os.path.join(FILE_DIR, f"temp_{filename}.enc")
                try:
                    encryptor.encrypt_file(filepath, encrypted_temp)
                    with open(encrypted_temp, 'rb') as f:
                        while chunk := f.read(BUFFER_SIZE):
                            conn.send(chunk)
                    print(f"[+] Encrypted file '{filename}' sent to {addr}")
                    log_event(addr[0], filename, "SENT_ENCRYPTED")
                except Exception as encrypt_error:
                    print(f"[-] Encryption failed: {encrypt_error}")
                    log_event(addr[0], filename, f"ENCRYPT_ERROR: {encrypt_error}")
                    conn.send(b'TRANSFER_ERROR')
                finally:
                    if os.path.exists(encrypted_temp):
                        os.remove(encrypted_temp)
            except Exception as transfer_error:
                print(f"[-] Transfer failed: {transfer_error}")
                log_event(addr[0], filename, f"TRANSFER_ERROR: {transfer_error}")
        else:
            conn.send(b'NOT_FOUND')
            print(f"[-] File '{filename}' not found")
            log_event(addr[0], filename, "NOT_FOUND")
    except Exception as e:
        print(f"[-] Connection error: {e}")
        log_event(addr[0], "CONNECTION", f"ERROR: {e}")
    finally:
        conn.close()

def start_server(authenticator):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}...")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, authenticator))
        thread.start()

def start_notification_listener():
    notify_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    notify_server.bind((HOST, NOTIFY_PORT))
    notify_server.listen(5)
    print(f"[*] Listening for notifications on {HOST}:{NOTIFY_PORT}...")
    while True:
        conn, addr = notify_server.accept()
        threading.Thread(target=handle_notifications, args=(conn, addr)).start()

def handle_notifications(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if data:
            notification = json.loads(data)
            print(f"[NOTIFICATION] File '{notification['filename']}' was {notification['action']}")
    except Exception as e:
        print(f"[-] Notification error: {e}")
    finally:
        conn.close()

def request_file(authenticator, peer_ip, peer_id, filename):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encrypted_temp = os.path.join(FILE_DIR, f"temp_{filename}.enc")
    filepath = os.path.join(FILE_DIR, filename)
    try:
        print(f"[*] Attempting to connect to {peer_ip}:{PORT}...")
        client.connect((peer_ip, PORT))
        print("[+] Connected to peer.")
        client.send(authenticator.peer_id.encode())
        challenge = client.recv(BUFFER_SIZE).decode('utf-8')
        print(f"[CLIENT] Received authentication challenge")
        signature = authenticator.sign(challenge)
        client.send(signature.encode('utf-8'))
        auth_response = client.recv(BUFFER_SIZE)
        if auth_response != b'AUTH_SUCCESS':
            print("[-] Authentication failed")
            log_event(peer_ip, filename, "AUTH_FAILED")
            return
        client.send(filename.encode())
        response = client.recv(BUFFER_SIZE)
        if response == b'OK':
            try:
                with open(encrypted_temp, 'wb') as f:
                    while True:
                        chunk = client.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                try:
                    encryptor.decrypt_file(encrypted_temp, filepath)
                    print(f"[+] File '{filename}' downloaded and decrypted successfully.")
                    log_event(peer_ip, filename, "RECEIVED_DECRYPTED")
                except Exception as decrypt_error:
                    print(f"[-] Decryption failed: {decrypt_error}")
                    log_event(peer_ip, filename, f"DECRYPT_ERROR: {decrypt_error}")
                    if os.path.exists(filepath):
                        os.remove(filepath)
            except Exception as transfer_error:
                print(f"[-] Transfer failed: {transfer_error}")
                log_event(peer_ip, filename, f"TRANSFER_ERROR: {transfer_error}")
            finally:
                if os.path.exists(encrypted_temp):
                    os.remove(encrypted_temp)
        elif response == b'NOT_FOUND':
            print("[-] File not found on the peer.")
            log_event(peer_ip, filename, "NOT_FOUND")
        else:
            print(f"[-] Unexpected response: {response}")
            log_event(peer_ip, filename, f"UNKNOWN_RESPONSE: {response}")
    except Exception as e:
        print(f"[-] Error: {e}")
        log_event(peer_ip, filename, f"ERROR: {e}")
    finally:
        client.close()
        if 'encrypted_temp' in locals() and os.path.exists(encrypted_temp):
            os.remove(encrypted_temp)

def track_file_changes():
    existing_files = {}
    for file in os.listdir(FILE_DIR):
        filepath = os.path.join(FILE_DIR, file)
        if os.path.isfile(filepath):
            existing_files[file] = os.path.getmtime(filepath)
    while True:
        current_files = set(os.listdir(FILE_DIR))
        for file in current_files - existing_files.keys():
            filepath = os.path.join(FILE_DIR, file)
            if os.path.isfile(filepath):
                existing_files[file] = os.path.getmtime(filepath)
                log_event("LOCAL", file, "CREATED")
        for file in set(existing_files.keys()) - current_files:
            log_event("LOCAL", file, "DELETED")
            existing_files.pop(file, None)
        for file in current_files & existing_files.keys():
            filepath = os.path.join(FILE_DIR, file)
            if os.path.isfile(filepath):
                current_mtime = os.path.getmtime(filepath)
                if current_mtime != existing_files[file]:
                    existing_files[file] = current_mtime
                    log_event("LOCAL", file, "MODIFIED")
        threading.Event().wait(5)

def trust_peer(peer_id, key_filename):
    key_path = os.path.join(KEYS_DIR, key_filename)
    trusted_key_path = os.path.join(TRUSTED_KEYS_DIR, f"{peer_id}_pub.pem")
    if not os.path.exists(key_path):
        print(f"[-] Error: Key file '{key_filename}' not found in {KEYS_DIR}.")
        return
    try:
        with open(key_path, "rb") as key_file:
            public_key = key_file.read()
        with open(trusted_key_path, "wb") as trusted_key_file:
            trusted_key_file.write(public_key)
        print(f"[+] Trusted peer '{peer_id}'. Key saved as {trusted_key_path}.")
    except Exception as e:
        print(f"[-] Error trusting peer: {e}")

if __name__ == "__main__":
    peer_id = input("Enter your peer ID: ").strip()
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(TRUSTED_KEYS_DIR, exist_ok=True)
    authenticator = PeerAuthenticator(peer_id)
    peer_manager = PeerManager(local_peer_id=peer_id)
    encryptor = FileEncryptor()
    threading.Thread(target=start_server, args=(authenticator,), daemon=True).start()
    threading.Thread(target=track_file_changes, daemon=True).start()
    threading.Thread(target=start_notification_listener, daemon=True).start()
    while True:
        command = input("Enter command (get, trust, list, lock, unlock): ").strip()
        if command.startswith("get"):
            try:
                _, peer_ip, remote_peer_id, filename = command.split()
                request_file(authenticator, peer_ip, remote_peer_id, filename)
            except ValueError:
                print("Invalid format. Use: get <peer_ip> <peer_id> <filename>")
        elif command.startswith("trust"):
            try:
                _, peer_id, key_filename = command.split()
                trust_peer(peer_id, key_filename)
            except ValueError:
                print("Invalid format. Use: trust <peer_id> <key_filename>")
        elif command == "list":
            print("\n=== Connected Peers ===")
            for peer_id, info in peer_manager.get_peers().items():
                print(f"{peer_id} | {info['ip']} | {info['status']} | Last seen: {info['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
            print()
        elif command.startswith("lock"):
            try:
                _, filename, password = command.split()
                filepath = os.path.join(FILE_DIR, filename)
                if os.path.exists(filepath):
                    set_password_for_file(filepath, password)
                else:
                    print("[-] File not found.")
            except ValueError:
                print("Usage: lock <filename> <password>")
        elif command.startswith("unlock"):
            try:
                _, filename, password = command.split()
                filepath = os.path.join(FILE_DIR, filename)
                if os.path.exists(filepath):
                    unlock_file_with_password(filepath, password)
                else:
                    print("[-] File not found.")
            except ValueError:
                print("Usage: unlock <filename> <password>")
            except Exception as e:
                print(f"[-] Unlock failed: {e}")
        else:
            print("Commands:")
            print("  get <peer_ip> <peer_id> <filename> - Download file")
            print("  trust <peer_id> <key_filename> - Trust a peer's key")
            print("  list - Show connected peers")
            print("  lock <filename> <password> - Lock a file with a password")
            print("  unlock <filename> <password> - Unlock a password-protected file")
