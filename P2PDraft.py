import socket  # Provides network communication capabilities
import threading  # Allows multiple clients to be served concurrently
import os  # Manages file operations
import datetime  # Adds timestamps to logs
import json
from encrypt_file import FileEncryptor
from peer_manager import PeerManager
from config import KEYS_DIR, TRUSTED_KEYS_DIR
from Authentication import PeerAuthenticator
from account_manager import register_peer, authenticate_peer, peer_exists
import getpass

HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5001   # Port for file transfer
NOTIFY_PORT = 5002 # Port for sending notifications
BUFFER_SIZE = 4096  # Amount of data read at once when sending/receiving files


# Security Configuration
CHALLENGE_SIZE = 32
# Directory to store shared files
FILE_DIR = "shared_files"
LOG_FILE = "sync_log.txt"  # Log file to track file changes
os.makedirs(FILE_DIR, exist_ok=True)  # Prevents an error if the directory already exists

# Set to store connected peers
connected_peers = set()

def log_event(peer, filename, action):
    """Logs file events with timestamps, peer IP, and action."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | {peer} | {filename} | {action}\n"

    with open(LOG_FILE, "a") as log:
        log.write(log_entry)

    print(f"[LOG] {log_entry.strip()}")
    notify_peers(filename, action)  # Notify all peers about the event

def notify_peers(filename, action):
    """Sends a notification to all registered peers about a file update."""
    timestamp = datetime.datetime.now().isoformat()
    notification = json.dumps({"filename": filename, "action": action, "timestamp": timestamp})

    for peer_ip in list(connected_peers):  # Iterate over connected peers
        try:
            notify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            notify_socket.connect((peer_ip, NOTIFY_PORT))
            notify_socket.send(notification.encode())
            notify_socket.close()
        except Exception:
            print(f"[-] Failed to notify {peer_ip}, removing from peer list.")
            connected_peers.remove(peer_ip)  # Remove unreachable peers


def handle_client(conn, addr, authenticator):
    """Handles incoming file requests from peers with encryption."""
    print(f"[+] Connection from {addr}")

    try:
        # Authentication phase
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

        # File transfer phase
        filename = conn.recv(BUFFER_SIZE).decode()
        filepath = os.path.join(FILE_DIR, filename)

        if os.path.exists(filepath):
            try:
                conn.send(b'OK')

                # Create temporary encrypted file
                encrypted_temp = os.path.join(FILE_DIR, f"temp_{filename}.enc")
                try:
                    encryptor.encrypt_file(filepath, encrypted_temp)

                    # Send encrypted file
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
                    # Clean up temporary file
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
    """Starts the peer in server mode to listen for file requests."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr, authenticator))
        thread.start()

def start_notification_listener():
    """Starts a server to listen for notifications from other peers."""
    notify_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    notify_server.bind((HOST, NOTIFY_PORT))
    notify_server.listen(5)
    print(f"[*] Listening for notifications on {HOST}:{NOTIFY_PORT}...")

    while True:
        conn, addr = notify_server.accept()
        threading.Thread(target=handle_notifications, args=(conn, addr)).start()

def handle_notifications(conn, addr):
    """Handles incoming notifications from peers and displays them."""
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
    """Requests and receives an encrypted file from another peer, then decrypts it."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encrypted_temp = os.path.join(FILE_DIR, f"temp_{filename}.enc")
    filepath = os.path.join(FILE_DIR, filename)

    try:
        print(f"[*] Attempting to connect to {peer_ip}:{PORT}...")
        client.connect((peer_ip, PORT))
        print("[+] Connected to peer.")

        # Authentication phase
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

        # File request phase
        client.send(filename.encode())
        response = client.recv(BUFFER_SIZE)

        if response == b'OK':
            try:
                # Receive encrypted file
                with open(encrypted_temp, 'wb') as f:
                    while True:
                        chunk = client.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)

                # Decrypt and verify
                try:
                    encryptor.decrypt_file(encrypted_temp, filepath)
                    print(f"[+] File '{filename}' downloaded and decrypted successfully.")
                    log_event(peer_ip, filename, "RECEIVED_DECRYPTED")

                except Exception as decrypt_error:
                    print(f"[-] Decryption failed: {decrypt_error}")
                    log_event(peer_ip, filename, f"DECRYPT_ERROR: {decrypt_error}")
                    if os.path.exists(filepath):
                        os.remove(filepath)  # Remove potentially corrupted file

            except Exception as transfer_error:
                print(f"[-] Transfer failed: {transfer_error}")
                log_event(peer_ip, filename, f"TRANSFER_ERROR: {transfer_error}")

            finally:
                # Clean up temporary files
                if os.path.exists(encrypted_temp):
                    os.remove(encrypted_temp)

        elif response == b'NOT_FOUND':
            print("[-] File not found on the peer.")
            log_event(peer_ip, filename, "NOT_FOUND")
        else:
            print(f"[-] Unexpected response: {response}")
            log_event(peer_ip, filename, f"UNKNOWN_RESPONSE: {response}")

    except ConnectionRefusedError:
        print(f"[-] Connection refused by {peer_ip}:{PORT}")
        log_event(peer_ip, "CONNECTION", "REFUSED")
    except socket.timeout:
        print(f"[-] Connection timeout with {peer_ip}")
        log_event(peer_ip, "CONNECTION", "TIMEOUT")
    except Exception as e:
        print(f"[-] Error: {e}")
        log_event(peer_ip, filename, f"ERROR: {e}")

    finally:
        client.close()
        # Final cleanup in case of any interruptions
        if 'encrypted_temp' in locals() and os.path.exists(encrypted_temp):
            os.remove(encrypted_temp)

def track_file_changes():
    """Monitors file changes (creation, modification, deletion)."""
    existing_files = {}

    # Initialize with file modification times
    for file in os.listdir(FILE_DIR):
        filepath = os.path.join(FILE_DIR, file)
        if os.path.isfile(filepath):
            existing_files[file] = os.path.getmtime(filepath)

    while True:
        current_files = set(os.listdir(FILE_DIR))

        # Detect new files
        for file in current_files - existing_files.keys():
            filepath = os.path.join(FILE_DIR, file)
            if os.path.isfile(filepath):
                existing_files[file] = os.path.getmtime(filepath)
                log_event("LOCAL", file, "CREATED")

        # Detect deleted files
        for file in set(existing_files.keys()) - current_files:
            log_event("LOCAL", file, "DELETED")
            existing_files.pop(file, None)

        # Detect modifications
        for file in current_files & existing_files.keys():
            filepath = os.path.join(FILE_DIR, file)
            if os.path.isfile(filepath):
                current_mtime = os.path.getmtime(filepath)
                if current_mtime != existing_files[file]:  # Only log if changed
                    existing_files[file] = current_mtime
                    log_event("LOCAL", file, "MODIFIED")

        threading.Event().wait(5)  # Check every 5 seconds



def trust_peer(peer_id, key_filename):
    """Adds a peer's public key to the trusted keys directory."""
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

    # 🔐 Check if peer exists
    if peer_exists(peer_id):
        print(f"🔐 Peer '{peer_id}' found. Please authenticate.")
        password = getpass.getpass("Enter your password: ")
        if authenticate_peer(peer_id, password):
            print("✅ Authentication successful.")
        else:
            print("❌ Incorrect password. Exiting.")
            exit(1)
    else:
        print(f"👤 New peer '{peer_id}' detected.")
        password = getpass.getpass("Set your password: ")
        confirm = getpass.getpass("Confirm your password: ")
        if password != confirm:
            print("❌ Passwords do not match. Exiting.")
            exit(1)
        if register_peer(peer_id, password):
            print("✅ Peer registered successfully.")
        else:
            print("❌ Failed to register peer. Exiting.")
            exit(1)

    # 📁 Ensure necessary directories exist
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(TRUSTED_KEYS_DIR, exist_ok=True)

    # 🔐 Initialize components
    authenticator = PeerAuthenticator(peer_id, password)
    peer_manager = PeerManager(local_peer_id=peer_id)
    encryptor = FileEncryptor()

    # 🚀 Start server and background threads
    threading.Thread(target=start_server, args=(authenticator,), daemon=True).start()
    threading.Thread(target=track_file_changes, daemon=True).start()
    threading.Thread(target=start_notification_listener, daemon=True).start()

    # 🧭 Main loop
    while True:
        command = input("Enter command (get <peer_ip> <peer_id> <filename>): ").strip()
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
                print(
                    f"{peer_id} | {info['ip']} | {info['status']} | Last seen: {info['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
            print()
        elif command == "exit" or command == "logout":
            print("👋 Logging out and exiting...")
            break
        else:
            print("Commands:")
            print("  get <peer_ip> <peer_id> <filename> - Download file")

