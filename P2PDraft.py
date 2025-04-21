import socket  # Provides network communication capabilities
import threading  # Allows multiple clients to be served concurrently
import os  # Manages file operations
import datetime  # Adds timestamps to logs
import json

HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5001       # Port for file transfer
NOTIFY_PORT = 5002  # Port for sending notifications
BUFFER_SIZE = 4096  # Amount of data read at once when sending/receiving files

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
    notification = json.dumps({"filename": filename, "action": action})

    for peer_ip in list(connected_peers):  # Iterate over connected peers
        try:
            notify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            notify_socket.connect((peer_ip, NOTIFY_PORT))
            notify_socket.send(notification.encode())
            notify_socket.close()
        except Exception:
            print(f"[-] Failed to notify {peer_ip}, removing from peer list.")
            connected_peers.remove(peer_ip)  # Remove unreachable peers

def handle_client(conn, addr):
    """Handles incoming file requests from peers."""
    print(f"[+] Connection from {addr}")
    try:
        filename = conn.recv(BUFFER_SIZE).decode()  # Receives the filename requested
        filepath = os.path.join(FILE_DIR, filename)  # Constructs the full file path

        if os.path.exists(filepath):  # If the file exists
            conn.send(b'OK')
            with open(filepath, 'rb') as f:
                while chunk := f.read(BUFFER_SIZE):
                    conn.send(chunk)
            print(f"[+] File '{filename}' sent to {addr}")
            log_event(addr[0], filename, "SENT")
        else:
            conn.send(b'NOT_FOUND')
            print(f"[-] File '{filename}' not found")
            log_event(addr[0], filename, "NOT_FOUND")
    except Exception as e:
        print(f"[-] Error: {e}")
        log_event(addr[0], "UNKNOWN", f"ERROR: {e}")
    finally:
        conn.close()

def start_server():
    """Starts the peer in server mode to listen for file requests."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Listening on {HOST}:{PORT}...")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
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

def request_file(peer_ip, filename):
    """Requests a file from another peer."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((peer_ip, PORT))
        client.send(filename.encode())

        response = client.recv(BUFFER_SIZE)
        if response == b'OK':
            filepath = os.path.join(FILE_DIR, filename)
            with open(filepath, 'wb') as f:
                while chunk := client.recv(BUFFER_SIZE):
                    f.write(chunk)
            print(f"[+] File '{filename}' downloaded successfully.")
            log_event(peer_ip, filename, "RECEIVED")
        else:
            print("[-] File not found on the peer.")
            log_event(peer_ip, filename, "NOT_FOUND")
    except Exception as e:
        print(f"[-] Error: {e}")
        log_event(peer_ip, filename, f"ERROR: {e}")
    finally:
        client.close()

def track_file_changes():
    """Monitors file changes (creation, modification, deletion)."""
    existing_files = set(os.listdir(FILE_DIR))

    while True:
        current_files = set(os.listdir(FILE_DIR))

        # Detect new files
        for file in current_files - existing_files:
            log_event("LOCAL", file, "CREATED")

        # Detect deleted files
        for file in existing_files - current_files:
            log_event("LOCAL", file, "DELETED")

        # Detect modifications
        for file in current_files & existing_files:
            file_path = os.path.join(FILE_DIR, file)
            if os.path.isfile(file_path):
                last_modified = os.path.getmtime(file_path)
                with open(LOG_FILE, "r") as log:
                    if f"MODIFIED | {file}" not in log.read():
                        log_event("LOCAL", file, "MODIFIED")

        existing_files = current_files  # Update existing files list
        threading.Event().wait(5)  # Check every 5 seconds

if __name__ == "__main__":
    # Start server thread
    threading.Thread(target=start_server, daemon=True).start()

    # Start file tracking thread
    threading.Thread(target=track_file_changes, daemon=True).start()

    while True:
        command = input("Enter command (get <peer_ip> <filename>): ").strip()
        if command.startswith("get"):
            _, peer_ip, filename = command.split()
            request_file(peer_ip, filename)
        else:
            print("Invalid command. Use: get <peer_ip> <filename>")
