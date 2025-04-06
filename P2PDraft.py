import socket
import threading
import os
import datetime
import json
import hashlib
import sys

HOST = '0.0.0.0'
PORT = 8080
NOTIFY_PORT = 5005
BUFFER_SIZE = 4096

FILE_DIR = "shared_files"
LOG_FILE = "sync_log.txt"
os.makedirs(FILE_DIR, exist_ok=True)

connected_peers = set()

def smart_input(prompt_text):
    """Secure input that falls back to visible if needed."""
    try:
        import getpass
        if sys.stdin.isatty():
            return getpass.getpass(prompt_text)
        else:
            raise Exception()
    except:
        print("Warning: Password input may be echoed.")
        return input(prompt_text)

def handle_error(context, exception):
    error_message = f"{context}: {exception}"
    print(f"[-] {error_message}")
    log_event("LOCAL", "ERROR", error_message)

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
        except Exception as e:
            handle_error(f"Notify failure for {peer_ip}", e)
            connected_peers.remove(peer_ip)

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        connected_peers.add(addr[0])
        filename = conn.recv(BUFFER_SIZE).decode()
        filepath = os.path.join(FILE_DIR, filename)

        # looking for .lock to see if the file is locked
        lock_path = filepath + ".lock"
        if os.path.exists(lock_path):
            # an alert letting the client know the file is protected
            conn.send(b'LOCKED')
            # get a password
            client_pass = conn.recv(BUFFER_SIZE).decode()
            hashed_input = hashlib.sha256(client_pass.encode()).hexdigest()
            with open(lock_path, "r") as f:
                stored_hash = f.read().strip()
            # check if hashed input matches the stored hash
            if hashed_input != stored_hash:
                # wrong password, no file
                conn.send(b'AUTH_FAILED')
                print("[-] Incorrect password attempt.")
                log_event(addr[0], filename, "AUTH_FAILED")
                return
            else:
                # file access given
                conn.send(b'AUTH_SUCCESS')
        else:
            # unlocked file
            conn.send(b'UNLOCKED')

        # sends file
        if os.path.exists(filepath):
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
        handle_error(f"Client error from {addr}", e)
        log_event(addr[0], "UNKNOWN", f"ERROR: {e}")
    finally:
        conn.close()

def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[*] Listening on {HOST}:{PORT}...")
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except Exception as e:
        handle_error("Server start failed", e)

def start_notification_listener():
    try:
        notify_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        notify_server.bind((HOST, NOTIFY_PORT))
        notify_server.listen(5)
        print(f"[*] Listening for notifications on {HOST}:{NOTIFY_PORT}...")
        while True:
            conn, addr = notify_server.accept()
            threading.Thread(target=handle_notifications, args=(conn, addr)).start()
    except Exception as e:
        handle_error("Notification listener failed", e)

def handle_notifications(conn, addr):
    try:
        data = conn.recv(BUFFER_SIZE).decode()
        if data:
            notification = json.loads(data)
            print(f"[NOTIFICATION] File '{notification['filename']}' was {notification['action']}")
    except Exception as e:
        handle_error(f"Notification error from {addr}", e)
    finally:
        conn.close()

def request_file(peer_ip, filename):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((peer_ip, PORT))
        client.send(filename.encode())

        # looking for locked file
        lock_status = client.recv(BUFFER_SIZE)
        if lock_status == b'LOCKED':
            password = smart_input("Enter password for locked file: ")
            client.send(password.encode())
            auth_result = client.recv(BUFFER_SIZE)
            if auth_result != b'AUTH_SUCCESS':
                print("[-] Incorrect password. Access denied.")
                return
        elif lock_status != b'UNLOCKED':
            print("[-] Unexpected response from server.")
            return

        # downloads the file
        response = client.recv(BUFFER_SIZE)
        if response == b'OK':
            filepath = os.path.join(FILE_DIR, filename)
            with open(filepath, 'wb') as f:
                while True:
                    chunk = client.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
            print(f"[+] File '{filename}' downloaded successfully.")
            log_event(peer_ip, filename, "RECEIVED")
        else:
            print("[-] File not found on the peer.")
            log_event(peer_ip, filename, "NOT_FOUND")
    except Exception as e:
        handle_error(f"Request to {peer_ip}", e)
        log_event(peer_ip, filename, f"ERROR: {e}")
    finally:
        client.close()

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

def lock_file(filename):
    """
    locks a file with a password by creating a .lock file containing a hashed password.
    When another peer tries to access this file, they will need to enter the correct password.
    """
    filepath = os.path.join(FILE_DIR, filename)
    lock_path = filepath + ".lock"

    if not os.path.exists(filepath):
        print("[-] File does not exist.")
        return

    if os.path.exists(lock_path):
        print("[-] File is already locked.")
        return

    password = smart_input("Enter a password to lock the file: ")
    hashed = hashlib.sha256(password.encode()).hexdigest()

    # save the hash to a .lock file next to the original
    with open(lock_path, "w") as f:
        f.write(hashed)

    print(f"[+] '{filename}' is now password protected.")

if __name__ == "__main__":
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=track_file_changes, daemon=True).start()
    threading.Thread(target=start_notification_listener, daemon=True).start()

    while True:
        command = input("Enter command (get <peer_ip> <filename> | lock <filename>): ").strip()
        if command.startswith("get"):
            try:
                _, peer_ip, filename = command.split()
                request_file(peer_ip, filename)
            except ValueError:
                print("Invalid format. Use: get <peer_ip> <filename>")
        elif command.startswith("lock"):
            try:
                _, filename = command.split()
                lock_file(filename)
            except ValueError:
                print("Invalid format. Use: lock <filename>")
        else:
            print("Commands:")
            print("  get <peer_ip> <filename> - Download file")
            print("  lock <filename>          - Password protect a file")
