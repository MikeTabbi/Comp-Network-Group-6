import socket
import threading
import os

HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5002  # Port for file transfer
BUFFER_SIZE = 4096

# Directory to store files
FILE_DIR = "shared_files"
os.makedirs(FILE_DIR, exist_ok=True)


def handle_error(message, exception):
    """Prints a standardized error message."""
    print(f"[-] {message}: {exception}")


def handle_client(conn, addr):
    """Handles incoming file requests from peers."""
    print(f"[+] Connection from {addr}")
    try:
        filename = conn.recv(BUFFER_SIZE).decode()
        filepath = os.path.join(FILE_DIR, filename)

        if os.path.exists(filepath):
            conn.send(b'OK')
            with open(filepath, 'rb') as f:
                while chunk := f.read(BUFFER_SIZE):
                    conn.send(chunk)
            print(f"[+] File '{filename}' sent to {addr}")
        else:
            conn.send(b'NOT_FOUND')
            print(f"[-] File '{filename}' not found")
    except Exception as e:
        handle_error("Client Handling Error", e)
    finally:
        conn.close()


def start_server():
    """Starts the peer in server mode to listen for file requests."""
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
        handle_error("Server Error", e)
    finally:
        server.close()


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
                    if not chunk:
                        break
                    f.write(chunk)
            print(f"[+] File '{filename}' downloaded successfully.")
        else:
            print("[-] File not found on the peer.")
    except Exception as e:
        handle_error("File Request Error", e)
    finally:
        client.close()


if __name__ == "__main__":
    # Start server thread
    threading.Thread(target=start_server, daemon=True).start()

    while True:
        command = input("Enter command (get <peer_ip> <filename>): ").strip()
        if command.startswith("get"):
            try:
                _, peer_ip, filename = command.split()
                request_file(peer_ip, filename)
            except ValueError:
                print("[-] Invalid command format. Use: get <peer_ip> <filename>")
        else:
            print("Invalid command. Use: get <peer_ip> <filename>")
