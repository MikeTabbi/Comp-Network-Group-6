# client.py

import socket
import os

# Client settings
PORT = 5002  # Port used to connect to the peer
BUFFER_SIZE = 4096  # Size of data chunks
FILE_DIR = "shared_files"
os.makedirs(FILE_DIR, exist_ok=True)


def request_file(peer_ip, filename):
    """Requests a file from another peer."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect to peer
        client.connect((peer_ip, PORT))
        # Send filename to peer
        client.send(filename.encode())

        # Wait for response
        response = client.recv(BUFFER_SIZE)
        if response == b'OK':
            # If peer has file, receive and write it
            filepath = os.path.join(FILE_DIR, filename)
            with open(filepath, 'wb') as f:
                while True:
                    chunk = client.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
            print(f"[+] File '{filename}' downloaded successfully.")
        else:
            print("[-] File not found on the peer.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client.close()  # Always close connection


if __name__ == "__main__":
    # Input loop for user to request files
    while True:
        command = input("Enter command (get <peer_ip> <filename>): ").strip()
        if command.startswith("get"):
            try:
                _, peer_ip, filename = command.split()
                request_file(peer_ip, filename)
            except ValueError:
                print("[-] Usage: get <peer_ip> <filename>")
        else:
            print("Invalid command. Use: get <peer_ip> <filename>")
