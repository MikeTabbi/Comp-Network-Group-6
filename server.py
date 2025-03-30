# server.py

import socket
import threading
import os

# Server settings
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5002  # Port for file transfer
BUFFER_SIZE = 4096  # Size of data chunks

# Directory to store files
FILE_DIR = "shared_files"
os.makedirs(FILE_DIR, exist_ok=True)


def handle_client(conn, addr):
    """Handles incoming file requests from peers."""
    print(f"[+] Connection from {addr}")
    try:
        # Receive filename from client
        filename = conn.recv(BUFFER_SIZE).decode()
        filepath = os.path.join(FILE_DIR, filename)

        # Check if file exists
        if os.path.exists(filepath):
            conn.send(b'OK')  # Acknowledge file availability
            # Read file in chunks and send
            with open(filepath, 'rb') as f:
                while chunk := f.read(BUFFER_SIZE):
                    conn.send(chunk)
            print(f"[+] File '{filename}' sent to {addr}")
        else:
            conn.send(b'NOT_FOUND')
            print(f"[-] File '{filename}' not found")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()  # Close connection


def start_server():
    """Starts the peer in server mode to listen for file requests."""

    # Including User Story 1: Error Handling
    try:
        # Creating a socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Binding the socket
        server.bind((HOST, PORT))
        # Listening for a connection with backlog 5
        server.listen(5)
        # Message displaying that it's listening
        print(f"[*] Listening on {HOST}:{PORT}...")

        # Loop to allow multiple connections
        while True:
            conn, addr = server.accept()
            # Creating a new thread for the connection
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            # Start the thread
            thread.start()
    except Exception as e:
        print(f"[-] Server Error: {e}")
    finally:
        server.close()  # Ensure socket is closed on exit



if __name__ == "__main__":
    start_server()
