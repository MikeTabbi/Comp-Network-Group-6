import socket
import threading
import time
from datetime import datetime, timedelta

TRACKER_HOST = '0.0.0.0'
TRACKER_PORT = 5003
PEER_TIMEOUT = 30  # Seconds until peer is considered offline

class PeerTracker:
    def __init__(self):
        self.peers = {}  # {ip: last_seen_time}
        self.lock = threading.Lock()
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def update_peer(self, ip):
        with self.lock:
            self.peers[ip] = datetime.now()

    def get_peers(self):
        with self.lock:
            return {
                ip: "Online" if (datetime.now() - last_seen).seconds < PEER_TIMEOUT 
                else "Offline"
                for ip, last_seen in self.peers.items()
            }

    def _cleanup_loop(self):
        while True:
            time.sleep(PEER_TIMEOUT)
            with self.lock:
                now = datetime.now()
                self.peers = {ip: t for ip, t in self.peers.items() 
                            if (now - t) < timedelta(seconds=PEER_TIMEOUT)}

# SINGLE SHARED TRACKER INSTANCE
tracker = PeerTracker()

def handle_client(conn, addr):
    try:
        data = conn.recv(1024).decode().strip()
        client_ip = addr[0]

        if data == 'HEARTBEAT':
            tracker.update_peer(client_ip)
            conn.send(b'ACK')
        elif data == 'LIST':
            peers = tracker.get_peers()
            response = "\n".join([f"{ip} - {status}" for ip, status in peers.items()])
            conn.send(response.encode())
        else:
            conn.send(b'Invalid command')
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def start_tracker_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((TRACKER_HOST, TRACKER_PORT))
    server.listen(5)
    print(f"[*] Tracker running on {TRACKER_PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_tracker_server()