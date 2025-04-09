import threading
from datetime import datetime
import socket
import netifaces

class PeerManager:
    """Manages tracking of connected peers including their status and connection count."""

    def __init__(self, local_peer_id=None):
        self.peers = {}
        self.local_peer_id = local_peer_id  # Store local peer ID
        self.local_peer_ip = self.get_local_ip()  # Get current machine's IP
        self.lock = threading.Lock()

    def get_local_ip(self):
    #Gets the local machine's IP address with fallback
        try:
        # Method 1: UDP connection (original)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            try:
            # Method 2: Hostname lookup
                return socket.gethostbyname(socket.gethostname())
            except:
            # Method 3: Network interface detection
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if not addr['addr'].startswith('127.'):
                                return addr['addr']
                return "127.0.0.1"
    def get_peers(self):
        """Returns a copy of all peers including local"""
        with self.lock:
            all_peers = {pid: info.copy() for pid, info in self.peers.items()}
            
            # Add local peer entry
            if self.local_peer_id:
                all_peers[self.local_peer_id] = {
                    'ip': self.local_peer_ip,
                    'connection_count': 'N/A (Self)',
                    'last_seen': 'N/A (Self)',
                    'status': 'This Device'
                }
            return all_peers


    def add_peer(self, peer_id, ip):
        """Adds or updates a peer's connection information."""
        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]['connection_count'] += 1
                self.peers[peer_id]['last_seen'] = datetime.now()
            else:
                self.peers[peer_id] = {
                    'ip': ip,
                    'connection_count': 1,
                    'last_seen': datetime.now()
                }

    def remove_peer(self, peer_id):
        """Decrements connection count and removes peer if no active connections."""
        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]['connection_count'] -= 1
                if self.peers[peer_id]['connection_count'] <= 0:
                    del self.peers[peer_id]
                else:
                    self.peers[peer_id]['last_seen'] = datetime.now()