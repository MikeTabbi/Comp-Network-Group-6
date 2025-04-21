import threading
import socket
from datetime import datetime, timedelta


class PeerManager:
    """Tracks connected peers with detailed info and health checks"""

    def __init__(self, local_peer_id=None):
        self.peers = {}  # {peer_id: {ip: str, last_seen: datetime, status: str}}
        self.local_peer_id = local_peer_id
        self.lock = threading.Lock()
        self.keepalive_interval = 300  # 5 minutes

        # Start background cleaner
        threading.Thread(target=self._cleanup_old_peers, daemon=True).start()

    def get_local_ip(self):
        """Get the LAN IP address of the current machine"""
        try:
            # Connect to a dummy address to determine active interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google DNS
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"  # Fallback
    def add_peer(self, peer_id, ip):
        """Add/update a connected peer"""
        with self.lock:
            self.peers[peer_id] = {
                'ip': ip,
                'last_seen': datetime.now(),
                'status': 'Connected'
            }

    def remove_peer(self, peer_id):
        """Remove a disconnected peer"""
        with self.lock:
            self.peers.pop(peer_id, None)

    def update_last_seen(self, peer_id):
        """Update last seen timestamp for keepalive"""
        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]['last_seen'] = datetime.now()

    def _cleanup_old_peers(self):
        """Background thread to remove stale peers"""
        while True:
            with self.lock:
                now = datetime.now()
                stale_peers = [
                    peer_id for peer_id, info in self.peers.items()
                    if now - info['last_seen'] > timedelta(seconds=self.keepalive_interval)
                       and peer_id != self.local_peer_id
                ]
                for peer_id in stale_peers:
                    self.peers[peer_id]['status'] = 'Disconnected'

            threading.Event().wait(60)  # Check every minute

    def get_peers(self):
        """Get all peers including local with formatted data"""
        with self.lock:
            peers = self.peers.copy()

            if self.local_peer_id:
                peers[self.local_peer_id] = {
                    'ip': self.get_local_ip(),  # <-- Use detected IP
                    'last_seen': datetime.now(),
                    'status': 'This Device'
                }

            return peers

    def get_online_peers(self):
        """Get only currently connected peers"""
        with self.lock:
            return {
                peer_id: info for peer_id, info in self.peers.items()
                if info['status'] == 'Connected' or peer_id == self.local_peer_id
            }