# Peer Connection
This is a basic P2P registration setup using Python and Flask.

## What It Does
When a new device connects, it's added to the peer table. The device then gets a list of all other connected devices.

In simpler terms, it helps a device say "I'm here" and find out who else is present too.

### How It Works
- A device locates a node (the server)
- It sends a POST request to `/register` with its device ID
- The node checks if that device is already in the peer list
- If not, it adds it to the list and responds with all registered peers

#### How to Run It
1. Open GitHub Codespaces.
2. Run the server:
   ```bash
   python server.py
