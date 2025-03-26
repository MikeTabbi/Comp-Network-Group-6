# Peer Connection
This is a basic peer-to-peer (P2P) registration setup using Python and Flask.

# What It Does
When a new device connects, it’s added to a peer table. The server then responds with a list of all devices currently connected.
In simpler terms, it helps a device say “I’m here” and find out who else is around.

# How It Works
- A device locates a node (server)
- It sends a POST request to `/register` with its `device_id`
- The server checks if the device is already in the peer table
- If not, it adds it and responds with a list of all peers

# How to Run It
1. Open GitHub Codespaces
2. Run the server:
   ```bash
   python server.py
Open a new terminal and run the device:

bash
Copy
Edit
python device.py
To simulate more devices:

Change the device_id value in device.py

Run it again to register another device

Example Output
json
Copy
Edit
{
  "message": "Device registered successfully.",
  "peers": ["device_001", "device_002"]
}
🔧 Built With
Python 3

Flask

Requests
---

# 5. **Save the file**  
Hit `CTRL + S` or just click **File > Save**

---

### 6. **Commit & Push to GitHub**

In the terminal, run:
```bash
git add README.md
git commit -m "Updated README with project overview and working example"
git push origin main
