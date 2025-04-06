import requests
from flask import Flask, request, jsonify, send_file
import sys

app = Flask(__name__)

# Customize peer details
peer_id = sys.argv[1] if len(sys.argv) > 1 else "Peer1"
peer_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5001  # Default to 5001 if not provided

file_chunks = {
    "chunk1": "path_to_chunk1.txt",
    "chunk2": "path_to_chunk2.txt"
}

# Use the exact URL for your server
server_url = 'https://effective-lamp-7xpr5q94j943p45w-5000.app.github.dev/register'

try:
    response = requests.post(server_url, json={
        "device_id": peer_id,
        "file_chunks": list(file_chunks.keys())
    })
    if response.status_code == 200:
        print(f"{peer_id} registered successfully!")
    else:
        print(f"Registration failed with status code {response.status_code}: {response.text}")
except requests.ConnectionError:
    print("Error: Unable to connect to the server. Make sure server.py is running.")

@app.route('/download/<chunk_name>', methods=['GET'])
def download(chunk_name):
    if chunk_name in file_chunks:
        return send_file(file_chunks[chunk_name], as_attachment=True)
    else:
        return jsonify({"error": "Chunk not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=peer_port)
