from flask import Flask, send_file, request
import os

app = Flask(__name__)
PEER_PORT = 5001  
SHARED_DIR = "shared"

@app.route('/get_chunk')
def get_chunk():
    chunk_name = request.args.get('name')
    chunk_path = os.path.join(SHARED_DIR, chunk_name)
    if os.path.exists(chunk_path):
        return send_file(chunk_path, as_attachment=True)
    else:
        return "Chunk not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PEER_PORT)
