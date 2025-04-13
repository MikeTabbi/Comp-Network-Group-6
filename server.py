from flask import Flask, request, jsonify

app = Flask(__name__)

# Fake peer table for now
peer_table = []

@app.route('/register', methods=['POST'])
def register():
    new_peer = request.json.get('device_id')
    if new_peer not in peer_table:
        peer_table.append(new_peer)
    return jsonify({
        "message": "Device registered successfully.",
        "peers": peer_table
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
