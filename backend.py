from flask import Flask, request, jsonify
from flask_socketio import SocketIO
import hashlib
import time
import sqlite3

# ========== Blockchain and Database ==========

class Block:
    def __init__(self, index, timestamp, file_hash, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.file_hash = file_hash
        self.previous_hash = previous_hash
        self.current_hash = self.compute_hash()

    def compute_hash(self):
        return hashlib.sha256(
            f"{self.index}{self.timestamp}{self.file_hash}{self.previous_hash}".encode()
        ).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.db_path = 'blockchain.db'
        self.load_from_db()

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), "Genesis", "0")
        self.chain.append(genesis_block)
        self.save_block(genesis_block)

    def add_block(self, file_hash):
        last_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            file_hash=file_hash,
            previous_hash=last_block.current_hash,
        )
        self.chain.append(new_block)
        self.save_block(new_block)

    def is_file_in_chain(self, file_hash):
        return any(block.file_hash == file_hash for block in self.chain)

    def connect_db(self):
        return sqlite3.connect(self.db_path)

    def save_block(self, block):
        conn = self.connect_db()
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS blocks (
                        `index` INTEGER PRIMARY KEY,
                        timestamp REAL,
                        file_hash TEXT,
                        previous_hash TEXT,
                        current_hash TEXT)''')
        c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?)", (
            block.index, block.timestamp, block.file_hash, block.previous_hash, block.current_hash))
        conn.commit()
        conn.close()

    def load_from_db(self):
        conn = self.connect_db()
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blocks'")
        if not c.fetchone():
            self.create_genesis_block()
            conn.close()
            return
        c.execute("SELECT * FROM blocks ORDER BY `index`")
        rows = c.fetchall()
        for row in rows:
            block = Block(*row[:4])
            block.current_hash = row[4]
            self.chain.append(block)
        conn.close()

def compute_file_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

# ========== Flask Server Setup ==========

blockchain = Blockchain()
peers = set()

app = Flask(__name__)
socketio = SocketIO(app)

@app.route("/connect", methods=["POST"])
def connect_peer():
    peer = request.json.get("peer")
    if peer:
        peers.add(peer)
        return jsonify({"message": f"Connected to peer {peer}"}), 201
    return jsonify({"error": "Invalid peer"}), 400

@app.route("/verify", methods=["POST"])
def verify_file():
    file_hash = request.json.get("file_hash")
    return jsonify({"is_in_chain": blockchain.is_file_in_chain(file_hash)}), 200

@app.route("/blocks", methods=["GET"])
def get_blocks():
    return jsonify([
        {
            "index": b.index,
            "timestamp": b.timestamp,
            "file_hash": b.file_hash,
            "previous_hash": b.previous_hash,
            "current_hash": b.current_hash
        } for b in blockchain.chain
    ])

def run_flask_server(port=5000):
    socketio.run(app, port=port, host="0.0.0.0", debug=False, use_reloader=False)
