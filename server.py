# Python example
import datetime
import sqlite3
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Connect to the database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Generate RSA Private Key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Expiration times
now = int(datetime.datetime.now().timestamp())
in_one_hour = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

# Insert keys into the database (one expired, one valid)
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_key_pem.decode('utf-8'), now))
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_key_pem.decode('utf-8'), in_one_hour))
conn.commit()

from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')
    current_time = int(time.time())
    
    # Select appropriate key
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp <= ?", (current_time,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))

    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "No valid key found"}), 404

    private_key = row[0]
    token = jwt.encode({"username": "userABC"}, private_key, algorithm="RS256")
    return jsonify({"token": token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    current_time = int(time.time())
    cursor.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    
    jwks = {
        "keys": [{"kid": i + 1, "key": row[0]} for i, row in enumerate(rows)]
    }
    return jsonify(jwks)

app.run(host="0.0.0.0", port=8080)
