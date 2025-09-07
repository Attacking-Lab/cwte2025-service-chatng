import jwt
import json
from flask import request, current_app
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import random
import string

def generate_token(username):
    return jwt.encode({"username": username}, current_app.config["JWT_SECRET"], algorithm="HS256")

def verify_token():
    token = request.headers.get("Authorization")
    if not token:
        return None
    try:
        data = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
        return data["username"]
    except:
        return None

def validate_key(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

def encrypt_data(data, key):
    if isinstance(key, str):
        key = key.encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(json.dumps(data).encode(), AES.block_size))
    iv = binascii.hexlify(cipher.iv).decode()
    ct = binascii.hexlify(ct_bytes).decode()
    return iv + ct

def decrypt_data(code, key):
    if isinstance(key, str):
        key = key.encode()
    iv = binascii.unhexlify(code[:32])
    ct = binascii.unhexlify(code[32:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return json.loads(pt.decode())

def random_name(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))
