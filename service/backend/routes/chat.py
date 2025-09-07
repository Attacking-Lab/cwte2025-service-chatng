from flask import Blueprint, request, jsonify, current_app, url_for
from utils import verify_token, encrypt_data, decrypt_data, validate_key
from bot import bot_load, bot_reply
import os
import time

chat_bp = Blueprint("chat", __name__)
FEED_SHARE_KEY = os.getenv("FEED_SHARE_KEY", "forgot-your-key?")

@chat_bp.route("/send", methods=["POST"])
def send_message():
    username = verify_token()
    if not username:
        return jsonify({"msg": "Unauthorized"}), 401

    data = request.json
    text = str(data["text"]).strip()
    receiver = str(data["receiver"]).strip()

    if len(text) > 512:
        return jsonify({"msg": "Message too long"}), 500
    if len(receiver) > 256:
        return jsonify({"msg": "Receiver's username us too long"}), 500

    receiver_user = current_app.mongo.db.users.find_one({"username": receiver})
    if not receiver_user:
        return jsonify({"msg": "receiver was not found"}), 500

    if (username != receiver_user['username']) and (receiver_user['type'] == 'human') and (not (username in receiver_user['friends'])):
        return jsonify({"msg": "You are not a friend of the receiver"}), 500

    msg = {
        "sender": username,
        "receiver": receiver_user['username'],
        "text": text,
        "timestamp": time.time()
    }
    current_app.mongo.db.messages.insert_one(msg)

    if receiver_user['type'] == 'bot':
        last_msg = current_app.mongo.db.messages.find_one({"sender": receiver_user['username'], "receiver": username}, sort=[("_id", -1)])
        state = 'init' if not last_msg else last_msg['state']

        bot = bot_load(receiver_user, username, state)
        if not bot:
            reply = '[Failed to load bot.]'
        else:
            reply, state = bot_reply(bot, text)
        
        msg = {
            "sender": receiver_user['username'],
            "receiver": username,
            "text": reply,
            "state": state,
            "timestamp": time.time()
        }
        current_app.mongo.db.messages.insert_one(msg)

    return jsonify({"msg": "Message sent"})

@chat_bp.route("/inbox", methods=["GET"])
def inbox():
    username = verify_token()
    if not username:
        return jsonify({"msg": "Unauthorized"}), 401

    msgs = list(current_app.mongo.db.messages.find({"$or": [
        {"receiver": username},
        {"sender": username}
    ]}))
    return jsonify(msgs)

@chat_bp.route("/shared/<code>", methods=["GET"])
def shared_feed(code):
    try:
        validate_key(FEED_SHARE_KEY)
    except Exception as e:
        return jsonify({"msg": "Server Error"}), 401

    sender = None
    receiver = None
    try:
        data = decrypt_data(code, FEED_SHARE_KEY)
        if 'n' in data:
            sender = data["n"]
            receiver = data["n"]
        else:
            sender = data["s"]
            receiver = data["r"]
    except Exception as e:
        return jsonify({"msg": "Invalid or corrupted link"}), 400

    msgs = list(current_app.mongo.db.messages.find({
        "receiver": receiver,
        "sender": sender
    }))
    return jsonify(msgs)

@chat_bp.route("/share", methods=["POST"])
def share_feed():
    username = verify_token()
    if not username:
        return jsonify({"msg": "Unauthorized"}), 401

    try:
        validate_key(FEED_SHARE_KEY)
    except Exception as e:
        return jsonify({"msg": "Server Error"}), 401

    data = request.json
    sender = str(data["sender"]).strip()
    receiver = str(data["receiver"]).strip()

    if (sender != username and receiver != username):
        return jsonify({"msg": "Unauthorized"}), 401

    if sender == receiver:
        share_data = {"n": sender}
    else:
        share_data = {"s": sender, "r": receiver}

    code = encrypt_data(share_data, FEED_SHARE_KEY)
    url = url_for("chat.shared_feed", code=code)
    return jsonify({"url": url})
