from werkzeug.security import generate_password_hash, check_password_hash

def create_user(mongo, username, password):
    users = mongo.db.users
    if users.find_one({"username": username}):
        return False
    users.insert_one({
        "username": username,
        "password": generate_password_hash(password),
        "type": "human",
        "friends": []
    })
    return True

def create_bot(mongo, username, owner, token):
    users = mongo.db.users
    if users.find_one({"username": username}):
        return False
    users.insert_one({
        "username": username,
        "token": token,
        "createdby": owner,
        "type": "bot"
    })
    return True

def validate_user(mongo, username, password):
    user = mongo.db.users.find_one({"username": username, "type": "human"})
    if user and check_password_hash(user["password"], password):
        return user
    return None
