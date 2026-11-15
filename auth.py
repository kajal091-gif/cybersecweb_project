import os, json

USER_FILE = "users.json"

# Load users from file
if os.path.exists(USER_FILE):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
else:
    users = {
        "admin": {"password": "password123", "key": os.urandom(32).hex()}
    }
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def save_users():
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def check_login(username, password):
    return username in users and users[username]["password"] == password

def register_user(username, password):
    if username in users:
        return False
    users[username] = {"password": password, "key": os.urandom(32).hex()}
    save_users()
    return True

def get_user_key(username):
    if username in users:
        return bytes.fromhex(users[username]["key"])
    return None
