"""
Add or update a portal user.

Usage:
    python manage_users.py add <username> <password> "Display Name"
    python manage_users.py list
    python manage_users.py remove <username>
"""
import sys
import json
import os
from werkzeug.security import generate_password_hash

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
os.makedirs(DATA_DIR, exist_ok=True)


def load():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def save(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    users = load()

    if cmd == "add" and len(args) >= 3:
        username, password = args[1], args[2]
        name = args[3] if len(args) > 3 else username
        users[username] = {
            "password_hash": generate_password_hash(password),
            "name": name,
        }
        save(users)
        print(f"User '{username}' saved.")
    elif cmd == "list":
        for u, v in users.items():
            print(f"  {u}  ({v.get('name')})")
        if not users:
            print("  (no users yet)")
    elif cmd == "remove" and len(args) >= 2:
        if users.pop(args[1], None) is not None:
            save(users)
            print(f"Removed '{args[1]}'.")
        else:
            print(f"No such user: {args[1]}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
