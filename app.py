from flask import Flask, request, send_file, jsonify
import os
import json
import secrets
import bcrypt

app = Flask(__name__)

USERS_FILE = "users.json"
PLAYERS_DIR = "players"


def ensure_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

    if not os.path.exists(PLAYERS_DIR):
        os.makedirs(PLAYERS_DIR)


def load_users():
    ensure_files()
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def get_username_from_token(token):
    users = load_users()

    for user, info in users.items():
        if info["token"] == token:
            return user

    return None


def hash_password(password):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(stored_password, provided_password):
    if stored_password.startswith("$2"):
        return bcrypt.checkpw(
            provided_password.encode("utf-8"),
            stored_password.encode("utf-8")
        )

    # compat mode for old plaintext accounts
    return stored_password == provided_password


@app.post("/signup")
def signup():
    data = request.get_json(force=True)

    username = data["username"]
    password = data["password"]

    users = load_users()

    if username in users:
        return jsonify(ok=False)

    token = secrets.token_hex(16)

    users[username] = {
        "password": hash_password(password),
        "token": token
    }

    save_users(users)

    os.makedirs(
        os.path.join(PLAYERS_DIR, username),
        exist_ok=True
    )

    return jsonify(
        ok=True,
        token=token
    )


@app.post("/login")
def login():
    data = request.get_json(force=True)

    username = data["username"]
    password = data["password"]

    users = load_users()

    if username not in users:
        return jsonify(ok=False)

    stored_password = users[username]["password"]

    if not verify_password(
        stored_password,
        password
    ):
        return jsonify(ok=False)

    return jsonify(
        ok=True,
        token=users[username]["token"]
    )


@app.post("/save")
def save():
    token = request.form["token"]
    file = request.files["save"]

    username = get_username_from_token(token)

    if username is None:
        return jsonify(ok=False)

    save_path = os.path.join(
        PLAYERS_DIR,
        username,
        "player"
    )

    file.save(save_path)

    return jsonify(ok=True)


@app.get("/load/<token>")
def load(token):
    username = get_username_from_token(token)

    if username is None:
        return jsonify(ok=False)

    save_path = os.path.join(
        PLAYERS_DIR,
        username,
        "player"
    )

    if not os.path.exists(save_path):
        return jsonify(ok=False)

    return send_file(
        save_path,
        mimetype="application/octet-stream"
    )


@app.post("/saveprofile")
def saveprofile():
    data = request.get_json(force=True)

    token = data["token"]
    profile = data["profile"]

    username = get_username_from_token(token)

    if username is None:
        return jsonify(ok=False)

    profile_path = os.path.join(
        PLAYERS_DIR,
        username,
        "profile.txt"
    )

    with open(
        profile_path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(profile)

    return jsonify(ok=True)


@app.get("/loadprofile/<token>")
def loadprofile(token):
    username = get_username_from_token(token)

    if username is None:
        return jsonify(ok=False)

    profile_path = os.path.join(
        PLAYERS_DIR,
        username,
        "profile.txt"
    )

    if not os.path.exists(profile_path):
        return jsonify(
            ok=False,
            profile=""
        )

    with open(
        profile_path,
        "r",
        encoding="utf-8"
    ) as f:
        profile = f.read()

    return jsonify(
        ok=True,
        profile=profile
    )


app.run(
    host="0.0.0.0",
    port=8080
)