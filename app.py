from flask import Flask, request, jsonify, send_file
import sqlite3
import bcrypt
import uuid
import os

app = Flask(__name__)

DB_NAME = "accounts.db"
SAVE_FOLDER = "saves"

if not os.path.exists(SAVE_FOLDER):
    os.makedirs(SAVE_FOLDER)


# =========================
# DATABASE
# =========================

def get_conn():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        token TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================
# ROOT
# =========================

@app.route("/")
def home():
    return "Spirit Backend Online"


# =========================
# SIGNUP
# =========================

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()

        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if username == "" or password == "":
            return jsonify({
                "ok": False,
                "message": "Missing data"
            })

        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT username FROM users WHERE username=?",
            (username,)
        )

        existing = cur.fetchone()

        if existing is not None:
            conn.close()

            return jsonify({
                "ok": False,
                "message": "Username already exists"
            })

        hashed = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()

        token = str(uuid.uuid4())

        cur.execute(
            "INSERT INTO users VALUES (?, ?, ?)",
            (
                username,
                hashed,
                token
            )
        )

        conn.commit()
        conn.close()

        return jsonify({
            "ok": True,
            "token": token
        })

    except Exception as ex:
        return jsonify({
            "ok": False,
            "message": str(ex)
        })


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            "SELECT password, token FROM users WHERE username=?",
            (username,)
        )

        row = cur.fetchone()

        conn.close()

        if row is None:
            return jsonify({
                "ok": False,
                "message": "User not found"
            })

        hashed_password = row[0]
        token = row[1]

        if not bcrypt.checkpw(
            password.encode(),
            hashed_password.encode()
        ):
            return jsonify({
                "ok": False,
                "message": "Wrong password"
            })

        return jsonify({
            "ok": True,
            "token": token
        })

    except Exception as ex:
        return jsonify({
            "ok": False,
            "message": str(ex)
        })


# =========================
# SAVE UPLOAD
# =========================

@app.route("/save", methods=["POST"])
def save():
    try:
        token = request.form.get("token")

        if token is None or token == "":
            return jsonify({
                "ok": False,
                "message": "Missing token"
            })

        if "save" not in request.files:
            return jsonify({
                "ok": False,
                "message": "Missing save file"
            })

        save_file = request.files["save"]

        path = os.path.join(
            SAVE_FOLDER,
            token + ".dat"
        )

        save_file.save(path)

        return jsonify({
            "ok": True
        })

    except Exception as ex:
        return jsonify({
            "ok": False,
            "message": str(ex)
        })


# =========================
# SAVE DOWNLOAD
# =========================

@app.route("/load/<token>", methods=["GET"])
def load(token):
    try:
        path = os.path.join(
            SAVE_FOLDER,
            token + ".dat"
        )

        if not os.path.exists(path):
            return jsonify({
                "ok": False,
                "message": "Save not found"
            })

        return send_file(
            path,
            as_attachment=True
        )

    except Exception as ex:
        return jsonify({
            "ok": False,
            "message": str(ex)
        })


# =========================
# START
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port
    )
