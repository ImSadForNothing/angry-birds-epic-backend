from flask import Flask, request, jsonify, Response
import os
import secrets
import bcrypt
import psycopg2

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            device_id TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            profile_data TEXT DEFAULT ''
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS savegames (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            save_blob BYTEA
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


def hash_password(password):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(
        provided_password.encode("utf-8"),
        stored_password.encode("utf-8")
    )


def get_user_by_token(token):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, username FROM users WHERE token = %s",
        (token,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row


@app.post("/signup")
def signup():
    data = request.get_json(force=True)

    username = data["username"]
    password = data["password"]
    device_id = data.get("device_id", "")

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM users WHERE username = %s",
        (username,)
    )

    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify(ok=False)

    token = secrets.token_hex(16)

    cur.execute(
        """
        INSERT INTO users (username, password_hash, token)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (
            username,
            hash_password(password),
            token
        )
    )

    user_id = cur.fetchone()[0]

    cur.execute(
        """
        INSERT INTO profiles (user_id, profile_data)
        VALUES (%s, %s)
        """,
        (user_id, "")
    )

    cur.execute(
        """
        INSERT INTO savegames (user_id, save_blob)
        VALUES (%s, NULL)
        """,
        (user_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify(ok=True, token=token)


@app.post("/login")
def login():
    data = request.get_json(force=True)

    username = data["username"]
    password = data["password"]

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT password_hash, token
        FROM users
        WHERE username = %s
        """,
        (username,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return jsonify(ok=False)

    password_hash, token = row

    if not verify_password(password_hash, password):
        return jsonify(ok=False)
        
if device_id:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE users
        SET device_id = %s
        WHERE username = %s
        """,
        (device_id, username)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify(ok=True, token=token)


@app.post("/saveprofile")
def saveprofile():
    data = request.get_json(force=True)

    token = data["token"]
    profile = data["profile"]

    user = get_user_by_token(token)

    if not user:
        return jsonify(ok=False)

    user_id = user[0]

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE profiles
        SET profile_data = %s
        WHERE user_id = %s
        """,
        (profile, user_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify(ok=True)


@app.get("/loadprofile/<token>")
def loadprofile(token):
    user = get_user_by_token(token)

    if not user:
        return jsonify(ok=False, profile="")

    user_id = user[0]

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT profile_data
        FROM profiles
        WHERE user_id = %s
        """,
        (user_id,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return jsonify(ok=False, profile="")

    return jsonify(ok=True, profile=row[0])


@app.post("/save")
def save():
    token = request.form["token"]
    file = request.files["save"]

    user = get_user_by_token(token)

    if not user:
        return jsonify(ok=False)

    user_id = user[0]
    save_data = file.read()

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE savegames
        SET save_blob = %s
        WHERE user_id = %s
        """,
        (psycopg2.Binary(save_data), user_id)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify(ok=True)


@app.get("/load/<token>")
def load(token):
    user = get_user_by_token(token)

    if not user:
        return jsonify(ok=False)

    user_id = user[0]

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT save_blob
        FROM savegames
        WHERE user_id = %s
        """,
        (user_id,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row or row[0] is None:
        return jsonify(ok=False)

    return Response(
        row[0],
        mimetype="application/octet-stream"
    )


@app.get("/")
def home():
    return "Backend online"


@app.get("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
