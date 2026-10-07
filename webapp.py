import base64
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

import server as core


ROOT = core.ROOT
DATABASE = core.DATABASE
PROFILE_PICTURES = core.PROFILE_PICTURES
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 3_000_000
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_FAILURE_LIMIT = 10
DUMMY_PASSWORD_HASH = core.hash_password("synora-dummy-password-check")


def login_rate_keys(identifier):
    client_ip = request.remote_addr or "unknown"
    return {
        hashlib.sha256(f"ip:{client_ip}".encode("utf-8")).hexdigest(),
        hashlib.sha256(f"identifier:{identifier.casefold()}".encode("utf-8")).hexdigest(),
    }


def json_body():
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else None


def current_user():
    token = request.cookies.get("session")
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(datetime.now(timezone.utc).timestamp())
    with core.connect_database() as connection:
        user = connection.execute(
            """SELECT users.id, users.username,
                      COALESCE(user_moderation.is_banned, 0) AS is_banned,
                      user_moderation.timeout_until
               FROM sessions JOIN users ON users.id = sessions.user_id
               LEFT JOIN user_moderation ON user_moderation.user_id = users.id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
            (token_hash, now),
        ).fetchone()
    if not user:
        return None
    if not core.is_admin_username(user["username"]):
        if user["is_banned"] or (user["timeout_until"] and user["timeout_until"] > now):
            return None
    return user


def set_session(response, user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = int(datetime.now(timezone.utc).timestamp()) + core.SESSION_SECONDS
    with core.connect_database() as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(datetime.now(timezone.utc).timestamp()),))
    secure_cookie = request.is_secure or os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
    response.set_cookie(
        "session", token, max_age=core.SESSION_SECONDS, httponly=True,
        secure=secure_cookie, samesite="Lax", path="/",
    )
    return response


def secure_response(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    if request.is_secure or os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.before_request
def enforce_same_origin_json():
    if request.method != "POST" or not request.path.startswith("/api/"):
        return None
    origin = request.headers.get("Origin")
    if origin and urlsplit(origin).netloc.casefold() != request.host.casefold():
        return jsonify(error="Cross-origin request rejected."), 403
    if not request.is_json:
        return jsonify(error="Send a JSON request."), 415
    return None


@app.after_request
def add_security_headers(response):
    return secure_response(response)


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Request body is too large."), 413


@app.get("/healthz")
def health_check():
    try:
        with core.connect_database() as connection:
            connection.execute("SELECT 1")
    except sqlite3.Error:
        return jsonify(status="unavailable"), 503
    return jsonify(status="ok")


@app.get("/api/me")
def api_me():
    user = current_user()
    return jsonify(user={"username": user["username"]} if user else None)


@app.get("/api/admin/status")
def api_admin_status():
    user = current_user()
    if not user:
        return jsonify(error="Please sign in to check admin access."), 401
    is_admin = core.is_admin_username(user["username"])
    return jsonify(is_admin=is_admin, role=core.SPECIAL_ROLES["admin"] if is_admin else None)


@app.get("/api/rooms")
def api_rooms():
    if not current_user():
        return jsonify(error="Please sign in to view chat rooms."), 401
    return jsonify(groups=core.ROOM_GROUPS)


@app.get("/api/profile")
def api_profile():
    user = current_user()
    if not user:
        return jsonify(error="Please sign in to view your profile."), 401
    with core.connect_database() as connection:
        profile = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return jsonify(profile=core.serialize_profile(profile), email=profile["email"])


@app.get("/api/users/<username>")
def api_member_profile(username):
    if not current_user():
        return jsonify(error="Please sign in to view member profiles."), 401
    if not core.USERNAME_PATTERN.fullmatch(username):
        return jsonify(error="User not found."), 404
    with core.connect_database() as connection:
        profile = connection.execute(
            """SELECT users.*,
                      (SELECT COUNT(*) FROM messages WHERE messages.user_id = users.id) AS message_count,
                      COALESCE(user_moderation.warned_role, 0) AS warned_role
               FROM users LEFT JOIN user_moderation ON user_moderation.user_id = users.id
               WHERE users.username = ? COLLATE NOCASE""",
            (username,),
        ).fetchone()
    if not profile:
        return jsonify(error="User not found."), 404
    return jsonify(profile=core.serialize_profile(profile, message_count=profile["message_count"]))


@app.get("/api/messages")
def api_get_messages():
    if not current_user():
        return jsonify(error="Please sign in to view chat."), 401
    room_id = request.args.get("room", "everyone")
    if room_id not in core.ROOMS:
        return jsonify(error="That chat room does not exist."), 404
    try:
        after_id = max(0, int(request.args.get("after", "0")))
    except ValueError:
        after_id = 0
    where_after = "AND messages.id > ?" if after_id else ""
    parameters = (room_id, after_id) if after_id else (room_id,)
    with core.connect_database() as connection:
        messages = connection.execute(
            f"""SELECT messages.id, users.username, messages.body, messages.created_at,
                       (SELECT COUNT(*) FROM messages AS all_messages WHERE all_messages.user_id = users.id) AS message_count,
                       COALESCE(user_moderation.warned_role, 0) AS warned_role
                FROM messages JOIN users ON users.id = messages.user_id
                LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                WHERE messages.room_id = ? {where_after}
                ORDER BY messages.id DESC LIMIT 100""",
            parameters,
        ).fetchall()
    return jsonify(room=core.ROOMS[room_id], messages=[core.serialize_message(item) for item in reversed(messages)])


@app.post("/api/signup")
def api_signup():
    data = json_body()
    if data is None:
        return jsonify(error="Send a valid JSON object."), 400
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    if not core.USERNAME_PATTERN.fullmatch(username):
        return jsonify(error="Username must be 3 to 20 characters using letters, numbers, or underscores."), 400
    if not core.username_is_allowed(username):
        return jsonify(error="That username is not allowed. Choose another."), 400
    if not core.EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return jsonify(error="Enter a valid email address."), 400
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return jsonify(error="Password must be between 8 and 128 characters."), 400
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    last_seen = int(datetime.now(timezone.utc).timestamp())
    try:
        with core.connect_database() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, email, password_hash, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                (username, email, core.hash_password(password), created_at, last_seen),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="That username or email is already registered."), 409
    response = jsonify(user={"username": username})
    response.status_code = 201
    return set_session(response, user_id)


@app.post("/api/login")
def api_login():
    data = json_body()
    if data is None:
        return jsonify(error="Send a valid JSON object."), 400
    identifier = str(data.get("identifier", "")).strip()
    password = data.get("password", "")
    now = int(datetime.now(timezone.utc).timestamp())
    rate_keys = login_rate_keys(identifier)
    placeholders = ",".join("?" for _ in rate_keys)
    with core.connect_database() as connection:
        connection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - 24 * 60 * 60,))
        counts = connection.execute(
            f"SELECT rate_key, COUNT(*) AS attempts FROM login_attempts WHERE rate_key IN ({placeholders}) AND attempted_at >= ? GROUP BY rate_key",
            (*rate_keys, now - LOGIN_WINDOW_SECONDS),
        ).fetchall()
    if any(row["attempts"] >= LOGIN_FAILURE_LIMIT for row in counts):
        return jsonify(error="Too many sign-in attempts. Try again in 15 minutes."), 429, {"Retry-After": str(LOGIN_WINDOW_SECONDS)}
    with core.connect_database() as connection:
        user = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
            (identifier, identifier),
        ).fetchone()
    password_to_check = password if isinstance(password, str) else ""
    expected_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_matches = core.password_matches(password_to_check, expected_hash)
    if not user or not isinstance(password, str) or not password_matches:
        with core.connect_database() as connection:
            connection.executemany(
                "INSERT INTO login_attempts (rate_key, attempted_at) VALUES (?, ?)",
                ((rate_key, now) for rate_key in rate_keys),
            )
        return jsonify(error="Username/email or password is incorrect."), 401
    if not core.is_admin_username(user["username"]):
        now = int(datetime.now(timezone.utc).timestamp())
        with core.connect_database() as connection:
            restriction = connection.execute(
                "SELECT is_banned, timeout_until FROM user_moderation WHERE user_id = ?", (user["id"],)
            ).fetchone()
        if restriction and restriction["is_banned"]:
            return jsonify(error="This account is banned."), 403
        if restriction and restriction["timeout_until"] and restriction["timeout_until"] > now:
            until = datetime.fromtimestamp(restriction["timeout_until"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            return jsonify(error=f"This account is timed out until {until}."), 403
    with core.connect_database() as connection:
        connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(datetime.now(timezone.utc).timestamp()), user["id"]))
        connection.executemany("DELETE FROM login_attempts WHERE rate_key = ?", ((rate_key,) for rate_key in rate_keys))
    return set_session(jsonify(user={"username": user["username"]}), user["id"])


@app.post("/api/logout")
def api_logout():
    token = request.cookies.get("session")
    if token:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with core.connect_database() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    response = jsonify(ok=True)
    response.delete_cookie(
        "session", path="/", httponly=True, secure=request.is_secure,
        samesite="Lax",
    )
    return response


@app.post("/api/presence")
def api_presence():
    user = current_user()
    if not user:
        return jsonify(error="Please sign in to view online users."), 401
    now = int(datetime.now(timezone.utc).timestamp())
    with core.connect_database() as connection:
        connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, user["id"]))
        online = connection.execute(
            """SELECT users.*,
                      (SELECT COUNT(*) FROM messages WHERE messages.user_id = users.id) AS message_count,
                      COALESCE(user_moderation.warned_role, 0) AS warned_role
               FROM users LEFT JOIN user_moderation ON user_moderation.user_id = users.id
               WHERE users.last_seen >= ? ORDER BY username COLLATE NOCASE""",
            (now - core.PRESENCE_SECONDS,),
        ).fetchall()
    return jsonify(users=[core.serialize_profile(item, datetime.now(timezone.utc), item["message_count"]) for item in online])


@app.post("/api/profile")
def api_save_profile():
    user = current_user()
    if not user:
        return jsonify(error="Please sign in to edit your profile."), 401
    data = json_body()
    if data is None:
        return jsonify(error="Send a valid JSON object."), 400
    bio = data.get("bio", "")
    if not isinstance(bio, str) or len(bio) > 500:
        return jsonify(error="Your bio must be 500 characters or fewer."), 400
    if not core.bio_is_allowed(bio):
        return jsonify(error="Please choose different wording for your bio."), 400
    with core.connect_database() as connection:
        existing = connection.execute(
            "SELECT profile_picture, created_at FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
    picture = existing["profile_picture"]
    avatar_data = data.get("avatar_data")
    if data.get("remove_picture"):
        picture = None
    elif avatar_data is not None:
        if not core.profile_picture_eligible(existing):
            return jsonify(error="Profile photos are available after your account is at least one day old."), 403
        if not isinstance(avatar_data, str):
            return jsonify(error="Choose a valid image file."), 400
        try:
            picture = core.store_profile_picture(avatar_data)
        except ValueError as error:
            return jsonify(error=str(error)), 400
    with core.connect_database() as connection:
        connection.execute("UPDATE users SET bio = ?, profile_picture = ? WHERE id = ?", (bio.strip(), picture, user["id"]))
        profile = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if existing["profile_picture"] and existing["profile_picture"] != picture:
        (PROFILE_PICTURES / existing["profile_picture"]).unlink(missing_ok=True)
    return jsonify(profile=core.serialize_profile(profile))


@app.post("/api/admin/command")
def api_admin_command():
    actor = current_user()
    if not actor:
        return jsonify(error="Please sign in to use admin commands."), 401
    if not core.is_admin_username(actor["username"]):
        return jsonify(error="Admin access is required."), 403
    data = json_body()
    if data is None:
        return jsonify(error="Send a valid JSON object."), 400
    try:
        output = core.execute_moderation_command(actor, data.get("command", ""))
    except PermissionError as error:
        return jsonify(error=str(error)), 403
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(output=output)


@app.post("/api/messages")
def api_send_message():
    user = current_user()
    if not user:
        return jsonify(error="Please sign in to send a message."), 401
    data = json_body()
    if data is None:
        return jsonify(error="Send a valid JSON object."), 400
    body = data.get("message", "")
    room_id = data.get("room", "everyone")
    if not isinstance(room_id, str) or room_id not in core.ROOMS:
        return jsonify(error="That chat room does not exist."), 404
    if not isinstance(body, str) or not body.strip() or len(body.strip()) > 2000:
        return jsonify(error="Messages must be between 1 and 2000 characters."), 400
    with core.connect_database() as connection:
        cursor = connection.execute(
            "INSERT INTO messages (user_id, body, created_at, room_id) VALUES (?, ?, ?, ?)",
            (user["id"], body.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), room_id),
        )
        message = connection.execute(
            """SELECT messages.id, users.username, messages.body, messages.created_at, messages.room_id,
                      (SELECT COUNT(*) FROM messages all_messages WHERE all_messages.user_id = users.id) AS message_count,
                      COALESCE(user_moderation.warned_role, 0) AS warned_role
               FROM messages JOIN users ON users.id = messages.user_id
               LEFT JOIN user_moderation ON user_moderation.user_id = users.id
               WHERE messages.id = ?""",
            (cursor.lastrowid,),
        ).fetchone()
    response = jsonify(message=core.serialize_message(message))
    response.status_code = 201
    return response


@app.get("/profile-pictures/<filename>")
def profile_picture(filename):
    if not re.fullmatch(r"[a-f0-9]{40}\.(?:png|jpg|webp)", filename):
        abort(404)
    target = (PROFILE_PICTURES / filename).resolve()
    try:
        target.relative_to(PROFILE_PICTURES)
    except ValueError:
        abort(404)
    if not target.is_file():
        abort(404)
    with core.connect_database() as connection:
        account = connection.execute(
            "SELECT created_at FROM users WHERE profile_picture = ?", (filename,)
        ).fetchone()
    if not account or not core.profile_picture_eligible(account):
        abort(404)
    return send_file(target, conditional=True, max_age=3600)


@app.get("/")
def home():
    return send_file(ROOT / "index.html")


@app.get("/<path:filename>")
def public_asset(filename):
    candidate = Path(filename)
    if any(part.startswith(".") for part in candidate.parts):
        abort(404)
    target = (ROOT / candidate).resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        abort(404)
    try:
        target.relative_to(PROFILE_PICTURES)
    except ValueError:
        pass
    else:
        abort(404)
    if target.suffix.lower() not in core.PUBLIC_FILE_EXTENSIONS or not target.is_file():
        abort(404)
    return send_file(target, conditional=True)


core.initialize_database()


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")), debug=False)