import hashlib
import hmac
import base64
import binascii
import json
import os
import re
import secrets
import shlex
import smtplib
import ssl
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from better_profanity import profanity
from roles import MESSAGE_ROLE_TIERS, SPECIAL_ROLES, primary_color_role, roles_for_user


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("CHAT_DATABASE", ROOT / "accounts.sqlite3"))
PROFILE_PICTURES = Path(os.environ.get("PROFILE_PICTURES_DIR", ROOT / "assets" / "profile-pictures")).expanduser().resolve()
SHORT_BRAND = "Synora"
FULL_BRAND = "SynoraConnect"
SESSION_SECONDS = 60 * 60 * 24 * 14
PRESENCE_SECONDS = 60
PUBLIC_FILE_EXTENSIONS = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".ttf", ".woff", ".woff2", ".ico"}
ROOM_GROUPS = [
    {"name": "Community", "rooms": [{"id": "everyone", "name": "Everyone"}]},
    {"name": "Tech", "rooms": [
        {"id": "it", "name": "IT"},
        {"id": "computer-science", "name": "Computer Science"},
        {"id": "web-development", "name": "Web Development"},
        {"id": "software-engineering", "name": "Software Engineering"},
        {"id": "mobile-development", "name": "Mobile Development"},
        {"id": "hardware", "name": "PC & Hardware"},
        {"id": "linux-open-source", "name": "Linux & Open Source"},
        {"id": "cloud-devops", "name": "Cloud & DevOps"},
        {"id": "networking", "name": "Networking"},
        {"id": "ai-data", "name": "AI & Data"},
        {"id": "cybersecurity", "name": "Cybersecurity"},
        {"id": "design-ux", "name": "Design & UX"},
        {"id": "tech-careers", "name": "Tech Careers"},
        {"id": "startups", "name": "Startups & Ideas"},
    ]},
    {"name": "Gaming", "rooms": [
        {"id": "looking-for-duo", "name": "Looking for Duo"},
        {"id": "looking-for-team", "name": "Looking for Team"},
        {"id": "gaming-chat", "name": "Just Chatting"},
        {"id": "pc-gaming", "name": "PC Gaming"},
        {"id": "console-gaming", "name": "Console Gaming"},
        {"id": "indie-games", "name": "Indie Games"},
        {"id": "co-op-games", "name": "Co-op Games"},
        {"id": "competitive-gaming", "name": "Competitive Gaming"},
        {"id": "game-development", "name": "Game Development"},
    ]},
    {"name": "Media", "rooms": [
        {"id": "anime", "name": "Anime"},
        {"id": "manga", "name": "Manga"},
        {"id": "movies", "name": "Movies"},
        {"id": "tv-shows", "name": "TV Shows"},
        {"id": "documentaries", "name": "Documentaries"},
        {"id": "books-comics", "name": "Books & Comics"},
        {"id": "music", "name": "Music"},
        {"id": "podcasts", "name": "Podcasts"},
    ]},
    {"name": "Interests", "rooms": [
        {"id": "art-design", "name": "Art & Design"},
        {"id": "food-cooking", "name": "Food & Cooking"},
        {"id": "fitness-wellness", "name": "Fitness & Wellness"},
        {"id": "travel", "name": "Travel"},
        {"id": "photography", "name": "Photography"},
        {"id": "science-space", "name": "Science & Space"},
        {"id": "learning-study", "name": "Learning & Study"},
        {"id": "pets", "name": "Pets"},
        {"id": "outdoors-nature", "name": "Outdoors & Nature"},
        {"id": "career-work", "name": "Career & Work"},
    ]},
]
ROOMS = {room["id"]: room for group in ROOM_GROUPS for room in group["rooms"]}
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
BLOCKED_USERNAMES = {
    "arse", "ass", "bastard", "bitch", "bollock", "bullshit", "cock", "coon",
    "asshole", "cunt", "damn", "dick", "dyke", "fag", "faggot", "fuck", "gaysex",
    "nigger", "nigga", "penis", "piss", "porn", "pussy", "rape", "retard",
    "shit", "slut", "spic", "tits", "twat", "vagina", "whore",
}
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
profanity.add_censor_words(BLOCKED_USERNAMES)


def connect_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def configured_admins():
    return {
        username.strip().casefold()
        for username in os.environ.get("ADMIN_USERNAMES", "").split(",")
        if username.strip()
    }


def is_admin_username(username):
    return username.casefold() in configured_admins()


def parse_timeout_duration(value):
    match = re.fullmatch(r"([1-9][0-9]{0,4})([smhd])", value.lower())
    if not match:
        return None
    amount = int(match.group(1))
    seconds_per_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    duration = amount * seconds_per_unit
    return duration if duration <= 30 * 86400 else None


def initialize_database():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    with connect_database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                email_verified_at TEXT,
                bio TEXT NOT NULL DEFAULT '',
                profile_picture TEXT,
                last_seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                room_id TEXT NOT NULL DEFAULT 'everyone'
            );
            CREATE INDEX IF NOT EXISTS messages_created_id ON messages(id);
            CREATE INDEX IF NOT EXISTS sessions_expiration ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS email_verifications (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_moderation (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                is_banned INTEGER NOT NULL DEFAULT 0,
                ban_reason TEXT,
                timeout_until INTEGER,
                timeout_reason TEXT,
                warned_role INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                last_reason TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS moderation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER NOT NULL REFERENCES users(id),
                target_user_id INTEGER NOT NULL REFERENCES users(id),
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                rate_key TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS login_attempts_key_time ON login_attempts(rate_key, attempted_at);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        for name, declaration in (
            ("email_verified_at", "TEXT"),
            ("bio", "TEXT NOT NULL DEFAULT ''"),
            ("profile_picture", "TEXT"),
            ("last_seen", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
        message_columns = {row["name"] for row in connection.execute("PRAGMA table_info(messages)")}
        if "room_id" not in message_columns:
            connection.execute("ALTER TABLE messages ADD COLUMN room_id TEXT NOT NULL DEFAULT 'everyone'")
        connection.execute("CREATE INDEX IF NOT EXISTS messages_room_id_id ON messages(room_id, id)")
        moderation_columns = {row["name"] for row in connection.execute("PRAGMA table_info(user_moderation)")}
        if "last_reason" not in moderation_columns:
            connection.execute("ALTER TABLE user_moderation ADD COLUMN last_reason TEXT")


def clean_username(value):
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    normalized = normalized.lower().translate(LEET_MAP)
    return re.sub(r"[^a-z0-9]", "", normalized)


def username_is_allowed(value):
    cleaned = clean_username(value)
    compressed = re.sub(r"(.)\1+", r"\1", cleaned)
    if any(profanity.contains_profanity(candidate) for candidate in (value, cleaned, compressed)):
        return False
    long_terms = (term for term in BLOCKED_USERNAMES if len(term) >= 4)
    if any(term in cleaned or term in compressed for term in long_terms):
        return False
    short_terms = {term for term in BLOCKED_USERNAMES if len(term) < 4}
    separated = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii").lower().translate(LEET_MAP)
    return not any(
        re.search(r"(?<![a-z])" + r"[^a-z0-9]*".join(term) + r"(?![a-z])", separated)
        for term in short_terms
    )


def bio_is_allowed(value):
    if profanity.contains_profanity(value):
        return False
    for token in re.findall(r"[^\s]+", value):
        normalized = clean_username(token)
        compressed = re.sub(r"(.)\1+", r"\1", normalized)
        if profanity.contains_profanity(normalized) or profanity.contains_profanity(compressed):
            return False
    return True


def role_for_message_count(message_count):
    return next((role for role in reversed(MESSAGE_ROLE_TIERS) if message_count >= role["threshold"]), None)


def serialize_message(message):
    data = dict(message)
    roles = roles_for_user(
        data["message_count"],
        is_admin_username(data["username"]),
        bool(data.get("warned_role", 0)),
    )
    data["roles"] = roles
    data["role"] = primary_color_role(roles)
    return data


def serialize_profile(user, now=None, message_count=None):
    now = now or datetime.now(timezone.utc)
    created_at = datetime.fromisoformat(user["created_at"])
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    old_enough = now - created_at >= timedelta(days=1)
    picture_allowed = bool(user["email_verified_at"] and old_enough)
    picture = user["profile_picture"] if picture_allowed else None
    profile = {
        "username": user["username"],
        "bio": user["bio"],
        "avatar_url": f"/profile-pictures/{picture}" if picture else None,
        "email_verified": bool(user["email_verified_at"]),
        "photo_eligible": picture_allowed,
        "created_at": user["created_at"],
    }
    if message_count is not None:
        profile["message_count"] = message_count
        roles = roles_for_user(
            message_count,
            is_admin_username(user["username"]),
            bool(user["warned_role"]) if "warned_role" in user.keys() else False,
        )
        profile["roles"] = roles
        profile["role"] = primary_color_role(roles)
    return profile


def store_profile_picture(data_url):
    match = re.fullmatch(r"data:(image/png|image/jpeg|image/webp);base64,([A-Za-z0-9+/=]+)", data_url)
    if not match:
        raise ValueError("Choose a PNG, JPG, or WebP image.")
    content_type, encoded = match.groups()
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("That image could not be read.") from None
    if not content or len(content) > 2_000_000:
        raise ValueError("Profile pictures must be smaller than 2 MB.")
    signatures = {
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/webp": content.startswith(b"RIFF") and content[8:12] == b"WEBP",
    }
    if not signatures[content_type]:
        raise ValueError("The selected file does not match its image type.")
    extension = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}[content_type]
    PROFILE_PICTURES.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(20)}.{extension}"
    (PROFILE_PICTURES / filename).write_bytes(content)
    return filename


def execute_moderation_command(actor, raw_command):
    if not is_admin_username(actor["username"]):
        raise PermissionError("Admin access is required.")
    if not isinstance(raw_command, str) or len(raw_command) > 300:
        raise ValueError("Enter one moderation command, up to 300 characters.")
    try:
        arguments = shlex.split(raw_command)
    except ValueError:
        raise ValueError("Could not parse command arguments.") from None
    if not arguments:
        raise ValueError("Enter a command. Type /help for available commands.")

    action = arguments[0].lstrip("/").lower()
    if action == "help" and len(arguments) == 1:
        return (
            "Available commands:\n"
            "/ban <username> [reason]\n"
            "/unban <username>\n"
            "/timeout <username> <10m|2h|7d> [reason]\n"
            "/untimeout <username>\n"
            "/kick <username>\n"
            "/warn <username> [reason]\n"
            "/addwarnrole <username>\n"
            "/removewarnrole <username>\n"
            "/clearwarns <username>\n"
            "/history <username>"
        )

    arity = {
        "ban": (2, None),
        "unban": (2, 2),
        "timeout": (3, None),
        "untimeout": (2, 2),
        "kick": (2, 2),
        "warn": (2, None),
        "addwarnrole": (2, 2),
        "removewarnrole": (2, 2),
        "clearwarns": (2, 2),
        "history": (2, 2),
    }
    if action not in arity:
        raise ValueError("Unknown command. Type /help for available commands.")
    minimum, maximum = arity[action]
    if len(arguments) < minimum or (maximum is not None and len(arguments) > maximum):
        raise ValueError("Invalid arguments. Type /help for command usage.")

    username = arguments[1]
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Enter a valid username.")
    reason = " ".join(arguments[3:] if action == "timeout" else arguments[2:])[:500]
    now = int(datetime.now(timezone.utc).timestamp())
    updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if action == "timeout":
        duration = parse_timeout_duration(arguments[2])
        if duration is None:
            raise ValueError("Use a duration like 15m, 2h, or 7d (maximum 30d).")
        timeout_until = now + duration

    with connect_database() as connection:
        target = connection.execute(
            "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if not target:
            raise ValueError("User not found.")
        if is_admin_username(target["username"]):
            raise ValueError("Admin accounts cannot be moderated with these commands.")
        connection.execute("INSERT OR IGNORE INTO user_moderation (user_id) VALUES (?)", (target["id"],))
        state = connection.execute("SELECT * FROM user_moderation WHERE user_id = ?", (target["id"],)).fetchone()

        if action == "ban":
            detail = reason or "No reason provided."
            connection.execute(
                "UPDATE user_moderation SET is_banned = 1, ban_reason = ?, updated_at = ? WHERE user_id = ?",
                (detail, updated_at, target["id"]),
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (target["id"],))
            result = f"Banned {target['username']}. Reason: {detail}"
        elif action == "unban":
            connection.execute(
                "UPDATE user_moderation SET is_banned = 0, ban_reason = NULL, timeout_until = NULL, timeout_reason = NULL, updated_at = ? WHERE user_id = ?",
                (updated_at, target["id"]),
            )
            result = f"Unbanned {target['username']} and cleared any active timeout."
            detail = ""
        elif action == "timeout":
            if state["is_banned"]:
                raise ValueError("Unban this account before applying a timeout.")
            detail = reason or "No reason provided."
            connection.execute(
                "UPDATE user_moderation SET timeout_until = ?, timeout_reason = ?, last_reason = ?, updated_at = ? WHERE user_id = ?",
                (timeout_until, detail, detail, updated_at, target["id"]),
            )
            until = datetime.fromtimestamp(timeout_until, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            result = f"Timed out {target['username']} until {until}. Reason: {detail}"
        elif action == "untimeout":
            connection.execute(
                "UPDATE user_moderation SET timeout_until = NULL, timeout_reason = NULL, updated_at = ? WHERE user_id = ?",
                (updated_at, target["id"]),
            )
            result = f"Removed the timeout for {target['username']}."
            detail = ""
        elif action == "kick":
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (target["id"],))
            result = f"Signed {target['username']} out. They can sign in again."
            detail = ""
        elif action == "warn":
            detail = reason or "No reason provided."
            connection.execute(
                "UPDATE user_moderation SET warned_role = 1, warning_count = warning_count + 1, last_reason = ?, updated_at = ? WHERE user_id = ?",
                (detail, updated_at, target["id"]),
            )
            warning_count = connection.execute(
                "SELECT warning_count FROM user_moderation WHERE user_id = ?", (target["id"],)
            ).fetchone()["warning_count"]
            result = f"Warned {target['username']} (warning {warning_count}). Reason: {detail}"
        elif action == "addwarnrole":
            detail = "Warning role assigned by admin."
            connection.execute(
                "UPDATE user_moderation SET warned_role = 1, last_reason = ?, updated_at = ? WHERE user_id = ?",
                (detail, updated_at, target["id"]),
            )
            result = f"Added the Warned role to {target['username']}."
        elif action == "removewarnrole":
            connection.execute(
                "UPDATE user_moderation SET warned_role = 0, updated_at = ? WHERE user_id = ?",
                (updated_at, target["id"]),
            )
            result = f"Removed the Warned role from {target['username']}."
            detail = ""
        elif action == "clearwarns":
            connection.execute(
                "UPDATE user_moderation SET warned_role = 0, warning_count = 0, last_reason = NULL, updated_at = ? WHERE user_id = ?",
                (updated_at, target["id"]),
            )
            result = f"Cleared warnings and the Warned role for {target['username']}."
            detail = ""
        else:
            entries = connection.execute(
                """SELECT users.username AS actor, moderation_log.action, moderation_log.detail, moderation_log.created_at
                   FROM moderation_log JOIN users ON users.id = moderation_log.actor_id
                   WHERE moderation_log.target_user_id = ? ORDER BY moderation_log.id DESC LIMIT 10""",
                (target["id"],),
            ).fetchall()
            if not entries:
                result = f"No moderation history for {target['username']}."
            else:
                result = "Recent moderation history:\n" + "\n".join(
                    f"{entry['created_at']} | {entry['action']} by {entry['actor']} | {entry['detail']}"
                    for entry in entries
                )
            detail = "Viewed moderation history."

        if action != "history":
            connection.execute(
                "INSERT INTO moderation_log (actor_id, target_user_id, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (actor["id"], target["id"], action, detail, updated_at),
            )
    return result


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"{salt.hex()}${password_hash.hex()}"


def password_matches(password, stored_hash):
    try:
        salt_hex, expected_hex = stored_hash.split("$", 1)
        actual = hash_password(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
        return hmac.compare_digest(actual, expected_hex)
    except (ValueError, TypeError):
        return False


class ChatHandler(SimpleHTTPRequestHandler):
    server_version = "SynoraConnect"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        if os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def translate_path(self, path):
        parsed_path = urlsplit(path).path
        if parsed_path.startswith("/profile-pictures/"):
            filename = parsed_path.removeprefix("/profile-pictures/")
            if re.fullmatch(r"[a-f0-9]{40}\.(?:png|jpg|webp)", filename):
                return str(PROFILE_PICTURES / filename)
            return str(PROFILE_PICTURES / "__not_found__")
        return super().translate_path(path)

    def log_message(self, format, *args):
        message = format % args if args else format
        request_path = urlsplit(self.path).path
        if self.path != request_path:
            message = message.replace(self.path, request_path)
        super().log_message("%s", message)

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_size=16_384):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > max_size:
                return None
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return None

    def issue_verification(self, user_id, email):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(datetime.now(timezone.utc).timestamp())
        with connect_database() as connection:
            connection.execute("DELETE FROM email_verifications WHERE user_id = ?", (user_id,))
            connection.execute(
                "INSERT INTO email_verifications (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, now + 24 * 60 * 60),
            )

        base_url = os.environ.get("APP_BASE_URL", f"http://127.0.0.1:{self.server.server_port}").rstrip("/")
        verification_url = f"{base_url}/verify.html#token={token}"
        smtp_host = os.environ.get("SMTP_HOST")
        if not smtp_host:
            return verification_url, "development"

        message = EmailMessage()
        message["Subject"] = f"Verify your {FULL_BRAND} email"
        message["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USERNAME", "noreply@localhost"))
        message["To"] = email
        message.set_content(f"Open this link to verify your email address (valid for 24 hours):\n\n{verification_url}\n")
        try:
            port = int(os.environ.get("SMTP_PORT", "587"))
            if os.environ.get("SMTP_USE_SSL") == "1":
                smtp = smtplib.SMTP_SSL(smtp_host, port, context=ssl.create_default_context(), timeout=15)
            else:
                smtp = smtplib.SMTP(smtp_host, port, timeout=15)
                smtp.starttls(context=ssl.create_default_context())
            with smtp:
                username = os.environ.get("SMTP_USERNAME")
                if username:
                    smtp.login(username, os.environ.get("SMTP_PASSWORD", ""))
                smtp.send_message(message)
            return None, "sent"
        except (OSError, smtplib.SMTPException, ValueError) as error:
            self.log_error("Email verification delivery failed: %s", error)
            return None, "failed"

    def current_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except (ValueError, KeyError):
            return None
        session = cookie.get("session")
        if not session:
            return None
        token_hash = hashlib.sha256(session.value.encode("utf-8")).hexdigest()
        with connect_database() as connection:
            user = connection.execute(
                """SELECT users.id, users.username,
                          COALESCE(user_moderation.is_banned, 0) AS is_banned,
                          user_moderation.timeout_until
                   FROM sessions
                   JOIN users ON users.id = sessions.user_id
                   LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                   WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
                (token_hash, int(datetime.now(timezone.utc).timestamp())),
            ).fetchone()
        if not user:
            return None
        if not is_admin_username(user["username"]):
            now = int(datetime.now(timezone.utc).timestamp())
            if user["is_banned"] or (user["timeout_until"] and user["timeout_until"] > now):
                return None
        return user

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = int(datetime.now(timezone.utc).timestamp()) + SESSION_SECONDS
        with connect_database() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires_at),
            )
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(datetime.now(timezone.utc).timestamp()),))
        secure = "; Secure" if os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"} else ""
        return f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}{secure}"

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            try:
                with connect_database() as connection:
                    connection.execute("SELECT 1")
            except sqlite3.Error:
                return self.send_json(503, {"status": "unavailable"})
            return self.send_json(200, {"status": "ok"})
        if parsed.path == "/api/me":
            user = self.current_user()
            return self.send_json(200, {"user": {"username": user["username"]} if user else None})
        if parsed.path == "/api/admin/status":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to check admin access."})
            admin = is_admin_username(user["username"])
            return self.send_json(200, {
                "is_admin": admin,
                "role": SPECIAL_ROLES["admin"] if admin else None,
            })
        if parsed.path == "/api/rooms":
            if not self.current_user():
                return self.send_json(401, {"error": "Please sign in to view chat rooms."})
            return self.send_json(200, {"groups": ROOM_GROUPS})
        if parsed.path == "/api/profile":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to view your profile."})
            with connect_database() as connection:
                profile = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            return self.send_json(200, {"profile": serialize_profile(profile), "email": profile["email"]})
        if parsed.path.startswith("/api/users/"):
            if not self.current_user():
                return self.send_json(401, {"error": "Please sign in to view member profiles."})
            username = unquote(parsed.path.removeprefix("/api/users/")).strip()
            if not USERNAME_PATTERN.fullmatch(username):
                return self.send_json(404, {"error": "User not found."})
            with connect_database() as connection:
                profile = connection.execute(
                    """SELECT users.*,
                              (SELECT COUNT(*) FROM messages WHERE messages.user_id = users.id) AS message_count,
                              COALESCE(user_moderation.warned_role, 0) AS warned_role
                          FROM users
                          LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                          WHERE users.username = ? COLLATE NOCASE""",
                    (username,),
                ).fetchone()
            if not profile:
                return self.send_json(404, {"error": "User not found."})
            return self.send_json(200, {"profile": serialize_profile(profile, message_count=profile["message_count"])})
        if parsed.path == "/api/messages":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to view chat."})
            query = parse_qs(parsed.query)
            room_id = query.get("room", ["everyone"])[0]
            if room_id not in ROOMS:
                return self.send_json(404, {"error": "That chat room does not exist."})
            try:
                after_id = max(0, int(query.get("after", ["0"])[0]))
            except ValueError:
                after_id = 0
            with connect_database() as connection:
                if after_id:
                    messages = connection.execute(
                        """SELECT messages.id, users.username, messages.body, messages.created_at,
                                  (SELECT COUNT(*) FROM messages AS all_messages WHERE all_messages.user_id = users.id) AS message_count,
                                  COALESCE(user_moderation.warned_role, 0) AS warned_role
                           FROM messages JOIN users ON users.id = messages.user_id
                              LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                           WHERE messages.room_id = ? AND messages.id > ? ORDER BY messages.id LIMIT 100""",
                        (room_id, after_id),
                    ).fetchall()
                else:
                    messages = connection.execute(
                        """SELECT messages.id, users.username, messages.body, messages.created_at,
                                  (SELECT COUNT(*) FROM messages AS all_messages WHERE all_messages.user_id = users.id) AS message_count,
                                  COALESCE(user_moderation.warned_role, 0) AS warned_role
                           FROM messages JOIN users ON users.id = messages.user_id
                              LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                           WHERE messages.room_id = ? ORDER BY messages.id DESC LIMIT 100""",
                        (room_id,),
                    ).fetchall()
            return self.send_json(200, {"room": ROOMS[room_id], "messages": [serialize_message(message) for message in reversed(messages)]})
        is_profile_picture = parsed.path.startswith("/profile-pictures/")
        static_path = Path(self.translate_path(parsed.path)).resolve()
        if is_profile_picture:
            try:
                static_path.relative_to(PROFILE_PICTURES)
            except ValueError:
                return self.send_error(404)
            if not static_path.is_file():
                return self.send_error(404)
        elif parsed.path != "/":
            try:
                static_path.relative_to(ROOT.resolve())
            except ValueError:
                return self.send_error(404)
            if static_path.suffix.lower() not in PUBLIC_FILE_EXTENSIONS or not static_path.is_file():
                return self.send_error(404)
        if not is_profile_picture and static_path == DATABASE.resolve():
            return self.send_error(404)
        self.path = parsed.path
        return super().do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        data = self.read_json(3_000_000 if path == "/api/profile" else 16_384)
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Send a valid JSON object."})

        if path == "/api/admin/command":
            actor = self.current_user()
            if not actor:
                return self.send_json(401, {"error": "Please sign in to use admin commands."})
            if not is_admin_username(actor["username"]):
                return self.send_json(403, {"error": "Admin access is required."})
            try:
                output = execute_moderation_command(actor, data.get("command", ""))
            except PermissionError as error:
                return self.send_json(403, {"error": str(error)})
            except ValueError as error:
                return self.send_json(400, {"error": str(error)})
            return self.send_json(200, {"output": output})

        if path == "/api/signup":
            username = str(data.get("username", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            password = data.get("password", "")
            if not USERNAME_PATTERN.fullmatch(username):
                return self.send_json(400, {"error": "Username must be 3 to 20 characters using letters, numbers, or underscores."})
            if not username_is_allowed(username):
                return self.send_json(400, {"error": "That username is not allowed. Choose another."})
            if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
                return self.send_json(400, {"error": "Enter a valid email address."})
            if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
                return self.send_json(400, {"error": "Password must be between 8 and 128 characters."})
            created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            last_seen = int(datetime.now(timezone.utc).timestamp())
            try:
                with connect_database() as connection:
                    cursor = connection.execute(
                        "INSERT INTO users (username, email, password_hash, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                        (username, email, hash_password(password), created_at, last_seen),
                    )
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return self.send_json(409, {"error": "That username or email is already registered."})
            verification_url, delivery = self.issue_verification(user_id, email)
            cookie = self.create_session(user_id)
            return self.send_json(201, {
                "user": {"username": username},
                "verification_url": verification_url,
                "verification_delivery": delivery,
            }, {"Set-Cookie": cookie})

        if path == "/api/login":
            identifier = str(data.get("identifier", "")).strip()
            password = data.get("password", "")
            with connect_database() as connection:
                user = connection.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                    (identifier, identifier),
                ).fetchone()
            if not user or not isinstance(password, str) or not password_matches(password, user["password_hash"]):
                return self.send_json(401, {"error": "Username/email or password is incorrect."})
            if not is_admin_username(user["username"]):
                now = int(datetime.now(timezone.utc).timestamp())
                with connect_database() as connection:
                    restrictions = connection.execute(
                        "SELECT is_banned, timeout_until FROM user_moderation WHERE user_id = ?",
                        (user["id"],),
                    ).fetchone()
                if restrictions and restrictions["is_banned"]:
                    return self.send_json(403, {"error": "This account is banned."})
                if restrictions and restrictions["timeout_until"] and restrictions["timeout_until"] > now:
                    until = datetime.fromtimestamp(restrictions["timeout_until"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    return self.send_json(403, {"error": f"This account is timed out until {until}."})
            with connect_database() as connection:
                connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (int(datetime.now(timezone.utc).timestamp()), user["id"]))
            cookie = self.create_session(user["id"])
            return self.send_json(200, {"user": {"username": user["username"]}}, {"Set-Cookie": cookie})

        if path == "/api/verify":
            token = data.get("token", "")
            if not isinstance(token, str) or not token:
                return self.send_json(400, {"error": "This verification link is invalid or expired."})
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            now = int(datetime.now(timezone.utc).timestamp())
            with connect_database() as connection:
                verification = connection.execute(
                    "SELECT user_id, expires_at FROM email_verifications WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
                if not verification or verification["expires_at"] <= now:
                    return self.send_json(400, {"error": "This verification link is invalid or expired."})
                connection.execute(
                    "UPDATE users SET email_verified_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(timespec="seconds"), verification["user_id"]),
                )
                connection.execute("DELETE FROM email_verifications WHERE user_id = ?", (verification["user_id"],))
            return self.send_json(200, {"ok": True, "message": "Email verified. Your account is ready."})

        if path == "/api/verification/resend":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to verify your email."})
            with connect_database() as connection:
                account = connection.execute("SELECT email, email_verified_at FROM users WHERE id = ?", (user["id"],)).fetchone()
            if account["email_verified_at"]:
                return self.send_json(200, {"message": "Your email is already verified."})
            verification_url, delivery = self.issue_verification(user["id"], account["email"])
            return self.send_json(200, {
                "message": "Verification email sent." if delivery == "sent" else "Use the local verification link below.",
                "verification_url": verification_url,
                "verification_delivery": delivery,
            })

        if path == "/api/presence":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to view online users."})
            now = int(datetime.now(timezone.utc).timestamp())
            with connect_database() as connection:
                connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, user["id"]))
                online = connection.execute(
                    """SELECT users.*,
                              (SELECT COUNT(*) FROM messages WHERE messages.user_id = users.id) AS message_count,
                              COALESCE(user_moderation.warned_role, 0) AS warned_role
                          FROM users
                          LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                          WHERE users.last_seen >= ? ORDER BY username COLLATE NOCASE""",
                    (now - PRESENCE_SECONDS,),
                ).fetchall()
            return self.send_json(200, {
                "users": [
                    serialize_profile(profile, datetime.now(timezone.utc), profile["message_count"])
                    for profile in online
                ]
            })

        if path == "/api/profile":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to edit your profile."})
            bio = data.get("bio", "")
            if not isinstance(bio, str) or len(bio) > 500:
                return self.send_json(400, {"error": "Your bio must be 500 characters or fewer."})
            if not bio_is_allowed(bio):
                return self.send_json(400, {"error": "Please choose different wording for your bio."})
            with connect_database() as connection:
                existing = connection.execute("SELECT profile_picture FROM users WHERE id = ?", (user["id"],)).fetchone()
            picture = existing["profile_picture"]
            avatar_data = data.get("avatar_data")
            if data.get("remove_picture"):
                picture = None
            elif avatar_data is not None:
                if not isinstance(avatar_data, str):
                    return self.send_json(400, {"error": "Choose a valid image file."})
                try:
                    picture = store_profile_picture(avatar_data)
                except ValueError as error:
                    return self.send_json(400, {"error": str(error)})
            with connect_database() as connection:
                connection.execute(
                    "UPDATE users SET bio = ?, profile_picture = ? WHERE id = ?",
                    (bio.strip(), picture, user["id"]),
                )
                profile = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            if existing["profile_picture"] and existing["profile_picture"] != picture:
                (PROFILE_PICTURES / existing["profile_picture"]).unlink(missing_ok=True)
            return self.send_json(200, {"profile": serialize_profile(profile)})

        if path == "/api/logout":
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            session = cookie.get("session")
            if session:
                token_hash = hashlib.sha256(session.value.encode("utf-8")).hexdigest()
                with connect_database() as connection:
                    connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            return self.send_json(200, {"ok": True}, {"Set-Cookie": "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})

        if path == "/api/messages":
            user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Please sign in to send a message."})
            body = data.get("message", "")
            room_id = data.get("room", "everyone")
            if not isinstance(room_id, str) or room_id not in ROOMS:
                return self.send_json(404, {"error": "That chat room does not exist."})
            if not isinstance(body, str) or not body.strip() or len(body.strip()) > 2000:
                return self.send_json(400, {"error": "Messages must be between 1 and 2000 characters."})
            with connect_database() as connection:
                cursor = connection.execute(
                    "INSERT INTO messages (user_id, body, created_at, room_id) VALUES (?, ?, ?, ?)",
                    (user["id"], body.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), room_id),
                )
                message_id = cursor.lastrowid
                message = connection.execute(
                          """SELECT messages.id, users.username, messages.body, messages.created_at, messages.room_id,
                              (SELECT COUNT(*) FROM messages AS all_messages WHERE all_messages.user_id = users.id) AS message_count,
                              COALESCE(user_moderation.warned_role, 0) AS warned_role
                          FROM messages JOIN users ON users.id = messages.user_id
                          LEFT JOIN user_moderation ON user_moderation.user_id = users.id
                          WHERE messages.id = ?""",
                    (message_id,),
                ).fetchone()
            return self.send_json(201, {"message": serialize_message(message)})

        return self.send_json(404, {"error": "Not found."})


def main():
    from webapp import app

    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()