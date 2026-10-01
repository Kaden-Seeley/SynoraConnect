# SynoraConnect

Synora is the community chat for technology, gaming, media, and other interests. It includes persistent accounts and room messages, email verification, profiles, presence, message-based roles, and an allowlisted moderation console.

## Run locally

```sh
python3 -m pip install -r requirements.txt
python3 server.py
```

Open `http://127.0.0.1:8000`. The local Flask development server is for development only; Render runs the WSGI app with Gunicorn.

## Publish on Render

The included `render.yaml` defines a Gunicorn web service and a persistent disk mounted at `/var/data`. The disk is important: without persistent storage, local SQLite accounts, messages, moderation history, and uploaded photos can disappear on redeploy. This SQLite setup is for one running service instance; use a managed PostgreSQL database before scaling to multiple instances.

Create the Render service from this Blueprint, then set these dashboard environment variables:

- `APP_BASE_URL`: the public HTTPS URL for SynoraConnect, such as `https://your-service.onrender.com`.
- `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM`: credentials/settings for a mail provider. `SMTP_PORT` defaults to `587`; set `SMTP_USE_SSL=1` only when your provider requires implicit TLS.
- `ADMIN_USERNAMES`: comma-separated, exact usernames permitted to use the moderation console. Leave it unset until you choose the admin account(s).

Render should keep `COOKIE_SECURE=1`, `CHAT_DATABASE=/var/data/accounts.sqlite3`, and `PROFILE_PICTURES_DIR=/var/data/profile-pictures` from the Blueprint. Do not put credentials in this file or commit them to GitHub; use the Render environment settings.

Without SMTP configured, development signup shows a local verification link. In deployment, configure SMTP and `APP_BASE_URL` so links reach the public HTTPS site. Verification tokens are one-use and expire after 24 hours.

## Git and private data

`.gitignore` excludes local databases and their sidecars, environment files, uploaded profile pictures, Python caches, and local virtual environments. The fallback image is expected at `assets/profile-placeholder.png` and may be committed as a static asset. Check `git status` before the first push; `.gitignore` cannot remove a secret or database that was already committed.

## Roles and moderation

Edit `roles.py` to change message-count tiers and role colors. Set `ADMIN_USERNAMES` to exact existing usernames in Render’s environment settings; restart/redeploy after changing the allowlist. Admins can use `/help`, `/ban`, `/unban`, `/timeout`, `/untimeout`, `/kick`, `/warn`, `/addwarnrole`, `/removewarnrole`, `/clearwarns`, and `/history` in the chat console. Timeouts are limited to 30 days, commands are parsed from a strict allowlist (not passed to a shell), admin accounts cannot be targeted, and actions are recorded in `moderation_log`.

## Security notes

Passwords use PBKDF2-HMAC-SHA256. Session cookies are HttpOnly and SameSite=Lax, and Secure on the HTTPS Render deployment. The WSGI app adds a Content Security Policy and other browser security headers, rejects cross-origin API posts, restricts public static files, and keeps the account database outside the served asset paths. Uploaded pictures are validated by type and size; bios are moderated server-side.

Failed logins are rate-limited to 10 attempts per 15 minutes per client IP and login identifier. Unknown-account failures still perform password-hash work to reduce account-name timing leaks.