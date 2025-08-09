# server_real.py
import os, sqlite3, bcrypt, uuid, time, datetime, threading, secrets, smtplib
from email.message import EmailMessage
from flask import Flask, request, jsonify, g
from flask_cors import CORS

# Optional Twilio SMS
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except Exception:
    TWILIO_AVAILABLE = False

DB_PATH = "mfa_real.db"
OTP_TTL_SECONDS = 180
SESSION_TTL_SECONDS = 1800
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_ATTEMPTS = 8

# SMTP envs
EMAIL_SMTP_HOST = os.environ.get("EMAIL_SMTP_HOST","")
EMAIL_SMTP_PORT = int(os.environ.get("EMAIL_SMTP_PORT","587") or 587)
EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME","")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD","")
EMAIL_FROM = os.environ.get("EMAIL_FROM", EMAIL_USERNAME)

# Twilio envs
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID","")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN","")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER","")  # e.g. +1234567890

app = Flask(__name__)
CORS(app)

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db(); cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        email TEXT,
        phone TEXT,
        mfa_enabled INTEGER DEFAULT 0,
        device_fingerprint TEXT,
        last_ip TEXT,
        created_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        otp TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT
    )""")
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

rate_store = {}
def allow_attempt(ip):
    now = time.time()
    lst = rate_store.get(ip, [])
    lst = [t for t in lst if now - t < RATE_LIMIT_WINDOW]
    if len(lst) >= RATE_LIMIT_MAX_ATTEMPTS:
        rate_store[ip] = lst
        return False
    lst.append(now)
    rate_store[ip] = lst
    return True

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), pw_hash)

def now_iso():
    return datetime.datetime.utcnow().isoformat()

def iso_plus_seconds(s):
    return (datetime.datetime.utcnow() + datetime.timedelta(seconds=s)).isoformat()

def gen_otp():
    return "{:06d}".format(secrets.randbelow(10**6))

def send_email(to_email: str, subject: str, body: str) -> bool:
    if not EMAIL_SMTP_HOST or not EMAIL_USERNAME or not EMAIL_PASSWORD:
        app.logger.error("SMTP not configured.")
        return False
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error("Email send failed: %s", e)
        return False

def send_sms_via_twilio(to_number: str, body: str) -> bool:
    if not TWILIO_AVAILABLE:
        app.logger.error("Twilio library not installed.")
        return False
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_FROM_NUMBER:
        app.logger.error("Twilio envs not configured.")
        return False
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        msg = client.messages.create(body=body, from_=TWILIO_FROM_NUMBER, to=to_number)
        app.logger.info(f"Twilio SID: {msg.sid}")
        return True
    except Exception as e:
        app.logger.error("Twilio send failed: %s", e)
        return False

# endpoints - same semantics as mock but with real sends
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()
    if not username or not password:
        return jsonify({"status":"FAIL","message":"username and password required"}), 400
    db = get_db(); cur = db.cursor()
    try:
        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash, email, phone, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, sqlite3.Binary(pw_hash), email if email else None, phone if phone else None, now_iso()))
        db.commit()
        return jsonify({"status":"OK","message":"user created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"status":"FAIL","message":"username exists"}), 409

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "unknown"
    if not allow_attempt(ip):
        return jsonify({"status":"FAIL","message":"rate limit exceeded"}), 429
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    device_fp = data.get("device_fingerprint") or ""
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row or not check_password(password, row["password_hash"]):
        return jsonify({"status":"FAIL","message":"invalid credentials"}), 401

    user_id = row["id"]
    if row["mfa_enabled"]:
        otp = gen_otp(); expires = iso_plus_seconds(OTP_TTL_SECONDS)
        cur.execute("INSERT INTO otps (user_id, otp, expires_at, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, otp, expires, now_iso()))
        cur.execute("UPDATE users SET last_ip = ?, device_fingerprint = ? WHERE id = ?", (ip, device_fp, user_id))
        db.commit()
        # try email first
        sent_email = False
        if row["email"]:
            sent_email = send_email(row["email"], "Your Digitopia OTP", f"Your OTP: {otp}\nExpires in {OTP_TTL_SECONDS} seconds.")
        if sent_email:
            return jsonify({"status":"OTP_SENT","message":"otp sent to email"}), 200
        # email failed or not configured -> try SMS if phone exists and Twilio configured
        sent_sms = False
        if row["phone"]:
            sent_sms = send_sms_via_twilio(row["phone"], f"Your OTP: {otp} (expires in {OTP_TTL_SECONDS}s)")
        if sent_sms:
            return jsonify({"status":"OTP_SENT","message":"otp sent via SMS"}), 200
        # fallback: fail and report (so admin knows)
        app.logger.error(f"Failed to send OTP to user {username}; email_ok={sent_email} sms_ok={sent_sms}")
        return jsonify({"status":"FAIL","message":"failed to deliver otp; check server config"}), 500
    else:
        token = str(uuid.uuid4()); expires = iso_plus_seconds(SESSION_TTL_SECONDS)
        cur.execute("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                    (token, user_id, expires, now_iso()))
        cur.execute("UPDATE users SET last_ip = ?, device_fingerprint = ? WHERE id = ?", (ip, device_fp, user_id))
        db.commit()
        return jsonify({"status":"SUCCESS","token":token,"expires_at":expires}), 200

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    otp = (data.get("otp") or "").strip()
    if not username or not otp:
        return jsonify({"status":"FAIL","message":"username and otp required"}), 400
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return jsonify({"status":"FAIL","message":"invalid user"}), 400
    user_id = row["id"]
    cur.execute("SELECT * FROM otps WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
    o = cur.fetchone()
    if not o:
        return jsonify({"status":"FAIL","message":"no otp found"}), 400
    if o["otp"] != otp:
        return jsonify({"status":"FAIL","message":"wrong otp"}), 401
    if datetime.datetime.fromisoformat(o["expires_at"]) < datetime.datetime.utcnow():
        return jsonify({"status":"FAIL","message":"otp expired"}), 401
    cur.execute("DELETE FROM otps WHERE id = ?", (o["id"],))
    db.commit()
    return jsonify({"status":"BIOMETRIC_REQUIRED","message":"proceed to biometric mock"}), 200

@app.route("/verify-biometric", methods=["POST"])
def verify_biometric():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    scan_pass = (data.get("scan_pass") or "").strip()
    device_fp = data.get("device_fingerprint") or ""
    ip = request.remote_addr or "unknown"
    if not username or not scan_pass:
        return jsonify({"status":"FAIL","message":"username and scan_pass required"}), 400
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return jsonify({"status":"FAIL","message":"invalid user"}), 400
    if scan_pass != "scan_ok":
        return jsonify({"status":"FAIL","message":"biometric failed (mock)"}), 401
    token = str(uuid.uuid4()); expires = iso_plus_seconds(SESSION_TTL_SECONDS)
    cur.execute("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token, row["id"], expires, now_iso()))
    cur.execute("UPDATE users SET last_ip = ?, device_fingerprint = ? WHERE id = ?", (ip, device_fp, row["id"]))
    db.commit()
    return jsonify({"status":"SUCCESS","token":token,"expires_at":expires}), 200

@app.route("/enable-mfa", methods=["POST"])
def enable_mfa():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    if not username or not password:
        return jsonify({"status":"FAIL","message":"username and password required"}), 400
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row or not check_password(password, row["password_hash"]):
        return jsonify({"status":"FAIL","message":"invalid credentials"}), 401
    if not row["email"] and not row["phone"]:
        return jsonify({"status":"FAIL","message":"user has no email or phone; cannot enable real OTP"}), 400
    cur.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (row["id"],))
    db.commit()
    return jsonify({"status":"OK","message":"MFA enabled (real mode)"}), 200

@app.route("/status", methods=["GET"])
def status():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    if not token:
        return jsonify({"status":"FAIL","message":"no token"}), 401
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    s = cur.fetchone()
    if not s:
        return jsonify({"status":"FAIL","message":"invalid token"}), 401
    if datetime.datetime.fromisoformat(s["expires_at"]) < datetime.datetime.utcnow():
        return jsonify({"status":"FAIL","message":"session expired"}), 401
    cur.execute("SELECT username, last_ip, device_fingerprint, mfa_enabled FROM users WHERE id = ?", (s["user_id"],))
    user = cur.fetchone()
    return jsonify({"status":"OK","username":user["username"], "last_ip":user["last_ip"], "device":user["device_fingerprint"], "mfa_enabled": bool(user["mfa_enabled"]) }), 200

@app.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    if not token:
        return jsonify({"status":"FAIL","message":"no token"}), 401
    db = get_db(); cur = db.cursor()
    cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
    db.commit()
    return jsonify({"status":"OK","message":"logged out"}), 200

def cleanup_loop():
    while True:
        try:
            db = sqlite3.connect(DB_PATH)
            cur = db.cursor()
            now = datetime.datetime.utcnow().isoformat()
            cur.execute("DELETE FROM otps WHERE expires_at < ?", (now,))
            cur.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            db.commit()
            db.close()
        except Exception as e:
            app.logger.error("cleanup error: %s", e)
        time.sleep(60)

if __name__ == "__main__":
    with app.app_context():
        init_db()
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
