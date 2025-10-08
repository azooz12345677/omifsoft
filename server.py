from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from flask_cors import CORS
import sqlite3
import json
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask import session
from urllib.parse import urlparse, urljoin
import os
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, validate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import random
import smtplib
import time
from email.message import EmailMessage

CWD = os.path.dirname(__file__)
# Use the workspace-level nm.db by default (one level up) if present, otherwise use local nm.db
DEFAULT_DB = os.path.abspath(os.path.join(CWD, '..', 'nm.db'))
if not os.path.exists(DEFAULT_DB):
    DEFAULT_DB = os.path.abspath(os.path.join(CWD, 'nm.db'))

DB_PATH = DEFAULT_DB

# process start time for uptime reporting
PROCESS_START = time.time()

app = Flask(__name__)
CORS(app)

# Initialize rate limiter (simple IP-based)
limiter = Limiter(key_func=get_remote_address, default_limits=[])
limiter.init_app(app)

# Prefer secrets from environment variables in production. Falls back to config module or hardcoded placeholder.
app.secret_key = os.environ.get('SECRET_KEY', None) or 'change-me-to-a-random-secret'
try:
    import config
    # config.py values are used only when environment variables are not provided
    app.secret_key = os.environ.get('SECRET_KEY') or getattr(config, 'SECRET_KEY', app.secret_key)
except Exception:
    pass

# Cookie/session security flags
app.config.update(
    # In production this should be True (only send cookies over HTTPS). For local/dev (HTTP on localhost)
    # we set it to False so the browser will send the session cookie and login works.
    # Change to True when running behind HTTPS in production.
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Limit upload size (5 MB default) to mitigate large file uploads
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH') or 5 * 1024 * 1024)

# Allowed extensions for uploads/downloads
ALLOWED_DOWNLOAD_EXT = {'.apk', '.zip', '.tar', '.gz', '.txt', '.pdf', '.exe'}
ALLOWED_AVATAR_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

csrf = CSRFProtect()
csrf.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# set login view so @login_required redirects here
login_manager.login_view = 'login'

# --- Admin token simple auth (for quick admin web UI) ---
try:
    import config
    ADMIN_TOKEN = getattr(config, 'ADMIN_TOKEN', None)
except Exception:
    ADMIN_TOKEN = None

# Disable token-based admin bypass for safety; prefer a single admin DB account.
ADMIN_TOKEN = None


def check_config_security():
    """Log simple warnings if a local config.py appears to contain secrets; encourage env vars.
    This is advisory only and will not modify files.
    """
    try:
        import config as _cfg
        # If a SECRET_KEY is present and looks like a default value, warn
        sk = getattr(_cfg, 'SECRET_KEY', '')
        if sk and ('change-me' in sk or len(sk) < 16):
            app.logger.warning('Insecure SECRET_KEY found in config.py — use a strong secret and prefer environment variables')
        # If SMTP credentials are present, warn about committing secrets
        if getattr(_cfg, 'SMTP_PASS', None) or getattr(_cfg, 'SMTP_USER', None):
            app.logger.warning('SMTP credentials present in config.py — avoid committing secrets to source control; prefer environment variables')
        if getattr(_cfg, 'ADMIN_TOKEN', None):
            app.logger.warning('ADMIN_TOKEN set in config.py — prefer setting it via environment variable in production')
    except Exception:
        pass


check_config_security()

def require_admin_token(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Admin functionality has been removed project-wide.
        # Short-circuit to return Gone so no admin endpoints remain accessible.
        return jsonify({'status': 'error', 'message': 'admin interface removed'}), 410
    return wrapper

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = bool(is_admin)

# Helper function to interact with the database
def query_database(query, args=(), one=False):
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute(query, args)
    if query.strip().upper().startswith('SELECT'):
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
        connection.close()
        if one:
            return result[0] if result else None
        return result
    else:
        connection.commit()
        lastrow = cursor.lastrowid
        connection.close()
        return lastrow


def parse_request():
    """Return (data_dict, is_form_bool).
    Prefers JSON if Content-Type indicates JSON; otherwise returns form data and marks is_form True.
    """
    ctype = (request.content_type or '').lower()
    if 'application/json' in ctype:
        return (request.get_json(silent=True) or {}), False
    # fallback to form data (also covers multipart/form-data)
    try:
        return (request.form.to_dict() or {}), True
    except Exception:
        return ({}, False)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    u = query_database('SELECT id, username, email, is_admin FROM users WHERE id = ?', (user_id,), one=True)
    if u:
        return User(u['id'], u['username'], u['email'], u.get('is_admin'))
    return None

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), 'static', 'downloads')
DEPLOY_DIR = os.path.join(os.path.dirname(__file__), 'deploy')
UPDATE_INFO_PATH = os.path.join(DEPLOY_DIR, 'update_info.json')


def safe_filename(filename: str) -> str:
    # basic safety: strip directory parts and allow only basename
    return os.path.basename(filename)


def read_update_info():
    """Read deploy/update_info.json if present and return dict, otherwise None."""
    try:
        if os.path.exists(UPDATE_INFO_PATH):
            with open(UPDATE_INFO_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        app.logger.exception('Failed to read update_info.json')
    return None


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


@app.route('/api/update/latest', methods=['GET'])
@limiter.limit('60 per minute')
def api_update_latest():
    """Return JSON with latest update metadata for Android app.

    Fields: version, changelog, url (relative), mandatory (bool), checksum (sha256), size (bytes), published_at
    """
    info = read_update_info()
    if not info:
        # fallback: try to inspect DOWNLOAD_DIR for .apk files and compute a minimal response
        try:
            apk_files = []
            if os.path.isdir(DOWNLOAD_DIR):
                for fn in os.listdir(DOWNLOAD_DIR):
                    if fn.lower().endswith('.apk') and os.path.isfile(os.path.join(DOWNLOAD_DIR, fn)):
                        apk_files.append(fn)
            if not apk_files:
                return jsonify({'status': 'ok', 'available': False}), 200
            # pick newest by mtime
            apk_files.sort(key=lambda x: os.path.getmtime(os.path.join(DOWNLOAD_DIR, x)), reverse=True)
            fn = apk_files[0]
            path = os.path.join(DOWNLOAD_DIR, fn)
            checksum = compute_sha256(path)
            size = os.path.getsize(path)
            return jsonify({'status': 'ok', 'available': True, 'version': 'unknown', 'changelog': '', 'url': url_for('download_file', filename=fn), 'mandatory': False, 'checksum': checksum, 'size': size}), 200
        except Exception:
            app.logger.exception('Failed to auto-generate update info')
            return jsonify({'status': 'error', 'message': 'no update info available'}), 500
    # ensure url is safe (relative or internal)
    # If url is provided as absolute, leave it unchanged.
    return jsonify({'status': 'ok', 'available': True, **info}), 200


@app.route('/api/update/download/<path:filename>', methods=['GET'])
@limiter.limit('60 per minute')
def download_file(filename):
    # Only serve files from DOWNLOAD_DIR and with allowed extensions
    fn = safe_filename(filename)
    full = os.path.join(DOWNLOAD_DIR, fn)
    if not os.path.isfile(full):
        return jsonify({'status': 'error', 'message': 'file not found'}), 404
    ext = os.path.splitext(fn)[1].lower()
    if ext not in ALLOWED_DOWNLOAD_EXT:
        return jsonify({'status': 'error', 'message': 'file type not allowed'}), 403
    return send_from_directory(DOWNLOAD_DIR, fn, as_attachment=True)


@app.route('/api/update/fileinfo/<path:filename>', methods=['GET'])
@limiter.limit('60 per minute')
def api_fileinfo(filename):
    """Return JSON with size and sha256 for a given filename in downloads.

    Example: GET /api/update/fileinfo/networkmode-1.2.0.apk
    """
    fn = safe_filename(filename)
    full = os.path.join(DOWNLOAD_DIR, fn)
    if not os.path.isfile(full):
        return jsonify({'status': 'error', 'message': 'file not found'}), 404
    try:
        size = os.path.getsize(full)
        checksum = compute_sha256(full)
        return jsonify({'status': 'ok', 'filename': fn, 'size': size, 'checksum': checksum}), 200
    except Exception:
        app.logger.exception('Failed to compute file info for %s', fn)
        return jsonify({'status': 'error', 'message': 'unable to compute file info'}), 500

# Ensure verification columns exist (safe ALTER TABLE)
def ensure_user_verification_columns():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN verification_code TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN verification_expiry INTEGER")
    except Exception:
        pass
    conn.commit(); conn.close()


def ensure_user_is_active_column():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    except Exception:
        pass
    conn.commit(); conn.close()


def ensure_user_plaintext_pw_column():
    """Optional column to store admin-visible plaintext passwords when explicitly enabled in config.
    This is disabled by default and should only be used in trusted/local environments.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN admin_plaintext_pw TEXT")
    except Exception:
        pass
    conn.commit(); conn.close()


def ensure_user_activity_columns():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN last_seen INTEGER")
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_user_activity_columns()


def ensure_user_avatar_column():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_user_avatar_column()


def ensure_user_is_admin_column():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_user_is_admin_column()

ensure_user_verification_columns()

ensure_user_is_active_column()
ensure_user_plaintext_pw_column()

# Optionally re-enable all users at startup when explicitly requested in config (useful to recover from accidental mass-disable)
try:
    import config as _cfg
    REENABLE = getattr(_cfg, 'ADMIN_REENABLE_ALL_ON_START', False)
except Exception:
    REENABLE = False
if REENABLE:
    try:
        query_database('UPDATE users SET is_active = 1 WHERE is_active IS NULL OR is_active = 0')
        app.logger.info('ADMIN_REENABLE_ALL_ON_START: all users enabled')
    except Exception:
        app.logger.exception('Failed to re-enable users on startup')

def generate_code(length=6):
    return ''.join(str(random.randint(0,9)) for _ in range(length))

def send_verification_email(to_email, code):
    # Try to use config SMTP settings if present, otherwise log to console
    try:
        import config
        SMTP_HOST = getattr(config, 'SMTP_HOST', None)
        SMTP_PORT = getattr(config, 'SMTP_PORT', 587)
        SMTP_USER = getattr(config, 'SMTP_USER', None)
        SMTP_PASS = getattr(config, 'SMTP_PASS', None)
        FROM = getattr(config, 'SMTP_FROM', 'no-reply@example.com')
    except Exception:
        SMTP_HOST = SMTP_PORT = SMTP_USER = SMTP_PASS = FROM = None

    subject = 'رمز التحقق - Network Mode'
    body = f'رمز التحقق الخاص بك هو: {code}\nإذا لم تطلب هذا، تجاهل الرسالة.'

    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = FROM
            msg['To'] = to_email
            msg.set_content(body)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            app.logger.info('Verification email sent to %s', to_email)
            return True
        except Exception as e:
            app.logger.warning('Failed to send email via SMTP: %s', e)
            # fallthrough to log
    # Fallback: log code to server logs (useful for local testing)
    app.logger.info('Verification code for %s: %s', to_email, code)
    return False


def send_email(to_email, subject, body):
    # generic email sender using config SMTP settings
    try:
        import config
        SMTP_HOST = getattr(config, 'SMTP_HOST', None)
        SMTP_PORT = getattr(config, 'SMTP_PORT', 587)
        SMTP_USER = getattr(config, 'SMTP_USER', None)
        SMTP_PASS = getattr(config, 'SMTP_PASS', None)
        FROM = getattr(config, 'SMTP_FROM', 'no-reply@example.com')
    except Exception:
        SMTP_HOST = SMTP_PORT = SMTP_USER = SMTP_PASS = FROM = None
    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = FROM
            msg['To'] = to_email
            msg.set_content(body)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            app.logger.info('Email sent to %s', to_email)
            return True
        except Exception as e:
            app.logger.warning('Failed to send email via SMTP: %s', e)
            return False
    app.logger.info('Email fallback (no SMTP): to=%s subject=%s body=%s', to_email, subject, body)
    return False


# update last_seen for authenticated users on each request
@app.before_request
def touch_last_seen():
    try:
        if current_user and getattr(current_user, 'is_authenticated', False):
            uid = int(current_user.get_id())
            now = int(time.time())
            query_database('UPDATE users SET last_seen = ? WHERE id = ?', (now, uid))
    except Exception:
        pass


@app.after_request
def set_security_headers(response):
    # Basic headers
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
    # HSTS only when running on HTTPS in production
    if request.scheme == 'https':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    # Minimal CSP: restrict to same origin for scripts/styles
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")
    return response


@app.before_request
def block_admin_api():
    # centrally disable any admin API paths to ensure admin functionality is fully removed
    if request.path.startswith('/admin/api/') or request.path in ('/admin', '/admin/login', '/admin/setup', '/admin/logout'):
        return jsonify({'status': 'error', 'message': 'admin interface removed'}), 410

@app.route('/')
def home():
    msg = None
    if session.pop('just_registered', None):
        msg = 'تم إنشاء الحساب بنجاح. مرحباً بك!'
    # list download files
    files = []
    if os.path.isdir(DOWNLOAD_DIR):
        for fn in os.listdir(DOWNLOAD_DIR):
            if os.path.isfile(os.path.join(DOWNLOAD_DIR, fn)):
                files.append(fn)
    return render_template('index.html', message=msg, files=files)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    if request.method == 'GET':
        next_param = request.args.get('next')
        return render_template('login.html', next=next_param)
    data, is_form = parse_request()
    if not data:
        return jsonify({"status": "error", "message": "لم يتم إرسال بيانات"}), 400
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        if is_form:
            return render_template('login.html', message='اسم المستخدم وكلمة المرور مطلوبان', next=request.form.get('next'))
        return jsonify({"status": "error", "message": "اسم المستخدم وكلمة المرور مطلوبان"}), 400
    user = query_database('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if user and check_password_hash(user['password'], password):
        # Prevent login for users who haven't verified their email yet
        # Treat is_verified explicitly as integer flag (0/1)
        try:
            verified_flag = int(user.get('is_verified') or 0)
        except Exception:
            verified_flag = 0
        if verified_flag != 1:
            # For form submissions, render the login page with a helpful message
            if is_form:
                return render_template('login.html', message='حسابك غير موثق بعد. الرجاء التحقق من بريدك أو إعادة إرسال رمز التحقق.', next=request.form.get('next'))
            # For AJAX/JSON clients, return a 403 with a clear status and include email so client can redirect
            return jsonify({"status": "pending_verification", "message": "الحساب غير موثق. تحقق من بريدك أو أعد إرسال رمز التحقق.", "email": user.get('email')}), 403
        user_obj = User(user['id'], user['username'], user['email'], is_admin=user.get('is_admin'))
        login_user(user_obj)
        # mark session is_admin if this user is the configured admin or has is_admin flag
        try:
            import config as _cfg
            admin_username = getattr(_cfg, 'ADMIN_USERNAME', 'admin azooz')
        except Exception:
            admin_username = 'admin azooz'
        try:
            if user_obj.is_admin or (getattr(user_obj, 'username', None) == admin_username):
                session['is_admin'] = True
            else:
                session.pop('is_admin', None)
        except Exception:
            session.pop('is_admin', None)
        # handle redirect to next if present and safe
        next_target = request.form.get('next') or request.args.get('next')
        if next_target and is_safe_url(next_target):
            return redirect(next_target)
        if is_form:
            return redirect(url_for('home'))
        return jsonify({"status": "success", "message": "تم تسجيل الدخول ✅"})
    if is_form:
        return render_template('login.html', message='بيانات الدخول خاطئة', next=request.form.get('next'))
    return jsonify({"status": "error", "message": "بيانات الدخول خاطئة ⚠️"}), 401

@app.route('/logout')
@login_required
def logout():
    # clear admin session flag when logging out
    session.pop('is_admin', None)
    logout_user()
    return jsonify({"status": "success", "message": "تم تسجيل الخروج"})

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data, is_form = parse_request()
    if not data:
        return jsonify({"status": "error", "message": "لم يتم إرسال بيانات"}), 400
    username = (data.get("username") or '').strip()
    password = data.get("password")
    email = (data.get("email") or '').strip()
    # server-side validation
    if not username or not password or not email:
        if is_form:
            return render_template('register.html', message='الرجاء تعبئة جميع الحقول')
        return jsonify({"status": "error", "message": "الرجاء تعبئة جميع الحقول"}), 400
    if '@' in username:
        if request.form:
            return render_template('register.html', message='اسم المستخدم لا يجب أن يحتوي على @')
        return jsonify({"status": "error", "message": "اسم المستخدم غير صالح"}), 400
    if '@' not in email or '.' not in email:
        if request.form:
            return render_template('register.html', message='البريد الإلكتروني غير صالح')
        return jsonify({"status": "error", "message": "البريد الإلكتروني غير صالح"}), 400
    if len(password) < 6:
        if request.form:
            return render_template('register.html', message='كلمة المرور يجب أن تكون 6 أحرف على الأقل')
        return jsonify({"status": "error", "message": "كلمة المرور قصيرة"}), 400
    existing_user = query_database('SELECT * FROM users WHERE username = ? OR email = ?', (username, email), one=True)
    if existing_user:
        if request.form:
            return render_template('register.html', message='المستخدم موجود مسبقاً')
        return jsonify({"status": "error", "message": "المستخدم موجود مسبقاً ⚠️"}), 409
    hashed = generate_password_hash(password)
    # insert user as unverified and generate numeric verification code
    code = generate_code()
    expiry = int(time.time()) + 60*60  # 1 hour expiry
    new_id = query_database('INSERT INTO users (username, password, email, is_verified, verification_code, verification_expiry) VALUES (?, ?, ?, 0, ?, ?)', (username, hashed, email, code, expiry))
    # send verification email (or log)
    send_verification_email(email, code)
    app.logger.info('New registration for %s (form=%s)', email, bool(request.form))
    # mark pending email in session for non-JS flows
    try:
        session['pending_verification_email'] = email
    except Exception:
        pass
    verify_url = url_for('verify', email=email)
    if is_form:
        # For plain form submissions, send a 303 See Other redirect to the verify page so the browser performs a GET
        return redirect(verify_url, code=303)
    # For AJAX/JSON clients include an explicit redirect target and Location header
    from flask import make_response
    payload = {"status": "pending_verification", "message": "تم إنشاء الحساب. تحقق من بريدك للحصول على رمز التحقق.", "email": email, "redirect": verify_url}
    resp = make_response(jsonify(payload), 201)
    resp.headers['Location'] = verify_url
    return resp


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        # If a token param is present, verify immediately and inform the user
        token = request.args.get('token')
        email = request.args.get('email')
        if token:
            # Try to find the user with this token
            u = query_database('SELECT * FROM users WHERE verification_code = ?', (token,), one=True)
            if not u:
                return render_template('verify.html', email=email, message='الرمز غير صالح أو انتهت صلاحيته')
            # check expiry
            if u.get('verification_expiry') and int(time.time()) > int(u.get('verification_expiry')):
                return render_template('verify.html', email=u.get('email'), message='انتهت صلاحية الرابط')
            # mark verified
            query_database('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expiry = NULL WHERE id = ?', (u['id'],))
            return render_template('verify.html', email=u.get('email'), message='تم التحقق بنجاح. يمكنك تسجيل الدخول الآن')
        # No token, show verification form (email may be prefilled)
        return render_template('verify.html', email=email)
    data, is_form = parse_request()
    email = data.get('email')
    code = data.get('code')
    if not email or not code:
        return jsonify({"status":"error","message":"البريد أو الرمز مفقود"}), 400
    u = query_database('SELECT * FROM users WHERE email = ?', (email,), one=True)
    if not u:
        return jsonify({"status":"error","message":"المستخدم غير موجود"}), 404
    if u.get('is_verified'):
        return jsonify({"status":"success","message":"المستخدم موثق بالفعل"})
    if u.get('verification_code') != code:
        return jsonify({"status":"error","message":"رمز التحقق خاطئ"}), 400
    if u.get('verification_expiry') and int(time.time()) > int(u.get('verification_expiry')):
        return jsonify({"status":"error","message":"انتهت صلاحية الرمز"}), 400
    # mark verified
    query_database('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expiry = NULL WHERE id = ?', (u['id'],))
    return jsonify({"status":"success","message":"تم التحقق. يمكنك تسجيل الدخول الآن"})


@app.route('/resend_verification', methods=['POST'])
@limiter.limit('10 per minute')
def resend_verification():
    data, is_form = parse_request()
    email = data.get('email')
    if not email:
        return jsonify({"status":"error","message":"البريد مطلوب"}), 400
    u = query_database('SELECT * FROM users WHERE email = ?', (email,), one=True)
    if not u:
        return jsonify({"status":"error","message":"المستخدم غير موجود"}), 404
    if u.get('is_verified'):
        return jsonify({"status":"success","message":"المستخدم موثق بالفعل"})
    # generate a fresh numeric verification code and update db
    code = generate_code()
    expiry = int(time.time()) + 60*60
    query_database('UPDATE users SET verification_code = ?, verification_expiry = ? WHERE id = ?', (code, expiry, u['id']))
    send_verification_email(email, code)
    return jsonify({"status":"success","message":"تم إرسال رمز تحقق جديد"})

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    # secure send from downloads folder using absolute path
    downloads_dir = os.path.join(app.root_path, 'static', 'downloads')
    # Prevent path traversal and enforce allowed extensions
    # Ensure secure filename and enforce allowed extensions
    safe = secure_filename(filename)
    if not safe or safe != filename:
        return jsonify({'status':'error','message':'invalid filename'}), 400
    _, ext = os.path.splitext(safe)
    if not ext or ext.lower() not in ALLOWED_DOWNLOAD_EXT:
        return jsonify({'status':'error','message':'file type not allowed'}), 403
    # Prevent path traversal by always serving from downloads_dir
    return send_from_directory(downloads_dir, safe, as_attachment=True)

@app.route('/contact', methods=['GET', 'POST'])
@limiter.limit('20 per hour')
def contact():
    if request.method == 'POST':
        # support both authenticated and anonymous submissions
        data, is_form = parse_request()
        message = (data.get('message') or '').strip()
        # honeypot check (bots often fill hidden fields)
        hp = (data.get('hp_field') or '').strip()
        if hp:
            app.logger.warning('Honeypot triggered from %s', request.remote_addr)
            return jsonify({'status':'error','message':'ممنوع'}), 400

        if not message:
            return jsonify({'status': 'error', 'message': 'الرجاء كتابة الرسالة'}), 400

        if current_user and getattr(current_user, 'is_authenticated', False):
            # use logged-in user's identity
            try:
                sender_id = int(current_user.get_id())
                sender = query_database('SELECT id, username, email FROM users WHERE id = ?', (sender_id,), one=True)
                name = sender.get('username') if sender else 'مستخدم'
                email = sender.get('email') if sender else ''
                registered = True
            except Exception:
                name = 'مستخدم'; email = ''; registered = False
        else:
            # anonymous: require name and email fields
            name = (data.get('name') or '').strip()
            email = (data.get('email') or '').strip()
            registered = False
            if not name or not email:
                # for form submit redirect back with an error flag? return JSON error for AJAX
                if not is_form:
                    return jsonify({'status':'error','message':'الرجاء إدخال اسم وبريد صالحين'}), 400
                # return to contact with an error marker (simple approach)
                return redirect(url_for('contact', err='missing'))
            # very basic email sanity check
            if '@' not in email or '.' not in email:
                if not is_form:
                    return jsonify({'status':'error','message':'البريد الإلكتروني غير صالح'}), 400
                return redirect(url_for('contact', err='bad_email'))

        subject = f"رسالة من موقع NetworkMode - {name}"
        body = f"From: {name} <{email}>\n\n{message}"
        # persist the message to the contacts table for admin review
        try:
            query_database('INSERT INTO contacts (name, email, message, created) VALUES (?, ?, ?, ?)', (name, email, message, int(time.time())))
        except Exception:
            app.logger.exception('Failed to save contact message to DB')

        # simple rate limiting per IP: allow max 5 messages per 3600 seconds
        try:
            ip = request.remote_addr or 'unknown'
            row = query_database('SELECT ip, count, first_seen FROM contact_rate WHERE ip = ?', (ip,), one=True)
            now = int(time.time())
            if not row:
                query_database('INSERT INTO contact_rate (ip, count, first_seen) VALUES (?, ?, ?)', (ip, 1, now))
            else:
                cnt = int(row.get('count') or 0)
                first_seen = int(row.get('first_seen') or now)
                if now - first_seen > 3600:
                    # reset window
                    query_database('UPDATE contact_rate SET count = ?, first_seen = ? WHERE ip = ?', (1, now, ip))
                else:
                    if cnt >= 5:
                        return jsonify({'status':'error','message':'معدل الإرسال مرتفع، حاول لاحقاً'}), 429
                    query_database('UPDATE contact_rate SET count = count + 1 WHERE ip = ?', (ip,))
        except Exception:
            app.logger.exception('Rate limiting check failed')

        admin_to = getattr(config, 'SMTP_FROM', None) or getattr(config, 'ADMIN_EMAIL', None) or None
        if not admin_to:
            app.logger.warning('No admin email configured; contact message logged')
            app.logger.info(body)
            return jsonify({'status': 'success', 'message': 'تم الإرسال (تم تسجيل الرسالة على الخادم)'}), 200

        try:
            send_email(admin_to, subject, body)
            # respond differently for AJAX vs normal form
            if not is_form:
                return jsonify({'status': 'success', 'message': 'تم الإرسال'}), 200
            # regular form submit -> redirect back with a flag so the page can show a toast
            return redirect(url_for('contact', sent=1))
        except Exception as e:
            app.logger.exception('Failed to send contact email')
            return jsonify({'status': 'error', 'message': 'فشل إرسال الرسالة'}), 500

    return render_template('contact.html')


@app.route('/forgot', methods=['GET', 'POST'])
@limiter.limit('5 per hour')
def forgot():
    if request.method == 'GET':
        return render_template('forgot.html')
    data = request.get_json() if request.is_json else request.form.to_dict()
    email = data.get('email')
    if not email:
        return jsonify({'status':'error','message':'البريد مطلوب'}), 400
    u = query_database('SELECT * FROM users WHERE email = ?', (email,), one=True)
    if not u:
        return jsonify({'status':'success','message':'إذا كان البريد مسجلاً سيتم إرسال رابط إعادة التعيين'}), 200
    code = generate_code()
    expiry = int(time.time()) + 60*20
    query_database('UPDATE users SET verification_code = ?, verification_expiry = ? WHERE id = ?', (code, expiry, u['id']))
    # send reset code to same email
    reset_link = url_for('verify', email=email, token=code, _external=True)
    body = f'رمز إعادة تعيين كلمة المرور: {code}\nأو اضغط الرابط: {reset_link}'
    send_email(email, 'إعادة تعيين كلمة المرور - NetworkMode', body)
    return jsonify({'status':'success','message':'تم إرسال رمز إعادة التعيين إلى بريدك'})


@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'GET':
        return render_template('profile.html')
    # handle avatar upload via multipart/form-data
    if 'avatar' in request.files:
        f = request.files['avatar']
        filename = secure_filename(f.filename or '')
        if not filename:
            return jsonify({'status':'error','message':'invalid filename'}), 400
        _, ext = os.path.splitext(filename)
        if not ext or ext.lower() not in ALLOWED_AVATAR_EXT:
            return jsonify({'status':'error','message':'avatar file type not allowed'}), 403
        uploads = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(uploads, exist_ok=True)
        # generate unique filename to avoid collisions
        uniq = f"{int(time.time())}_{random.randint(1000,9999)}_{filename}"
        dest = os.path.join(uploads, uniq)
        try:
            f.save(dest)
        except Exception as e:
            app.logger.exception('Failed to save avatar: %s', e)
            return jsonify({'status':'error','message':'failed to save avatar'}), 500
        # update user record
        query_database('UPDATE users SET avatar = ? WHERE id = ?', (uniq, int(current_user.get_id())))
        return jsonify({'status':'success','message':'avatar uploaded','avatar': uniq})
    # otherwise handle simple profile fields via JSON
    data = request.get_json() or {}
    allowed = ['username','email']
    sets=[]; vals=[]
    for k in allowed:
        if k in data:
            sets.append(f"{k} = ?"); vals.append(data[k])
    if sets:
        vals.append(int(current_user.get_id()))
        q = 'UPDATE users SET ' + ','.join(sets) + ' WHERE id = ?'
        query_database(q, tuple(vals))
        return jsonify({'status':'success','message':'updated'})
    return jsonify({'status':'error','message':'no data'}), 400

# Note: profile route (GET/POST) already defined above with avatar handling.


@app.route('/admin')
def admin_ui():
    # Admin UI permanently removed.
    return jsonify({'status': 'error', 'message': 'admin interface removed'}), 410


@app.route('/admin/api/users', methods=['GET'])
@require_admin_token
def admin_list_users():
    # simple listing, not paginated for speed
    try:
        # include is_active so the admin UI can render activation state
        # optionally include admin_plaintext_pw when ADMIN_SHOW_PLAINTEXT_PASSWORDS enabled in config
        try:
            import config as _cfg
            SHOW_PLAIN = getattr(_cfg, 'ADMIN_SHOW_PLAINTEXT_PASSWORDS', False)
        except Exception:
            SHOW_PLAIN = False
        if SHOW_PLAIN:
            users = query_database('SELECT id, username, email, is_verified, is_active, admin_plaintext_pw, last_seen FROM users ORDER BY id DESC')
        else:
            users = query_database('SELECT id, username, email, is_verified, is_active, last_seen FROM users ORDER BY id DESC')
    except Exception:
        # older DB schema may lack is_verified; fall back to basic columns
        try:
            users = query_database('SELECT id, username, email FROM users ORDER BY id DESC')
            # normalize rows to include is_verified and is_active
            for u in users:
                u.setdefault('is_verified', 0)
                u.setdefault('is_active', 0)
                # ensure plaintext key exists for compatibility with admin UI
                u.setdefault('admin_plaintext_pw', None)
        except Exception as e:
            return jsonify({'status':'error', 'message': 'failed to list users', 'error': str(e)}), 500
    return jsonify({'status':'success','users': users})


@app.route('/admin/api/status', methods=['GET'])
@require_admin_token
def admin_status():
    # basic site status: uptime, db size, user counts
    try:
        uptime = int(time.time() - PROCESS_START)
        db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
        total_users = query_database('SELECT COUNT(*) as c FROM users', one=True)
        verified_users = query_database('SELECT COUNT(*) as c FROM users WHERE is_verified = 1', one=True)
        return jsonify({'status':'success', 'uptime': uptime, 'db_size': db_size, 'total_users': total_users.get('c',0), 'verified_users': verified_users.get('c',0)})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}), 500


@app.route('/admin/api/active-users', methods=['GET'])
@require_admin_token
def admin_active_users():
    # users with last_seen within the last 5 minutes
    cutoff = int(time.time()) - 60*5
    try:
        rows = query_database('SELECT id, username, email, last_seen FROM users WHERE last_seen IS NOT NULL AND last_seen >= ? ORDER BY last_seen DESC', (cutoff,))
        # convert last_seen to friendly seconds-ago
        for r in rows:
            r['seconds_ago'] = int(time.time()) - int(r.get('last_seen') or 0)
        return jsonify({'status':'success','active': rows})
    except Exception as e:
        return jsonify({'status':'error','message':str(e)}), 500


SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'admin_settings.json')

def read_settings():
    if not os.path.exists(SETTINGS_FILE):
        default = {'maintenance_mode': False, 'welcome_message': 'مرحباً بك في NetworkMode'}
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
            import json
            fh.write(json.dumps(default, ensure_ascii=False))
        return default
    try:
        import json
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


def ensure_messages_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            created INTEGER,
            replied INTEGER DEFAULT 0,
            reply_text TEXT,
            replied_at INTEGER
        )''')
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_messages_table()


def ensure_contacts_reply_columns():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE contacts ADD COLUMN replied INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE contacts ADD COLUMN reply_text TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE contacts ADD COLUMN replied_at INTEGER")
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_contacts_reply_columns()


def ensure_rate_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS contact_rate (
            ip TEXT PRIMARY KEY,
            count INTEGER,
            first_seen INTEGER
        )''')
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_rate_table()


def ensure_mail_queue_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''CREATE TABLE IF NOT EXISTS mail_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_email TEXT,
            subject TEXT,
            body TEXT,
            created INTEGER,
            attempts INTEGER DEFAULT 0,
            last_error TEXT
        )''')
    except Exception:
        pass
    conn.commit(); conn.close()


ensure_mail_queue_table()


def enqueue_mail(to_email, subject, body):
    try:
        query_database('INSERT INTO mail_queue (to_email, subject, body, created) VALUES (?, ?, ?, ?)', (to_email, subject, body, int(time.time())))
        return True
    except Exception:
        app.logger.exception('Failed to enqueue mail')
        return False


import threading


def mail_queue_worker():
    """Background thread that sends queued emails sequentially."""
    while True:
        try:
            row = query_database('SELECT id, to_email, subject, body, attempts FROM mail_queue ORDER BY created ASC LIMIT 1', one=True)
            if not row:
                time.sleep(2)
                continue
            mid = row.get('id')
            to = row.get('to_email')
            subj = row.get('subject')
            body = row.get('body')
            attempts = int(row.get('attempts') or 0)
            ok = send_email(to, subj, body)
            if ok:
                # remove from queue
                query_database('DELETE FROM mail_queue WHERE id = ?', (mid,))
            else:
                attempts += 1
                # update attempts and optionally record last_error (not capturing exception text here)
                query_database('UPDATE mail_queue SET attempts = ? WHERE id = ?', (attempts, mid))
                # backoff for retries
                if attempts > 5:
                    # drop after many attempts to avoid endless loop
                    query_database('DELETE FROM mail_queue WHERE id = ?', (mid,))
                else:
                    time.sleep(min(30, attempts * 5))
        except Exception:
            app.logger.exception('Mail queue worker error')
            time.sleep(5)


# NOTE: mail worker is intentionally NOT started inside the web process.
# Run `python mail_worker.py` in a separate process/service to handle queued emails.


def write_settings(s):
    try:
        import json
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(s, ensure_ascii=False))
        return True
    except Exception:
        return False


@app.route('/admin/api/settings', methods=['GET'])
@require_admin_token
def admin_get_settings():
    return jsonify({'status':'success', 'settings': read_settings()})


@app.route('/admin/api/settings', methods=['POST'])
@require_admin_token
def admin_post_settings():
    # Only allow CSRF-exempt operation when using admin token auth (API). Session-authenticated admins must include CSRF token.
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin settings: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    s = read_settings()
    s.update(data)
    ok = write_settings(s)
    if not ok:
        return jsonify({'status':'error','message':'failed to save'}), 500
    return jsonify({'status':'success','settings': s})


@app.route('/admin/api/users', methods=['DELETE'])
@require_admin_token
def admin_delete_users():
    if not getattr(request, '_admin_token_auth', False):
        pass
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not ids:
        return jsonify({'status':'error','message':'ids required'}), 400
    q = 'DELETE FROM users WHERE id IN ({})'.format(','.join('?' for _ in ids))
    query_database(q, tuple(ids))
    return jsonify({'status':'success','deleted': len(ids)})


@app.route('/admin/api/users/enable_all', methods=['POST'])
@require_admin_token
def admin_enable_all_users():
    # require CSRF for session-authenticated admins
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin enable_all: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    try:
        updated = query_database('UPDATE users SET is_active = 1 WHERE is_active IS NULL OR is_active = 0')
        return jsonify({'status':'success','message':'all users enabled'})
    except Exception as e:
        app.logger.exception('Failed to enable all users')
        return jsonify({'status':'error','message': str(e)}), 500


@app.route('/admin/api/resend', methods=['POST'])
@require_admin_token
def admin_resend():
    if not getattr(request, '_admin_token_auth', False):
        pass
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({'status':'error','message':'email required'}), 400
    u = query_database('SELECT * FROM users WHERE email = ?', (email,), one=True)
    if not u:
        return jsonify({'status':'error','message':'user not found'}), 404
    if u.get('is_verified'):
        return jsonify({'status':'success','message':'user already verified'})
    code = generate_code()
    expiry = int(time.time()) + 60*60
    query_database('UPDATE users SET verification_code = ?, verification_expiry = ? WHERE id = ?', (code, expiry, u['id']))
    send_verification_email(email, code)
    return jsonify({'status':'success','message':'verification resent'})


@app.route('/admin/login', methods=['GET','POST'])
@limiter.limit('6 per minute')
def admin_login():
    # Simple admin session login using ADMIN_PASSWORD from config
    try:
        import config
        ADMIN_PASSWORD = getattr(config, 'ADMIN_PASSWORD', None)
    except Exception:
        ADMIN_PASSWORD = None
    # Admin login removed
    return jsonify({'status': 'error', 'message': 'admin interface removed'}), 410
    # prefer form data for HTML form submissions; fall back to JSON for API clients
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    # If username+password provided, try to authenticate against users table
    username = (data.get('username') or '').strip()
    password = data.get('password')
    if username and password:
        u = query_database('SELECT * FROM users WHERE username = ?', (username,), one=True)
        if not u or not check_password_hash(u.get('password',''), password):
            # UI removed: still return JSON for API clients
            return jsonify({'status':'error','message':'invalid credentials'}), 403
        # require user to be admin
        try:
            is_admin_flag = int(u.get('is_admin') or 0)
        except Exception:
            is_admin_flag = 0
        # allow only designated admin user or explicit is_admin flag
        try:
            import config as _cfg
            admin_username = getattr(_cfg, 'ADMIN_USERNAME', 'admin azooz')
        except Exception:
            admin_username = 'admin azooz'
        if is_admin_flag != 1 and u.get('username') != admin_username:
            return jsonify({'status':'error','message':'user is not admin'}), 403
        # successful login
        session['is_admin'] = True
        # also login user into Flask-Login session
        login_user(User(u['id'], u['username'], u['email'], True))
        # successful login: return JSON (SPA will redirect)
        return jsonify({'status':'success','message':'logged in'})
    # fallback: allow config.ADMIN_PASSWORD
    pwd = data.get('password')
    # Admin UI removed: do not accept password-based admin login via this endpoint
    return jsonify({'status':'error','message':'admin UI removed'}), 410



@app.route('/admin/setup', methods=['POST'])
def admin_setup():
    """Create an initial admin user if none exists. Call with JSON {"username":"...","password":"...","email":"..."} and must include config.ADMIN_PASSWORD in body or config to authorize."""
    try:
        import config
        ADMIN_PASSWORD = getattr(config, 'ADMIN_PASSWORD', None)
    except Exception:
        ADMIN_PASSWORD = None
    data = request.get_json() or {}
    auth = data.get('admin_password')
    token = data.get('admin_token') or request.headers.get('Authorization')
    if token and token.startswith('Bearer '): token = token.split(' ',1)[1]
    # Do not allow setup unless explicitly enabled in config
    try:
        import config as _cfg
        ALLOW_ADMIN_SETUP = getattr(_cfg, 'ALLOW_ADMIN_SETUP', False)
    except Exception:
        ALLOW_ADMIN_SETUP = False
    return jsonify({'status':'error','message':'admin interface removed'}), 410

    # authorize either with ADMIN_PASSWORD if configured, or ADMIN_TOKEN
    if ADMIN_PASSWORD:
        if auth != ADMIN_PASSWORD:
            return jsonify({'status':'error','message':'not authorized'}), 403
    else:
        if not token or token != ADMIN_TOKEN:
            return jsonify({'status':'error','message':'not authorized'}), 403
    username = (data.get('username') or '').strip()
    password = data.get('password')
    email = (data.get('email') or '').strip()
    if not username or not password or not email:
        return jsonify({'status':'error','message':'missing fields'}), 400
    # create user as admin
    hashed = generate_password_hash(password)
    try:
        new_id = query_database('INSERT INTO users (username, password, email, is_verified, is_admin) VALUES (?, ?, ?, 1, 1)', (username, hashed, email))
        return jsonify({'status':'success','id': new_id})
    except Exception as e:
        app.logger.exception('admin setup failed')
        return jsonify({'status':'error','message': str(e)}), 500


@app.route('/admin/logout')
def admin_logout():
    return jsonify({'status':'error','message':'admin interface removed'}), 410


@app.route('/admin/api/downloads', methods=['GET'])
@require_admin_token
def admin_list_downloads():
    downloads_dir = os.path.join(app.root_path, 'static', 'downloads')
    files = []
    if os.path.isdir(downloads_dir):
        for fn in os.listdir(downloads_dir):
            path = os.path.join(downloads_dir, fn)
            if os.path.isfile(path):
                files.append({'name': fn, 'size': os.path.getsize(path)})
    return jsonify({'status':'success', 'files': files})


@app.route('/admin/api/downloads', methods=['POST'])
@require_admin_token
def admin_upload_download():
    # Only exempt CSRF when using token-based admin auth; session-based admin must include CSRF token
    if not getattr(request, '_admin_token_auth', False):
        # Validate CSRF token for session-authenticated admins
        try:
            # Try header first then form
            token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token') or request.cookies.get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin upload: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    # accept multipart file upload field 'file'
    if 'file' not in request.files:
        return jsonify({'status':'error','message':'file required'}), 400
    f = request.files['file']
    uploads = os.path.join(app.root_path, 'static', 'downloads')
    os.makedirs(uploads, exist_ok=True)
    safe_name = secure_filename(f.filename or '')
    if not safe_name:
        return jsonify({'status':'error','message':'invalid filename'}), 400
    _, ext = os.path.splitext(safe_name)
    if not ext or ext.lower() not in ALLOWED_DOWNLOAD_EXT:
        return jsonify({'status':'error','message':'file type not allowed'}), 403
    dest = os.path.join(uploads, safe_name)
    f.save(dest)
    return jsonify({'status':'success','message':'uploaded', 'file': safe_name})


@app.route('/admin/api/downloads', methods=['DELETE'])
@require_admin_token
def admin_delete_download():
    if not getattr(request, '_admin_token_auth', False):
        # require CSRF token for session-based admin
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin delete download: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    name = data.get('name')
    if not name:
        return jsonify({'status':'error','message':'name required'}), 400
    # sanitize name
    safe = secure_filename(name or '')
    if not safe:
        return jsonify({'status':'error','message':'invalid filename'}), 400
    path = os.path.join(app.root_path, 'static', 'downloads', safe)
    if not os.path.exists(path):
        return jsonify({'status':'error','message':'not found'}), 404
    os.remove(path)
    return jsonify({'status':'success','message':'deleted'})


@app.route('/admin/api/downloads/rename', methods=['POST'])
@require_admin_token
def admin_rename_download():
    # allow renaming files in static/downloads
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin rename download: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    old = data.get('old_name')
    new = data.get('new_name')
    if not old or not new:
        return jsonify({'status':'error','message':'old_name and new_name required'}), 400
    safe_old = secure_filename(old)
    safe_new = secure_filename(new)
    if not safe_old or not safe_new:
        return jsonify({'status':'error','message':'invalid filename'}), 400
    downloads_dir = os.path.join(app.root_path, 'static', 'downloads')
    old_path = os.path.join(downloads_dir, safe_old)
    new_path = os.path.join(downloads_dir, safe_new)
    if not os.path.exists(old_path):
        return jsonify({'status':'error','message':'source not found'}), 404
    if os.path.exists(new_path):
        return jsonify({'status':'error','message':'target already exists'}), 409
    # enforce allowed extensions
    _, ext_old = os.path.splitext(safe_old)
    _, ext_new = os.path.splitext(safe_new)
    if ext_old.lower() not in ALLOWED_DOWNLOAD_EXT or ext_new.lower() not in ALLOWED_DOWNLOAD_EXT:
        return jsonify({'status':'error','message':'file type not allowed'}), 403
    try:
        os.rename(old_path, new_path)
        return jsonify({'status':'success','message':'renamed', 'name': safe_new})
    except Exception as e:
        app.logger.exception('Failed to rename file')
        return jsonify({'status':'error','message': str(e)}), 500


@app.route('/admin/api/messages', methods=['GET'])
@require_admin_token
def admin_list_messages():
    try:
        rows = query_database('SELECT id, name, email, message, created, replied, reply_text, replied_at FROM contacts ORDER BY created DESC')
        for r in rows:
            r['age_seconds'] = int(time.time()) - int(r.get('created') or 0)
            # mark whether the email corresponds to a registered user
            if r.get('email'):
                u = query_database('SELECT id FROM users WHERE email = ?', (r.get('email'),), one=True)
                if u:
                    r['registered'] = True
                    r['user_id'] = u.get('id')
                else:
                    r['registered'] = False
                    r['user_id'] = None
            else:
                r['registered'] = False
                r['user_id'] = None
        return jsonify({'status':'success', 'messages': rows})
    except Exception as e:
        app.logger.exception('Failed to list messages')
        return jsonify({'status':'error','message':str(e)}), 500


@app.route('/admin/api/messages', methods=['DELETE'])
@require_admin_token
def admin_delete_message():
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin delete message: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    mid = data.get('id')
    if not mid:
        return jsonify({'status':'error','message':'id required'}), 400
    try:
        query_database('DELETE FROM contacts WHERE id = ?', (mid,))
        return jsonify({'status':'success','deleted': mid})
    except Exception as e:
        app.logger.exception('Failed to delete message')
        return jsonify({'status':'error','message':str(e)}), 500


@app.route('/admin/api/messages/reply', methods=['POST'])
@require_admin_token
def admin_reply_message():
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin reply: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    mid = data.get('id')
    reply_text = data.get('reply') or ''
    if not mid or not reply_text:
        return jsonify({'status':'error','message':'id and reply required'}), 400
    try:
        m = query_database('SELECT id, name, email, message FROM contacts WHERE id = ?', (mid,), one=True)
        if not m:
            return jsonify({'status':'error','message':'message not found'}), 404
        # send reply email to the sender
        subj = f"رد من NetworkMode - رد على رسالتك"
        body = f"مرحباً {m.get('name')},\n\n{reply_text}\n\n-----Original Message-----\n{m.get('message')}"
        # persist reply info and enqueue mail for sending
        try:
            query_database('UPDATE contacts SET replied = 1, reply_text = ?, replied_at = ? WHERE id = ?', (reply_text, int(time.time()), mid))
        except Exception:
            app.logger.exception('Failed to save reply metadata')
        enqueued = enqueue_mail(m.get('email'), subj, body)
        if not enqueued:
            app.logger.warning('Failed to enqueue reply email to %s; falling back to immediate send', m.get('email'))
            sent = send_email(m.get('email'), subj, body)
            return jsonify({'status':'success','sent': bool(sent), 'enqueued': False})
        return jsonify({'status':'success','sent': True, 'enqueued': True})
    except Exception as e:
        app.logger.exception('Failed to reply to message')
        return jsonify({'status':'error','message':str(e)}), 500


@app.route('/admin/api/user/<int:user_id>', methods=['PATCH'])
@require_admin_token
def admin_update_user(user_id):
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin update user: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    # allow toggling verification and activation; password handled separately
    allowed = ['username', 'email', 'is_verified', 'is_active']
    sets = []
    vals = []
    for k in allowed:
        if k in data:
            sets.append(f"{k} = ?")
            vals.append(data[k])
    if not sets:
        return jsonify({'status':'error','message':'no fields'}), 400
    vals.append(user_id)
    q = 'UPDATE users SET ' + ','.join(sets) + ' WHERE id = ?'
    query_database(q, tuple(vals))
    return jsonify({'status':'success','message':'updated'})


@app.route('/admin/api/user/<int:user_id>/password', methods=['POST'])
@require_admin_token
def admin_change_user_password(user_id):
    # Allow admin to set a user's password directly
    if not getattr(request, '_admin_token_auth', False):
        try:
            token = request.headers.get('X-CSRFToken') or request.get_json(silent=True) and request.get_json().get('csrf_token')
            validate_csrf(token)
        except Exception as e:
            app.logger.warning('CSRF validation failed for admin change password: %s', e)
            return jsonify({'status':'error','message':'CSRF validation failed'}), 403
    data = request.get_json() or {}
    newpw = data.get('password')
    if not newpw or len(newpw) < 6:
        return jsonify({'status':'error','message':'password must be at least 6 characters'}), 400
    hashed = generate_password_hash(newpw)
    try:
        query_database('UPDATE users SET password = ? WHERE id = ?', (hashed, user_id))
        # Optionally store admin-visible plaintext password if feature enabled in config
        try:
            import config as _cfg
            SHOW_PLAIN = getattr(_cfg, 'ADMIN_SHOW_PLAINTEXT_PASSWORDS', False)
        except Exception:
            SHOW_PLAIN = False
        if SHOW_PLAIN:
            try:
                query_database('UPDATE users SET admin_plaintext_pw = ? WHERE id = ?', (newpw, user_id))
            except Exception:
                app.logger.exception('Failed to write admin_plaintext_pw')
        return jsonify({'status':'success','message':'password updated'})
    except Exception as e:
        app.logger.exception('Failed to change user password')
        return jsonify({'status':'error','message':str(e)}), 500

# make csrf token available in templates
@app.context_processor
def inject_csrf():
    # expose generate_csrf function to templates as csrf_token()
    # also expose a simple static version timestamp to help bust client cache when developing
    try:
        vs = int(time.time())
    except Exception:
        vs = 0
    return dict(csrf_token=generate_csrf, static_version=vs)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

