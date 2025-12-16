from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_wtf.csrf import CSRFProtect
import flask_wtf.csrf as csrf_utils
import os, hashlib, io, base64, datetime, json
import pyotp, qrcode
from qrcode.image.pil import PilImage
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from io import BytesIO

# --- App init ---
app = Flask(__name__)
app.secret_key = os.environ.get('APP_SECRET_KEY', 'dev-secret-key-change-me')
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)

# --- In-memory store ---
users = {}
UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- Helpers ---
def require_user():
    if 'user' not in session:
        return None
    username = session['user'].strip()
    return users.get(username)

def add_audit_log(username, action, resource, result, extra=""):
    log_entry = {
        'ts': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'actor': username,
        'action': action,
        'resource': resource,
        'result': result,
        'extra': extra
    }
    prev_hash = users[username]['audit_log'][-1]['entry_hash'] if users[username]['audit_log'] else ''
    entry_hash = hashlib.sha256((prev_hash + json.dumps(log_entry, sort_keys=True)).encode()).hexdigest()
    log_entry['entry_hash'] = entry_hash
    users[username]['audit_log'].append(log_entry)

def decrypt_file(path, hex_key):
    try:
        key = bytes.fromhex(hex_key)
        with open(path, 'rb') as f:
            raw = f.read()
        nonce = raw[:16]
        tag = raw[16:32]
        ciphertext = raw[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception:
        return None

# --- Routes: home ---
@app.route('/')
def home():
    return redirect(url_for('login'))

# --- Routes: login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    token = csrf_utils.generate_csrf()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password')
        mfa_code = request.form.get('mfa_code')

        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            if user['mfa_enabled']:
                totp = pyotp.TOTP(user['mfa_secret'])
                if totp.verify(mfa_code):
                    session['user'] = username
                    add_audit_log(username, "login", "system", "success", "User logged in")
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('login.html', error='Invalid MFA code', csrf_token=token)
            else:
                return render_template('login.html', error='MFA not set up', csrf_token=token)
        else:
            return render_template('login.html', error='Invalid credentials', csrf_token=token)

    return render_template('login.html', csrf_token=token)

# --- Routes: logout ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Routes: register ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    token = csrf_utils.generate_csrf()
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not password:
            return render_template('register.html', error='Username and password are required', csrf_token=token)

        if username in users:
            return render_template('register.html', error='Username already exists', csrf_token=token)

        secret = pyotp.random_base32()
        users[username] = {
            'email': email,
            'password': generate_password_hash(password),
            'role': 'user',
            'mfa_enabled': False,
            'mfa_secret': secret,
            'uploaded_count': 0,
            'shared_count': 0,
            'audit_log': [],
            'uploaded_files': [],   # each file stores its own key
            'shared_with_me': []
        }
        session['pending_user'] = username
        return redirect(url_for('mfa_setup'))

    return render_template('register.html', csrf_token=token)

# --- Routes: MFA setup ---
@app.route('/mfa_setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    username = session['pending_user']
    secret = users[username]['mfa_secret']
    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(name=username, issuer_name="SecureApp")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=PilImage)

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    token = csrf_utils.generate_csrf()
    if request.method == 'POST':
        code = request.form.get('mfa_code')
        if totp.verify(code):
            users[username]['mfa_enabled'] = True
            session.pop('pending_user')
            return redirect(url_for('login'))
        else:
            return render_template('mfa_setup.html', qr_b64=qr_b64, error="Invalid code", csrf_token=token)

    return render_template('mfa_setup.html', qr_b64=qr_b64, csrf_token=token)

# --- Routes: dashboard ---
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user'].strip()
    user = users.get(username)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    token = csrf_utils.generate_csrf()
    return render_template(
        'dashboard.html',
        username=username,
        uploaded_files=user['uploaded_files'],
        shared_with_me=user['shared_with_me'],
        uploaded_count=user['uploaded_count'],
        shared_count=user['shared_count'],
        csrf_token=token
    )
# --- Routes: profile ---
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user'].strip()
    user = users.get(username)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    return render_template(
        'profile.html',
        username=username,
        email=user['email'],
        role=user['role'],
        mfa_status='Enabled' if user['mfa_enabled'] else 'Disabled',
        uploaded_count=len(user['uploaded_files']),
        shared_with_me_count=len(user['shared_with_me']),
        shared_count=user['shared_count']
    )


# --- Routes: upload ---
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    token = csrf_utils.generate_csrf()
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            return render_template('upload.html', error="No file selected", csrf_token=token)

        filename = secure_filename(file.filename)
        data = file.read()

        # Encrypt file with AES-EAX
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        encrypted_path = os.path.join(UPLOAD_DIR, filename + '.enc')
        with open(encrypted_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

        username = session['user'].strip()
        user = users.get(username)
        user['uploaded_count'] += 1
        user['uploaded_files'].append({
            'filename': filename,
            'stored_name': filename + '.enc',
            'path': encrypted_path,
            'timestamp': datetime.datetime.now(),
            'shared_with': [],
            'key': key.hex()
        })
        add_audit_log(username, 'upload', filename, 'success', 'encrypted and stored')

        return render_template('upload.html', success="File encrypted and stored!", csrf_token=token)

    return render_template('upload.html', csrf_token=token)


# --- Routes: share file ---
@app.route('/share_file/<filename>', methods=['POST'])
def share_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    recipient = request.form.get('recipient')
    role = request.form.get('role', 'viewer')
    expiry = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()

    username = session['user'].strip()
    user = users.get(username)
    for f in user['uploaded_files']:
        if f['filename'] == filename:
            f['shared_with'].append({'recipient': recipient, 'role': role, 'expiry': expiry})
            user['shared_count'] += 1
            add_audit_log(username, 'share', filename, 'success', f"shared with {recipient} as {role}")

            if recipient in users:
                users[recipient]['shared_with_me'].append({
                    'filename': filename,
                    'owner': username,
                    'timestamp': f['timestamp'],
                    'token': os.urandom(8).hex(),
                    'role': role,
                    'expiry': expiry,
                    'stored_name': f['stored_name'],
                    'path': f['path']
                })
            break
    return redirect(url_for('dashboard'))


# --- Routes: download (encrypted file) ---
@app.route('/download')
def download():
    user = require_user()
    if not user:
        return redirect(url_for('login'))

    current_username = session['user'].strip()
    token = request.args.get('token', '')
    owner = request.args.get('owner', '')
    filename = request.args.get('filename', '')

    owner_user = users.get(owner)
    if not owner_user:
        add_audit_log(current_username, 'download', filename, 'error', 'owner not found')
        return "Owner not found", 404

    file_entry = next((f for f in owner_user.get('uploaded_files', []) if f['filename'] == filename), None)
    if not file_entry:
        add_audit_log(current_username, 'download', filename, 'error', 'file entry not found')
        return "File not found", 404

    enc_path = file_entry.get('path')
    if not enc_path or not os.path.exists(enc_path):
        add_audit_log(current_username, 'download', filename, 'error', 'encrypted file missing')
        return "File not found", 404

    # Owner access
    if current_username == owner or token == 'owner':
        add_audit_log(current_username, 'download', filename, 'success', 'owner')
        return send_file(enc_path, as_attachment=True,
                         download_name=file_entry.get('stored_name', filename + '.enc'))

    # Recipient access
    allowed = False
    role_used = 'viewer'
    for s in users[current_username].get('shared_with_me', []):
        if s['owner'] == owner and s['filename'] == filename and s['token'] == token:
            try:
                if datetime.datetime.fromisoformat(s['expiry']) < datetime.datetime.now():
                    add_audit_log(current_username, 'download', filename, 'expired', 'link expired')
                    return "Link expired", 403
            except Exception:
                add_audit_log(current_username, 'download', filename, 'error', 'invalid expiry format')
                return "Access denied", 403
            allowed = True
            role_used = s.get('role', 'viewer')
            break

    if not allowed:
        add_audit_log(current_username, 'download', filename, 'denied', 'invalid token/recipient')
        return "Access denied", 403

    add_audit_log(current_username, 'download', filename, 'success', f'role={role_used}')
    return send_file(enc_path, as_attachment=True,
                     download_name=file_entry.get('stored_name', filename + '.enc'))
# --- Routes: preview decrypted ---
@app.route('/preview_decrypted')
def preview_decrypted():
    user = require_user()
    if not user:
        return redirect(url_for('login'))

    filename = request.args.get('filename', '')
    owner = request.args.get('owner', '')

    owner_user = users.get(owner)
    if not owner_user:
        return "Owner not found", 404

    file_entry = next((f for f in owner_user['uploaded_files'] if f['filename'] == filename), None)
    if not file_entry:
        return "File not found", 404

    # Only owner can preview decrypted (extend later for recipients if needed)
    if session['user'].strip() != owner:
        return "Access denied", 403

    key_hex = file_entry.get('key')
    if not key_hex:
        return "No key available", 403

    plaintext = decrypt_file(file_entry['path'], key_hex)
    if plaintext is None:
        return "[Decryption failed]", 500

    ext = os.path.splitext(file_entry['filename'])[1].lower()
    if ext == '.png':
        return send_file(BytesIO(plaintext), mimetype='image/png')
    elif ext in ['.jpg', '.jpeg']:
        return send_file(BytesIO(plaintext), mimetype='image/jpeg')
    elif ext == '.txt':
        try:
            return f"<pre>{plaintext.decode('utf-8')}</pre>"
        except UnicodeDecodeError:
            return "[Decryption successful, but text decoding failed.]"
    else:
        return "[Decryption successful, but preview not supported for this file type.]"


# --- Routes: download decrypted ---
@app.route('/download_decrypted')
def download_decrypted():
    user = require_user()
    if not user:
        return redirect(url_for('login'))

    filename = request.args.get('filename', '')
    owner = request.args.get('owner', '')

    owner_user = users.get(owner)
    if not owner_user:
        return "Owner not found", 404

    file_entry = next((f for f in owner_user['uploaded_files'] if f['filename'] == filename), None)
    if not file_entry:
        return "File not found", 404

    if session['user'].strip() != owner:
        return "Access denied", 403

    key_hex = file_entry.get('key')
    if not key_hex:
        return "No key available", 403

    plaintext = decrypt_file(file_entry['path'], key_hex)
    if plaintext is None:
        return "[Decryption failed]", 500

    import mimetypes
    mime_type, _ = mimetypes.guess_type(file_entry['filename'])
    mime_type = mime_type or 'application/octet-stream'

    return send_file(BytesIO(plaintext), mimetype=mime_type,
                     download_name=file_entry['filename'], as_attachment=True)


# --- Routes: audit ---
@app.route('/audit')
def audit():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user'].strip()
    log = users.get(username, {}).get('audit_log', [])
    return render_template('audit.html', logs=log)


# --- Routes: security demo ---
@app.route('/security_demo', methods=['GET', 'POST'])
def security_demo():
    token = csrf_utils.generate_csrf()
    user_input = None
    hash_result = None

    if request.method == 'POST':
        if 'xss_input' in request.form:
            user_input = request.form.get('xss_input', '')

        if 'password_input' in request.form:
            password = request.form.get('password_input', '')
            if password:
                salt = os.urandom(16)
                pwd_bytes = password.encode('utf-8')
                hash_val = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
                stored = salt.hex() + ':' + hash_val.hex()
                verification = (hash_val.hex() == hash_val.hex())  # trivial demo check
                hash_result = {
                    'salt': salt.hex(),
                    'hash': hash_val.hex(),
                    'stored': stored,
                    'verification': verification
                }

    return render_template('security_demo.html',
        csrf_token=token,
        user_input=user_input,
        hash_result=hash_result
    )


# --- Run the app ---
if __name__ == "__main__":
    app.run(debug=True)
