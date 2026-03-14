from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os
import base64
import jwt
import datetime
from zoneinfo import ZoneInfo
IST = ZoneInfo('Asia/Kolkata')

# ─── App Setup ───────────────────────────────────────────────
app = Flask(__name__)

# ✅ SECRET_KEY from environment variable
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-local-secret-change-in-prod')

CORS(app, supports_credentials=False, origins="*",
     allow_headers=["Content-Type", "Authorization", "ngrok-skip-browser-warning"],
     methods=["GET", "POST", "OPTIONS"])

@app.after_request
def add_headers(response):
    origin = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Origin'] = origin if origin else '*'
    response.headers['Access-Control-Allow-Credentials'] = 'false'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, ngrok-skip-browser-warning'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['ngrok-skip-browser-warning'] = 'true'
    return response

@app.route('/api/messages', methods=['OPTIONS'])
@app.route('/api/login', methods=['OPTIONS'])
@app.route('/api/register', methods=['OPTIONS'])
@app.route('/api/send-message', methods=['OPTIONS'])
@app.route('/api/me', methods=['OPTIONS'])
@app.route('/api/other-user', methods=['OPTIONS'])
@app.route('/api/delete-message', methods=['OPTIONS'])
@app.route('/api/react-message', methods=['OPTIONS'])
@app.route('/api/pin-message', methods=['OPTIONS'])
@app.route('/api/edit-message', methods=['OPTIONS'])
@app.route('/api/pinned-messages', methods=['OPTIONS'])
def handle_options():
    return '', 200

socketio = SocketIO(app, cors_allowed_origins="*",
                    transports=['websocket', 'polling'],
                    logger=False, engineio_logger=False)

# ─── Encryption Setup ────────────────────────────────────────
# ✅ FERNET_KEY from environment variable (base64 encoded)
_fernet_env = os.environ.get('FERNET_KEY')
if _fernet_env:
    FERNET_KEY = base64.b64decode(_fernet_env)
else:
    # Local fallback: read from file or generate
    KEY_FILE = os.path.join(os.path.dirname(__file__), 'encryption.key')
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            FERNET_KEY = f.read()
    else:
        FERNET_KEY = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(FERNET_KEY)

cipher = Fernet(FERNET_KEY)

def encrypt_msg(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_msg(token):
    try:
        return cipher.decrypt(token.encode()).decode()
    except Exception:
        return token

# ─── Online Users Tracker ────────────────────────────────────
online_users = {}   # { username: socket_id }

# ─── Database ────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id     INTEGER NOT NULL,
            receiver_id   INTEGER NOT NULL,
            message       TEXT    NOT NULL,
            message_type  TEXT    DEFAULT 'text',
            seen          INTEGER DEFAULT 0,
            deleted       INTEGER DEFAULT 0,
            reaction      TEXT    DEFAULT NULL,
            reply_to      INTEGER DEFAULT NULL,
            reply_text    TEXT    DEFAULT NULL,
            timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id)   REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    # Add columns if upgrading existing db
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN reaction TEXT DEFAULT NULL')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN reply_to INTEGER DEFAULT NULL')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN reply_text TEXT DEFAULT NULL')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN pinned INTEGER DEFAULT 0')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN forwarded INTEGER DEFAULT 0')
    except: pass
    try:
        conn.execute('ALTER TABLE messages ADD COLUMN scheduled_at TEXT DEFAULT NULL')
    except: pass
    conn.commit()
    conn.close()
    print("✅ Database initialised → database.db")

# ─── JWT Helpers ─────────────────────────────────────────────
def create_token(user_id, username):
    payload = {
        'user_id':  user_id,
        'username': username,
        'exp':      datetime.datetime.now(IST) + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth.split(' ', 1)[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except Exception:
        return None

# ═════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═════════════════════════════════════════════════════════════

@app.route('/api/register', methods=['POST'])
def register():
    data     = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required.'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters.'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters.'}), 400

    conn = get_db()
    try:
        count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if count >= 2:
            return jsonify({'error': 'Max 2 users allowed. This chat is private.'}), 403
        exists = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        if exists:
            return jsonify({'error': 'Username already taken.'}), 409
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?,?)', (username, pw_hash))
        conn.commit()
        return jsonify({'message': f'User "{username}" registered!'}), 201
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required.'}), 400

    conn = get_db()
    try:
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid username or password.'}), 401
        if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            return jsonify({'error': 'Invalid username or password.'}), 401

        token = create_token(user['id'], user['username'])
        return jsonify({
            'message': 'Login successful',
            'token':   token,
            'user':    {'id': user['id'], 'username': user['username']}
        }), 200
    finally:
        conn.close()


@app.route('/api/me', methods=['GET'])
def me():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'user': {'id': payload['user_id'], 'username': payload['username']}}), 200


@app.route('/api/other-user', methods=['GET'])
def other_user():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = get_db()
    try:
        user = conn.execute(
            'SELECT id, username FROM users WHERE id != ?', (payload['user_id'],)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Other user not registered yet.'}), 404
        return jsonify({'user': {'id': user['id'], 'username': user['username']}}), 200
    finally:
        conn.close()


# ═════════════════════════════════════════════════════════════
# MESSAGE ROUTES
# ═════════════════════════════════════════════════════════════

@app.route('/api/send-message', methods=['POST'])
def send_message():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401

    data         = request.get_json()
    raw_message  = data.get('message', '').strip()
    message_type = data.get('message_type', 'text')

    if not raw_message:
        return jsonify({'error': 'Message cannot be empty.'}), 400

    conn = get_db()
    try:
        receiver = conn.execute(
            'SELECT id, username FROM users WHERE id != ?', (payload['user_id'],)
        ).fetchone()
        if not receiver:
            return jsonify({'error': 'Receiver not found.'}), 404

        reply_to   = data.get('reply_to')
        reply_text = data.get('reply_text')
        forwarded  = 1 if data.get('forwarded') else 0
        scheduled_at = data.get('scheduled_at')
        encrypted = encrypt_msg(raw_message)
        conn.execute(
            'INSERT INTO messages (sender_id, receiver_id, message, message_type, reply_to, reply_text, forwarded, scheduled_at) VALUES (?,?,?,?,?,?,?,?)',
            (payload['user_id'], receiver['id'], encrypted, message_type, reply_to, reply_text, forwarded, scheduled_at)
        )
        conn.commit()

        msg_id    = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        timestamp = datetime.datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S')

        msg_payload = {
            'id':           msg_id,
            'sender_id':    payload['user_id'],
            'sender_name':  payload['username'],
            'receiver_id':  receiver['id'],
            'message':      raw_message,
            'message_type': message_type,
            'seen':         False,
            'deleted':      False,
            'reaction':     None,
            'reply_to':     reply_to,
            'reply_text':   reply_text,
            'pinned':       False,
            'edited':       False,
            'forwarded':    bool(forwarded),
            'timestamp':    timestamp,
            'scheduled_at': scheduled_at,
        }

        receiver_sid = online_users.get(receiver['username'])
        if receiver_sid:
            socketio.emit('receive_message', msg_payload, to=receiver_sid)

        return jsonify({'message': msg_payload}), 200
    finally:
        conn.close()


@app.route('/api/messages', methods=['GET'])
def get_messages():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT m.id, m.sender_id, m.receiver_id, m.message,
                   m.message_type, m.seen, m.timestamp,
                   COALESCE(m.deleted, 0) as deleted,
                   COALESCE(m.reaction, NULL) as reaction,
                   COALESCE(m.reply_to, NULL) as reply_to,
                   COALESCE(m.reply_text, NULL) as reply_text,
                   COALESCE(m.pinned, 0) as pinned,
                   COALESCE(m.edited, 0) as edited,
                   COALESCE(m.forwarded, 0) as forwarded,
                   u.username AS sender_name
            FROM   messages m
            JOIN   users    u ON u.id = m.sender_id
            WHERE  m.scheduled_at IS NULL OR m.scheduled_at <= datetime('now')
            ORDER  BY m.timestamp ASC
        ''').fetchall()

        messages = [{
            'id':           r['id'],
            'sender_id':    r['sender_id'],
            'sender_name':  r['sender_name'],
            'receiver_id':  r['receiver_id'],
            'message':      '🚫 This message was deleted' if r['deleted'] else decrypt_msg(r['message']),
            'message_type': 'deleted' if r['deleted'] else r['message_type'],
            'seen':         bool(r['seen']),
            'deleted':      bool(r['deleted']),
            'reaction':     r['reaction'],
            'reply_to':     r['reply_to'],
            'reply_text':   r['reply_text'],
            'pinned':       bool(r['pinned']),
            'edited':       bool(r['edited']),
            'forwarded':    bool(r['forwarded']),
            'timestamp':    r['timestamp'],
        } for r in rows]

        conn.execute('UPDATE messages SET seen=1 WHERE receiver_id=? AND seen=0',
                     (payload['user_id'],))
        conn.commit()
        return jsonify({'messages': messages}), 200
    finally:
        conn.close()


@app.route('/api/users', methods=['GET'])
def list_users():
    conn = get_db()
    try:
        rows = conn.execute('SELECT id, username, created_at FROM users').fetchall()
        return jsonify({'users': [dict(r) for r in rows]}), 200
    finally:
        conn.close()


# ═════════════════════════════════════════════════════════════
# SOCKET.IO EVENTS
# ═════════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    print(f"🔌 Socket connected: {request.sid}")


@socketio.on('disconnect')
def on_disconnect():
    gone = None
    for uname, sid in list(online_users.items()):
        if sid == request.sid:
            gone = uname
            del online_users[uname]
            break
    if gone:
        print(f"📴 {gone} disconnected")
        socketio.emit('user_status', {'username': gone, 'online': False})
        socketio.emit('online_users', list(online_users.keys()))


@socketio.on('join')
def on_join(data):
    username = data.get('username')
    if not username:
        return
    online_users[username] = request.sid
    print(f"✅ {username} joined (sid: {request.sid})")
    socketio.emit('online_users', list(online_users.keys()))
    socketio.emit('user_status', {'username': username, 'online': True})


@socketio.on('typing')
def on_typing(data):
    username = next((u for u, s in online_users.items() if s == request.sid), None)
    if username:
        socketio.emit('typing_status', {'username': username, 'typing': data.get('typing', False)})


@socketio.on('mark_seen')
def on_mark_seen(data):
    message_id = data.get('message_id')
    if not message_id:
        return
    conn = get_db()
    try:
        row = conn.execute('SELECT sender_id FROM messages WHERE id=?', (message_id,)).fetchone()
        if row:
            conn.execute('UPDATE messages SET seen=1 WHERE id=?', (message_id,))
            conn.commit()
            sender = conn.execute('SELECT username FROM users WHERE id=?', (row['sender_id'],)).fetchone()
            if sender and sender['username'] in online_users:
                socketio.emit('message_seen', {'message_id': message_id},
                              to=online_users[sender['username']])
    finally:
        conn.close()


@app.route('/api/delete-message', methods=['POST'])
def delete_message():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json()
    msg_id = data.get('message_id')
    conn = get_db()
    try:
        msg = conn.execute('SELECT sender_id FROM messages WHERE id=?', (msg_id,)).fetchone()
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        if msg['sender_id'] != payload['user_id']:
            return jsonify({'error': 'Cannot delete others messages'}), 403
        conn.execute('UPDATE messages SET deleted=1 WHERE id=?', (msg_id,))
        conn.commit()
        other = conn.execute('SELECT username FROM users WHERE id != ?', (payload['user_id'],)).fetchone()
        if other and other['username'] in online_users:
            socketio.emit('message_deleted', {'message_id': msg_id}, to=online_users[other['username']])
        return jsonify({'message': 'Deleted'}), 200
    finally:
        conn.close()


@app.route('/api/react-message', methods=['POST'])
def react_message():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json()
    msg_id   = data.get('message_id')
    reaction = data.get('reaction')
    conn = get_db()
    try:
        conn.execute('UPDATE messages SET reaction=? WHERE id=?', (reaction, msg_id))
        conn.commit()
        socketio.emit('message_reaction', {'message_id': msg_id, 'reaction': reaction})
        return jsonify({'message': 'Reacted'}), 200
    finally:
        conn.close()

@app.route('/api/pin-message', methods=['POST'])
def pin_message():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    data   = request.get_json()
    msg_id = data.get('message_id')
    pinned = 1 if data.get('pinned') else 0
    conn   = get_db()
    try:
        conn.execute('UPDATE messages SET pinned=? WHERE id=?', (pinned, msg_id))
        conn.commit()
        socketio.emit('message_pinned', {'message_id': msg_id, 'pinned': bool(pinned)})
        return jsonify({'message': 'Pinned' if pinned else 'Unpinned'}), 200
    finally:
        conn.close()


@app.route('/api/edit-message', methods=['POST'])
def edit_message():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    data       = request.get_json()
    msg_id     = data.get('message_id')
    new_text   = (data.get('message') or '').strip()
    if not new_text:
        return jsonify({'error': 'Message cannot be empty'}), 400
    conn = get_db()
    try:
        msg = conn.execute('SELECT sender_id FROM messages WHERE id=?', (msg_id,)).fetchone()
        if not msg:
            return jsonify({'error': 'Not found'}), 404
        if msg['sender_id'] != payload['user_id']:
            return jsonify({'error': 'Cannot edit others messages'}), 403
        encrypted = encrypt_msg(new_text)
        conn.execute('UPDATE messages SET message=?, edited=1 WHERE id=?', (encrypted, msg_id))
        conn.commit()
        socketio.emit('message_edited', {'message_id': msg_id, 'message': new_text})
        return jsonify({'message': 'Edited'}), 200
    finally:
        conn.close()


@app.route('/api/pinned-messages', methods=['GET'])
def get_pinned():
    payload = verify_token()
    if not payload:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT m.id, m.message, m.message_type, m.timestamp, m.deleted,
                   COALESCE(m.edited,0) as edited,
                   u.username AS sender_name
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.pinned=1 AND m.deleted=0
            ORDER BY m.timestamp ASC
        ''').fetchall()
        msgs = [{'id': r['id'], 'message': decrypt_msg(r['message']),
                 'message_type': r['message_type'], 'timestamp': r['timestamp'],
                 'sender_name': r['sender_name'], 'edited': bool(r['edited'])} for r in rows]
        return jsonify({'messages': msgs}), 200
    finally:
        conn.close()


# ═════════════════════════════════════════════════════════════
# RUN
# ═════════════════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    print("\n🔒 CipherChat Backend")
    print("📡 Running at  → http://localhost:5000")
    print("─" * 44)

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)