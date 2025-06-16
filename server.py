# FILE: server.py (Final Version with HWID and IP Locking)

from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)

# --- Load secrets from Render's Environment Variables ---
CRYPTOLENS_TOKEN = os.environ.get("CRYPTOLENS_TOKEN")
PRODUCT_ID = os.environ.get("PRODUCT_ID")
ORBITAL_API_KEY = os.environ.get("ORBITAL_API_KEY")

CRYPTOLENS_API_URL = "https://api.cryptolens.io/api/key/activate"

# --- In-memory dictionary to store temporary IP sessions ---
# Key: HWID, Value: User's IP Address
IP_SESSIONS = {}

def get_user_ip():
    """Correctly gets the user's real IP address from behind Render's proxy."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

@app.route("/request_session", methods=["POST"])
def request_session():
    """
    Step 1: Client sends its HWID. The server records the client's IP address
    and associates it with their HWID for a short time.
    """
    hwid = request.json.get("machine_code")
    if not hwid:
        return jsonify({"status": "error", "message": "Machine code not provided."}), 400

    user_ip = get_user_ip()
    IP_SESSIONS[hwid] = user_ip
    
    print(f"Session requested for HWID {hwid[:10]}... from IP {user_ip}") # For your logs
    
    return jsonify({"status": "success", "message": "Session initiated."})

@app.route("/validate", methods=["POST"])
def validate_license():
    """
    Step 2: Client sends HWID and license key. The server validates the IP,
    then checks with Cryptolens, and finally returns the API key.
    """
    if not all([CRYPTOLENS_TOKEN, PRODUCT_ID, ORBITAL_API_KEY]):
        return jsonify({ "status": "error", "message": "Backend server is not configured correctly." }), 500

    license_key = request.json.get("license_key")
    hwid = request.json.get("machine_code")
    
    if not license_key or not hwid:
        return jsonify({"status": "error", "message": "License key or machine ID not provided."}), 400

    # --- IP Validation Check ---
    current_user_ip = get_user_ip()
    stored_ip_for_hwid = IP_SESSIONS.get(hwid)

    if not stored_ip_for_hwid:
        return jsonify({"status": "error", "message": "No active session. Please restart the application."}), 403
        
    if current_user_ip != stored_ip_for_hwid:
        print(f"IP MISMATCH for HWID {hwid[:10]}... | Stored: {stored_ip_for_hwid}, Current: {current_user_ip}")
        return jsonify({"status": "error", "message": "IP address mismatch. Please restart the application."}), 403
    
    # IP check passed, now validate with Cryptolens
    payload = {
        "token": CRYPTOLENS_TOKEN,
        "ProductId": PRODUCT_ID,
        "Key": license_key,
        "MachineCode": hwid
    }

    try:
        response = requests.post(CRYPTOLENS_API_URL, data=payload)
        response.raise_for_status()
        data = response.json()

        # IMPORTANT: Clean up the session so it can't be re-used
        if hwid in IP_SESSIONS:
            del IP_SESSIONS[hwid]

        if data.get("result") != 0:
            return jsonify({ "status": "error", "message": data.get("message", "Invalid key or machine.") }), 403
        
        # --- SUCCESS ---
        # Respond with the secret OrbitalStress API key
        return jsonify({ "status": "success", "api_key": ORBITAL_API_KEY })

    except Exception as e:
        return jsonify({ "status": "error", "message": f"An unexpected server error occurred: {e}" }), 500
