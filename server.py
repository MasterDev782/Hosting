from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)

# --- Load secrets from Render's Environment Variables ---
CRYPTOLENS_TOKEN = os.environ.get("CRYPTOLENS_TOKEN")
PRODUCT_ID = os.environ.get("PRODUCT_ID")
ORBITAL_API_KEY = os.environ.get("ORBITAL_API_KEY") # Note: This is not used by the client anymore, but good to keep here.

CRYPTOLENS_API_URL = "https://api.cryptolens.io/api/key/activate"

# --- In-memory dictionary to store temporary IP sessions ---
# This is simple and works well. It will be cleared if the server restarts.
IP_SESSIONS = {}

def get_user_ip():
    """
    Correctly gets the user's real IP address from behind Render's proxy.
    """
    if 'X-Forwarded-For' in request.headers:
        # The header can be a comma-separated list of IPs. The first one is the original client.
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

# --- NEW ENDPOINT: /request_session ---
@app.route("/request_session", methods=["POST"])
def request_session():
    """
    Receives a HWID from the client and records their current IP address.
    This "locks" the session to their IP for the next validation attempt.
    """
    hwid = request.json.get("machine_code")
    if not hwid:
        return jsonify({"status": "error", "message": "Machine code not provided."}), 400

    user_ip = get_user_ip()
    
    # Store the mapping: HWID -> User's IP
    IP_SESSIONS[hwid] = user_ip
    
    print(f"Session requested for HWID {hwid[:10]}... from IP {user_ip}") # Logging for you to see
    
    return jsonify({"status": "success", "message": "Session initiated."})

# --- UPDATED ENDPOINT: /validate ---
@app.route("/validate", methods=["POST"])
def validate_license():
    """
    Validates the license key, but now ALSO checks if the incoming IP
    matches the one stored in the session.
    """
    # Load data from the client request
    license_key = request.json.get("license_key")
    hwid = request.json.get("machine_code")
    
    if not license_key or not hwid:
        return jsonify({"status": "error", "message": "License key or machine ID not provided."}), 400

    # --- THE NEW IP CHECK ---
    current_user_ip = get_user_ip()
    stored_ip_for_hwid = IP_SESSIONS.get(hwid)

    if not stored_ip_for_hwid:
        return jsonify({"status": "error", "message": "No active session. Please restart the application."}), 403
        
    if current_user_ip != stored_ip_for_hwid:
        print(f"IP MISMATCH for HWID {hwid[:10]}... | Stored: {stored_ip_for_hwid}, Current: {current_user_ip}")
        return jsonify({"status": "error", "message": "IP address mismatch. Please restart the application."}), 403
    
    # If the IP check passes, we can now check with Cryptolens
    print(f"IP check PASSED for HWID {hwid[:10]}... Now validating key with Cryptolens.")

    # Prepare payload for Cryptolens
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

        # After the check, clear the session so it can't be re-used
        if hwid in IP_SESSIONS:
            del IP_SESSIONS[hwid]

        if data.get("result") != 0:
            return jsonify({ "status": "error", "message": data.get("message", "Invalid key or machine.") }), 403
        
        return jsonify({ "status": "success", "api_key": ORBITAL_API_KEY })

    except Exception as e:
        return jsonify({ "status": "error", "message": f"An unexpected server error occurred: {e}" }), 500
