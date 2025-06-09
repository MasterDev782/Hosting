# server.py on Render (with IP Lock)

from flask import Flask, request, jsonify
import os
import requests
import time

app = Flask(__name__)

# --- Load secrets from environment variables ---
CRYPTOLENS_TOKEN = os.environ.get("CRYPTOLENS_TOKEN")
PRODUCT_ID = os.environ.get("PRODUCT_ID")
ORBITAL_API_KEY = os.environ.get("ORBITAL_API_KEY")

# --- Simple in-memory store for IP-locked sessions ---
# Format: { "hwid": ("ip_address", expiry_timestamp) }
active_sessions = {}

# --- NEW ENDPOINT to initiate a session ---
@app.route("/request_session", methods=["POST"])
def request_session():
    hwid = request.json.get("machine_code")
    if not hwid:
        return jsonify({"status": "error", "message": "HWID required."}), 400

    # Get the client's public IP address. Render provides this in the headers.
    # The 'X-Forwarded-For' header is standard for this.
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # Set expiry for 60 seconds from now
    expiry = time.time() + 60
    
    # Store the session, locking the HWID to the current IP
    active_sessions[hwid] = (client_ip, expiry)
    
    # Tell the client it's okay to proceed
    return jsonify({"status": "success", "message": "Session initiated."})


# --- UPDATED /validate ENDPOINT ---
@app.route("/validate", methods=["POST"])
def validate_license():
    license_key = request.json.get("license_key")
    hwid = request.json.get("machine_code")
    
    # Get the IP of the machine making THIS request
    current_request_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # --- THE NEW IP-LOCK CHECK ---
    if hwid not in active_sessions:
        return jsonify({"status": "error", "message": "No active session. Please restart."}), 400

    stored_ip, expiry_time = active_sessions[hwid]

    if time.time() > expiry_time:
        del active_sessions[hwid] # Clean up expired session
        return jsonify({"status": "error", "message": "Session expired. Please restart."}), 400
        
    if stored_ip != current_request_ip:
        # IPs do not match! This is a potential replay attack.
        del active_sessions[hwid] # Invalidate the session
        return jsonify({"status": "error", "message": "IP mismatch. Security check failed."}), 403

    # If we get here, the IP lock is valid.
    # We can now consume the session so it can't be used again for another /validate call.
    del active_sessions[hwid]

    # --- PROCEED WITH THE ORIGINAL CRYPTOLENS CHECK ---
    payload = {
        "token": CRYPTOLENS_TOKEN,
        "ProductId": PRODUCT_ID,
        "Key": license_key,
        "MachineCode": hwid
    }
    try:
        response = requests.post("https://api.cryptolens.io/api/key/activate", data=payload)
        response.raise_for_status()
        data = response.json()
        if data.get("result") != 0:
            return jsonify({ "status": "error", "message": data.get("message", "Invalid key or machine.") }), 403
        
        # We don't need to return the API key if the goal is only to protect the app startup
        return jsonify({ "status": "success" })
    except Exception as e:
        return jsonify({ "status": "error", "message": f"An unexpected server error occurred: {e}" }), 500
