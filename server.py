# server.py for Render

from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)

# These secrets are loaded from the Render environment
CRYPTOLENS_TOKEN = os.environ.get("CRYPTOLENS_TOKEN")
PRODUCT_ID = os.environ.get("PRODUCT_ID")
ORBITAL_API_KEY = os.environ.get("ORBITAL_API_KEY")

CRYPTOLENS_API_URL = "https://api.cryptolens.io/api/key/activate"

@app.route("/validate", methods=["POST"])
def validate_license():
    if not all([CRYPTOLENS_TOKEN, PRODUCT_ID, ORBITAL_API_KEY]):
        return jsonify({ "status": "error", "message": "Backend server is not configured correctly." }), 500

    license_key = request.json.get("license_key")
    machine_code = request.json.get("machine_code")

    if not license_key or not machine_code:
        return jsonify({ "status": "error", "message": "License key or machine ID not provided." }), 400

    payload = {
        "token": CRYPTOLENS_TOKEN,
        "ProductId": PRODUCT_ID,
        "Key": license_key,
        "MachineCode": machine_code
    }

    try:
        response = requests.post(CRYPTOLENS_API_URL, data=payload)
        response.raise_for_status()
        data = response.json()

        if data.get("result") != 0:
            return jsonify({ "status": "error", "message": data.get("message", "Invalid key or machine.") }), 403
        
        return jsonify({ "status": "success", "api_key": ORBITAL_API_KEY })

    except Exception as e:
        return jsonify({ "status": "error", "message": f"An unexpected server error occurred: {e}" }), 500

# Render needs this to run with Gunicorn
# No need for an if __name__ == "__main__": block