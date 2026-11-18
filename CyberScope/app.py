from flask import Flask, jsonify, request
from config import Config
import hashlib
import base64

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.after_request
    def apply_defensive_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.route("/api/dashboard", methods=["GET"])
    def dashboard_summary():
        return jsonify({"status": "ok", "platform": "CyberScope v1.0"})

    @app.route("/api/crypto/hash", methods=["POST"])
    def crypto_hash():
        payload = request.get_json(silent=True) or {}
        text = payload.get("text", "").encode("utf-8")
        return jsonify({
            "sha256": hashlib.sha256(text).hexdigest(),
            "sha512": hashlib.sha512(text).hexdigest()
        })

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
