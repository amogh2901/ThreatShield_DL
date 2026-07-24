import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

from flask import Flask, request, jsonify
from flask_cors import CORS

from detector import detect_attack
from logger import log_attack
from threat_intelligence import get_threat_info

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({
        "status": "ThreatShield API Running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:

        result = detect_attack(url)

        # Handle different detector return formats
        if isinstance(result, tuple):

            if len(result) == 3:
                attack, confidence, _ = result

            elif len(result) == 2:
                attack, confidence = result

            else:
                attack = result[0]
                confidence = 1.0

        else:
            attack = result
            confidence = 1.0

        info = get_threat_info(attack)

        log_attack(
            request=url,
            attack_type=attack,
            confidence=confidence,
            severity=info.get("severity", "LOW")
        )

        return jsonify({
            "attack": attack,
            "severity": info["severity"],
            "confidence": round(confidence * 100, 2)
        })

    except Exception as e:

        return jsonify({
            "attack": "error",
            "severity": "LOW",
            "confidence": 0,
            "error": str(e)
        })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )