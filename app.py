from flask import Flask, request, jsonify
from flask_cors import CORS
from score_email import score_email

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return "Servidor de Spam Detector activo. Usa /score con POST", 200

@app.route("/score", methods=["POST"])
def score_endpoint():
    raw_email = request.json.get("email")
    if not raw_email:
        return jsonify({"error": "Campo 'email' requerido"}), 400
    
    try:
        return jsonify({"score": score_email(raw_email)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)