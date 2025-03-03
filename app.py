from flask import Flask, request, jsonify
from score_email import score_email

app = Flask(__name__)

@app.route("/score", methods=["POST"])
def score_endpoint():
    raw_email = request.json.get("email")
    if not raw_email:
        return jsonify({"error": "El campo 'email' es requerido"}), 400
    
    try:
        score = score_email(raw_email)
        return jsonify({"score": score})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("Iniciando servidor Flask...")  # Mensaje de depuración
    app.run(host="0.0.0.0", port=5000, debug=True)