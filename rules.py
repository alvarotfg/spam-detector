RULES = [
    (r"oferta exclusiva", 10),
    (r"ganador afortunado", 15),
    (r"urgente", 5),
    (r"http[s]?://\S+", 20),  # Enlaces
    (r"suspicious-domain\.com", 25),  # Dominios sospechosos
    (r"phishing", 10),  # Palabra "phishing"
    (r"verifica tu cuenta", 15),  # Frase común en phishing
]