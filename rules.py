RULES = [
    {
        "name": "urgent_keywords",
        "pattern": r"\b(urgente|verifica tu cuenta|actúa ahora)\b",
        "score": 15
    },
    {
        "name": "suspicious_links",
        "pattern": r"http[s]?://(phishing-site|fake-domain)\.com",
        "score": 25
    },
    {
        "name": "generic_spam_terms",
        "pattern": r"\b(oferta exclusiva|ganador afortunado)\b",
        "score": 20
    }
]