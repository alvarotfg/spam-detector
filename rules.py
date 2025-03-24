RULES = [
    # Palabras clave comunes en spam
    {
        "name": "urgent_keywords",
        "pattern": r"\b(urgente|verifica tu cuenta|actúa ahora)\b",
        "score": 15
    },
    {
        "name": "spam_keywords",
        "pattern": r"\b(oferta exclusiva|ganador afortunado|dinero fácil)\b",
        "score": 20
    },
    {
        "name": "phishing_keywords",
        "pattern": r"\b(phishing|suplantación|robo de identidad)\b",
        "score": 25
    },
    {
        "name": "lottery_keywords",
        "pattern": r"\b(lotería|premio|ganaste|sorteo)\b",
        "score": 20
    },
    {
        "name": "financial_keywords",
        "pattern": r"\b(banco|tarjeta de crédito|contraseña|seguridad)\b",
        "score": 15
    },
    {
        "name": "free_offers",
        "pattern": r"\b(gratis|sin costo|oferta limitada)\b",
        "score": 15
    },
    {
        "name": "adult_content",
        "pattern": r"\b(sexo|adulto|webcam|enlace explícito)\b",
        "score": 30
    },
    {
        "name": "medical_keywords",
        "pattern": r"\b(viagra|cialis|medicamento|receta)\b",
        "score": 25
    },
    {
        "name": "work_from_home",
        "pattern": r"\b(trabaja desde casa|ingresos extra|oportunidad de negocio)\b",
        "score": 20
    },
    {
        "name": "loan_keywords",
        "pattern": r"\b(préstamo|crédito|dinero rápido|interés bajo)\b",
        "score": 20
    },

    # URLs sospechosas
    {
        "name": "suspicious_urls",
        "pattern": r"http[s]?://(phishing|spam|fake)\.\S+",
        "score": 25
    },
    {
        "name": "shortened_urls",
        "pattern": r"http[s]?://(bit\.ly|goo\.gl|tinyurl\.com)\/\S+",
        "score": 15
    },
    {
        "name": "ip_based_urls",
        "pattern": r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "score": 20
    },
    {
        "name": "malicious_domains",
        "pattern": r"\.(xyz|top|club|online|gq)\b",
        "score": 15
    },
    {
        "name": "fake_banks",
        "pattern": r"http[s]?://(banco|bank|paypal)\.(fake|phishing)\.\S+",
        "score": 30
    },

    # Encabezados sospechosos
    {
        "name": "suspicious_from",
        "pattern": r"@(phishing-site|fake-domain|spammer)\.com",
        "score": 30
    },
    {
        "name": "invalid_reply_to",
        "pattern": r"Reply-To: .*@(example|fake)\.com",
        "score": 20
    },
    {
        "name": "mismatched_sender",
        "pattern": r"From: .*@\S+\.\S+\nReply-To: .*@\S+\.\S+",
        "score": 25
    },
    {
        "name": "no_subject",
        "pattern": r"Subject:\s*$",
        "score": 10
    },
    {
        "name": "generic_subject",
        "pattern": r"Subject: (Hola|Hola amigo|Estimado cliente)",
        "score": 15
    },

    # Metadatos y encabezados técnicos
    {
        "name": "missing_dkim",
        "pattern": r"DKIM-Signature: .*",
        "score": -10  # Restar puntos si DKIM está presente
    },
    {
        "name": "spf_fail",
        "pattern": r"Received-SPF: fail",
        "score": 30
    },
    {
        "name": "dmarc_fail",
        "pattern": r"DMARC-Filter: fail",
        "score": 25
    },
    {
        "name": "no_mx_record",
        "pattern": r"Received: .*no MX record",
        "score": 20
    },
    {
        "name": "blacklisted_ip",
        "pattern": r"Received: .*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]",
        "score": 30
    },

    # Patrones avanzados
    {
        "name": "html_forms",
        "pattern": r"<form\b[^>]*>",
        "score": 20
    },
    {
        "name": "javascript_code",
        "pattern": r"<script\b[^>]*>",
        "score": 25
    },
    {
        "name": "hidden_text",
        "pattern": r"style=['\"]display:\s*none",
        "score": 20
    },
    {
        "name": "fake_buttons",
        "pattern": r"<a\b[^>]*>\s*(clic aquí|ver más)\s*</a>",
        "score": 15
    },
    {
        "name": "fake_logos",
        "pattern": r"<img\b[^>]*src=['\"](.*logo.*)['\"]",
        "score": 10
    },

    # Reglas adicionales
    {
        "name": "excessive_punctuation",
        "pattern": r"!!!|\?\?\?|\.\.\.",
        "score": 10
    },
    {
        "name": "all_caps_subject",
        "pattern": r"Subject: [A-Z\s]{10,}",
        "score": 15
    },
    {
        "name": "exclamation_marks",
        "pattern": r"!{3,}",
        "score": 10
    },
    {
        "name": "too_many_links",
        "pattern": r"(http[s]?://\S+){5,}",
        "score": 20
    },
    {
        "name": "fake_attachments",
        "pattern": r"Content-Disposition: attachment; filename=['\"].*\.(exe|bat|scr)['\"]",
        "score": 30
    },

    # Reglas específicas para phishing
    {
        "name": "fake_login_pages",
        "pattern": r"http[s]?://\S+/login\b",
        "score": 25
    },
    {
        "name": "fake_reset_links",
        "pattern": r"http[s]?://\S+/reset-password\b",
        "score": 25
    },
    {
        "name": "fake_bank_links",
        "pattern": r"http[s]?://\S+/banking\b",
        "score": 30
    },
    {
        "name": "fake_payment_links",
        "pattern": r"http[s]?://\S+/payment\b",
        "score": 30
    },
    {
        "name": "fake_support_links",
        "pattern": r"http[s]?://\S+/support\b",
        "score": 20
    },

    # Reglas adicionales para mejorar la detección
    {
        "name": "fake_social_media",
        "pattern": r"http[s]?://\S+/(facebook|twitter|instagram)\b",
        "score": 20
    },
    {
        "name": "fake_shopping_links",
        "pattern": r"http[s]?://\S+/(shop|cart|checkout)\b",
        "score": 25
    },
    {
        "name": "fake_download_links",
        "pattern": r"http[s]?://\S+/download\b",
        "score": 20
    },
    {
        "name": "fake_news_links",
        "pattern": r"http[s]?://\S+/(news|article)\b",
        "score": 15
    },
    {
        "name": "fake_job_offers",
        "pattern": r"http[s]?://\S+/(careers|jobs)\b",
        "score": 20
    }
]