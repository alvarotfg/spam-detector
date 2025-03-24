import email
import re
from email.header import decode_header
from bs4 import BeautifulSoup
from rules import RULES

def parse_email(raw_email: str) -> dict:
    msg = email.message_from_string(raw_email)
    parsed = {
        "from": msg.get("From", ""),
        "subject": decode_header(msg.get("Subject", ""))[0][0].decode(),
        "body_plain": "",
        "body_html": "",
        "attachments": [],
        "spf": msg.get("Received-SPF", ""),
        "dkim": msg.get("DKIM-Signature", ""),
        "dmarc": msg.get("Authentication-Results", "").lower().count("dmarc=pass") > 0
    }

    # Extraer cuerpo y adjuntos
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            parsed["body_plain"] += part.get_payload(decode=True).decode(errors="ignore")
        elif content_type == "text/html":
            html = part.get_payload(decode=True).decode(errors="ignore")
            parsed["body_html"] += BeautifulSoup(html, "html.parser").get_text()
        elif part.get_filename():
            parsed["attachments"].append(part.get_filename())

    return parsed

def score_email(raw_email: str) -> float:
    parsed = parse_email(raw_email)
    score = 0

    # Aplicar reglas a todos los campos
    for rule in RULES:
        for field in ["body_plain", "body_html", "subject", "from"]:
            if re.search(rule["pattern"], str(parsed.get(field, "")), re.IGNORECASE):
                score += rule["score"]

    # Verificación técnica (SPF/DKIM/DMARC)
    if "fail" in parsed["spf"].lower():
        score += 30
    if not parsed["dkim"]:
        score += 20
    if not parsed["dmarc"]:
        score += 25

    return score