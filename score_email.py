import email
import re
from email.header import decode_header
from bs4 import BeautifulSoup
from rules import RULES

def parse_email(raw_email: str) -> dict:
    msg = email.message_from_string(raw_email)
    
    subject_decoded, encoding = decode_header(msg.get("Subject", ""))[0]
    if isinstance(subject_decoded, bytes):
        subject_decoded = subject_decoded.decode(encoding or "utf-8", errors="ignore")
    
    parsed = {
        "from": msg.get("From", ""),
        "subject": subject_decoded,
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

def score_email(raw_email: str) -> dict:
    parsed = parse_email(raw_email)
    score = 0
    matched_rules = []

    # Aplicar reglas a todos los campos
    for rule in RULES:
        for field in ["body_plain", "body_html", "subject", "from"]:
            if re.search(rule["pattern"], str(parsed.get(field, "")), re.IGNORECASE):
                score += rule["score"]
                matched_rules.append(rule["name"])

    # Verificación técnica (SPF/DKIM/DMARC)
    if "fail" in parsed["spf"].lower():
        score += 2
        matched_rules.append("spf_fail")
    if not parsed["dkim"]:
        score += 2
        matched_rules.append("missing_dkim")
    if not parsed["dmarc"]:
        score += 2
        matched_rules.append("dmarc_fail")

    return {
        "score": score,
        "matched_rules": matched_rules
    }