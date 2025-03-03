import email
import re
from rules import RULES

def score_email(raw_email: str) -> float:
    msg = email.message_from_string(raw_email)
    from_email = msg.get("from", "")
    subject = msg.get("subject", "")
    body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
            elif content_type == "text/html":
                body = part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")
    
    score = 0
    for pattern, points in RULES:
        if re.search(pattern, body, re.IGNORECASE):
            score += points
        if re.search(pattern, subject, re.IGNORECASE):
            score += points
        if re.search(pattern, from_email, re.IGNORECASE):
            score += points
    
    return min(score, 100)