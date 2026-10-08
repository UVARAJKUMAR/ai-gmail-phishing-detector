import ipaddress
import requests
from urllib.parse import urlparse
from email.header import decode_header, make_header
from email.utils import parseaddr

from config import ALLOWED_DOMAINS, BLOCKED_DOMAINS, SAFE_BROWSING_API_KEY

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"}
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".cmd", ".bat", ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".reg"}
URGENCY_WORDS = {"verify", "urgent", "immediately", "suspended", "locked", "password", "login", "confirm", "security alert", "invoice", "payment", "refund", "gift card", "account"}
BRAND_WORDS = {"microsoft", "google", "apple", "paypal", "amazon", "facebook", "instagram", "netflix", "bank"}

def decode_mime(value):
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return str(value or "")

def analyze_sender(msg):
    raw_from = msg.get("From", "")
    display_name, address = parseaddr(raw_from)
    display_name = decode_mime(display_name)
    address = address.lower().strip()
    domain = address.split("@", 1)[1] if "@" in address else ""
    score, reasons = 0, []

    if not address or "@" not in address:
        score += 30
        reasons.append("Sender address is malformed or missing.")

    if display_name and domain:
        for brand in BRAND_WORDS:
            if brand in display_name.lower() and brand not in domain:
                score += 18
                reasons.append(f"Display name mentions '{brand}' but sender domain is '{domain}'.")
                break

    if domain in BLOCKED_DOMAINS:
        score += 50
        reasons.append(f"Sender domain is on the configured blocklist: {domain}")

    if domain in ALLOWED_DOMAINS:
        score -= 10

    return score, reasons, address, domain

def analyze_url(url):
    score, reasons = 0, []
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = (parsed.hostname or "").lower().rstrip(".")

    if not domain:
        return 30, ["URL has no valid hostname."], domain

    try:
        ipaddress.ip_address(domain)
        score += 35
        reasons.append("URL uses a raw IP address instead of a domain name.")
    except ValueError:
        pass

    if domain.startswith("xn--") or ".xn--" in domain:
        score += 20
        reasons.append("URL uses punycode, which can be used in look-alike domains.")

    if domain in URL_SHORTENERS:
        score += 12
        reasons.append(f"URL uses a URL-shortening service: {domain}")

    if "@" in url:
        score += 25
        reasons.append("URL contains '@', which can hide the actual destination.")

    if parsed.scheme.lower() != "https":
        score += 8
        reasons.append("URL does not use HTTPS.")

    try:
        if parsed.port not in (None, 80, 443):
            score += 12
            reasons.append(f"URL uses an unusual port: {parsed.port}")
    except ValueError:
        score += 20
        reasons.append("URL contains an invalid port.")

    if len(url) > 180:
        score += 8
        reasons.append("URL is unusually long.")

    if domain.count(".") >= 4:
        score += 10
        reasons.append("URL contains many subdomain levels.")

    if any(word in url.lower() for word in ("login", "verify", "verification", "password", "signin", "secure", "account", "update", "confirm", "wallet")):
        score += 8
        reasons.append("URL contains common credential/security keywords.")

    if domain in BLOCKED_DOMAINS:
        score += 50
        reasons.append(f"URL domain is on the configured blocklist: {domain}")

    return score, reasons, domain

def safe_browsing_check(url):
    if not SAFE_BROWSING_API_KEY:
        return 0, []

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "gmail-phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=8)
        response.raise_for_status()
        matches = response.json().get("matches", [])
        if matches:
            types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return 60, ["Google Safe Browsing reported this URL: " + ", ".join(types)]
    except requests.RequestException as exc:
        return 0, [f"Safe Browsing check failed: {exc.__class__.__name__}"]

    return 0, []

def analyze_email(msg, body, urls, attachments):
    score, reasons = 0, []

    sender_score, sender_reasons, sender, sender_domain = analyze_sender(msg)
    score += sender_score
    reasons.extend(sender_reasons)

    subject = decode_mime(msg.get("Subject", ""))
    text_lower = (subject + "\n" + body).lower()
    urgency_hits = [w for w in URGENCY_WORDS if w in text_lower]

    if len(urgency_hits) >= 3:
        score += 12
        reasons.append("Message contains several urgency/security keywords: " + ", ".join(sorted(urgency_hits)[:6]))

    for url in urls[:25]:
        url_score, url_reasons, _ = analyze_url(url)
        score += url_score
        reasons.extend(url_reasons)
        sb_score, sb_reasons = safe_browsing_check(url)
        score += sb_score
        reasons.extend(sb_reasons)

    for attachment in attachments:
        filename = attachment["filename"].lower()
        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            score += 35
            reasons.append(f"Attachment has a potentially dangerous file type: {attachment['filename']}")

    reasons = list(dict.fromkeys(reasons))[:20]

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_level": level,
        "score": max(0, score),
        "reasons": reasons,
        "sender": sender,
        "sender_domain": sender_domain,
        "subject": subject,
        "urls": urls[:25],
        "attachments": attachments,
    }
