import os
from dotenv import load_dotenv

load_dotenv()

def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

GMAIL_ADDRESS = required("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = required("GMAIL_APP_PASSWORD")
ALERT_TO = os.getenv("ALERT_TO", GMAIL_ADDRESS).strip()

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))
MAX_EMAILS_PER_CYCLE = int(os.getenv("MAX_EMAILS_PER_CYCLE", "20"))
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()

ALLOWED_DOMAINS = {x.strip().lower() for x in os.getenv("ALLOWED_DOMAINS", "").split(",") if x.strip()}
BLOCKED_DOMAINS = {x.strip().lower() for x in os.getenv("BLOCKED_DOMAINS", "").split(",") if x.strip()}
ALERT_ON_MEDIUM = os.getenv("ALERT_ON_MEDIUM", "true").lower() in {"1", "true", "yes", "y", "on"}

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
