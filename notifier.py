import smtplib
from email.message import EmailMessage
from email.utils import formatdate

from config import (
    GMAIL_ADDRESS,
    GMAIL_APP_PASSWORD,
    ALERT_TO,
    SMTP_HOST,
    SMTP_PORT,
)


def send_alert(result):
    """Send one formatted phishing/security alert email."""

    msg = EmailMessage()

    risk = result.get("risk_level", "UNKNOWN")
    score = result.get("score", 0)
    sender = result.get("sender", "Unknown")
    sender_domain = result.get("sender_domain", "Unknown")
    subject = result.get("subject", "No subject")

    reasons = "\n".join(
        f"  • {reason}"
        for reason in result.get("reasons", [])
    ) or "  • No specific reason recorded."

    urls = "\n".join(
        f"  • {url}"
        for url in result.get("urls", [])
    ) or "  • None"

    attachments = "\n".join(
        f"  • {a.get('filename', 'Unknown')} | "
        f"{a.get('content_type', 'Unknown')} | "
        f"{a.get('size', 0)} bytes"
        for a in result.get("attachments", [])
    ) or "  • None"

    msg["From"] = GMAIL_ADDRESS
    msg["To"] = ALERT_TO
    msg["Date"] = formatdate(localtime=True)
    msg["Subject"] = f"[PHISHING ALERT] {risk} risk | Score {score}"

    # Strong machine-readable marker so the detector can ignore its own alerts
    # without analyzing the alert body.
    msg["X-Phishing-Detector-Alert"] = "true"
    msg["X-Phishing-Detector-Version"] = "1.0"
    msg["Auto-Submitted"] = "auto-generated"

    body = f"""
============================================================
                 PHISHING SECURITY ALERT
============================================================

A Gmail message has been flagged by the local phishing detector.

RISK INFORMATION
-----------------
Risk Level       : {risk}
Risk Score       : {score}

EMAIL INFORMATION
-----------------
Sender           : {sender}
Sender Domain    : {sender_domain}
Subject          : {subject}

DETECTION REASONS
-----------------
{reasons}

SUSPICIOUS URLS
---------------
{urls}

ATTACHMENTS
-----------
{attachments}

RECOMMENDED ACTION
------------------
• Do not click suspicious links.
• Do not open unexpected attachments.
• Verify sensitive requests through a trusted channel.
• Report the original message if required by your organization.

IMPORTANT
---------
This alert is an automated heuristic assessment. It does not prove
that an email is malicious or legitimate.

The detector did not open or click any URL.

------------------------------------------------------------
Automated message from Gmail Phishing Detection System
------------------------------------------------------------
"""

    msg.set_content(body.strip())

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        timeout=20
    ) as smtp:
        smtp.login(
            GMAIL_ADDRESS,
            GMAIL_APP_PASSWORD
        )
        smtp.send_message(msg)
