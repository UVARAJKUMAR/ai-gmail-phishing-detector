import re
from email import policy
from email.parser import BytesParser
from html import unescape

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")

def parse_email(raw_bytes: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)

def clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)]}>'\"")

def extract_urls(text: str):
    found = [clean_url(x) for x in URL_RE.findall(text or "")]
    return list(dict.fromkeys(found))

def html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html or "")
    html = re.sub(r"(?i)<br\s*/?>", "\n", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    return unescape(html)

def get_body_and_urls(msg):
    text_parts, html_parts = [], []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    text_parts.append(part.get_content())
                except Exception:
                    pass
            elif part.get_content_type() == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            if msg.get_content_type() == "text/html":
                html_parts.append(msg.get_content())
            else:
                text_parts.append(msg.get_content())
        except Exception:
            pass

    combined = "\n".join(text_parts)
    if html_parts:
        combined += "\n" + "\n".join(html_to_text(x) for x in html_parts)

    urls = extract_urls(combined)

    for html in html_parts:
        hrefs = re.findall(r"""(?is)href\s*=\s*["']([^"']+)["']""", html)
        for href in hrefs:
            if href.lower().startswith(("http://", "https://", "www.")):
                urls.append(clean_url(href))

    return combined, list(dict.fromkeys(urls))

def get_attachments(msg):
    result = []
    if not msg.is_multipart():
        return result

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unnamed"
            result.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b"")
            })
    return result
