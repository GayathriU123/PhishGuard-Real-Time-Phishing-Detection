import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
URGENT_TERMS = (
    "urgent",
    "immediately",
    "within 24 hours",
    "suspended",
    "action required",
)
SENSITIVE_TERMS = (
    "password",
    "sign in",
    "verify your account",
    "payment",
    "bank",
    "invoice",
    "credentials",
)


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _decode_message(raw: bytes) -> tuple[object, str]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("The email could not be parsed. Check the message format.") from exc
    text_parts: list[str] = []
    link_sources: list[str] = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = (message,)
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        link_sources.append(content)
        if part.get_content_type() == "text/html":
            extractor = _HTMLTextExtractor()
            extractor.feed(content)
            text_parts.extend(extractor.text)
            link_sources.extend(extractor.hrefs)
        else:
            text_parts.append(content)
    return message, "\n".join(text_parts + link_sources)


def _email_address_domain(header: str | None) -> tuple[str | None, str | None]:
    if not header:
        return None, None
    display_name, address = parseaddr(str(header))
    if "@" not in address:
        return display_name or None, None
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return display_name or None, None
    return display_name or None, domain or None


def _extract_urls(text: str, max_urls: int = 20) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
            if len(urls) >= max_urls:
                break
    return urls


def parse_email(raw: bytes) -> dict[str, object]:
    message, searchable = _decode_message(raw)
    sender_header = str(message.get("From", "")) or None
    reply_to_header = str(message.get("Reply-To", "")) or None
    sender_name, sender_domain = _email_address_domain(sender_header)
    _, reply_domain = _email_address_domain(reply_to_header)
    lower_text = searchable.lower()
    subject = str(message.get("Subject", ""))[:200] or None
    signals: list[dict[str, str | int]] = []
    if sender_domain and reply_domain and sender_domain != reply_domain:
        signals.append(
            {
                "type": "rule",
                "severity": "high",
                "points": 25,
                "title": "From and Reply-To domains differ",
                "description": "Replies would go to a different domain than the displayed sender.",
            }
        )
    urgent_found = next((term for term in URGENT_TERMS if term in lower_text), None)
    if urgent_found:
        signals.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 10,
                "title": "Urgency language",
                "description": "The message contains a common pressure tactic.",
            }
        )
    sensitive_found = next((term for term in SENSITIVE_TERMS if term in lower_text), None)
    if sensitive_found:
        signals.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 10,
                "title": "Credential or payment wording",
                "description": "The message refers to credentials, account access, or a payment.",
            }
        )
    urls = _extract_urls(searchable)
    if len(urls) > 3:
        signals.append(
            {
                "type": "rule",
                "severity": "low",
                "points": 5,
                "title": "Multiple links",
                "description": f"The message contains {len(urls)} distinct links.",
            }
        )
    return {
        "subject": subject,
        "sender_name": sender_name,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
        "urls": urls,
        "signals": signals,
    }
