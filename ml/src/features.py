import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

FEATURE_COLUMNS = (
    "url_length",
    "host_length",
    "dot_count",
    "subdomain_depth",
    "path_length",
    "query_length",
    "hyphen_count",
    "digit_count",
    "at_count",
    "percent_count",
    "has_ip_host",
    "has_https",
    "has_punycode",
    "has_nonstandard_port",
    "suspicious_token_count",
    "character_entropy",
)

SUSPICIOUS_TOKENS = (
    "account",
    "billing",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
)
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def parse_http_url(value: str) -> tuple[str, object, str]:
    if not isinstance(value, str):
        raise ValueError("Enter a complete HTTP or HTTPS URL.")
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        raise ValueError("URL must contain 1–2048 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValueError("URL cannot contain control characters.")
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc
    if scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("Enter a complete URL beginning with http:// or https://.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL hostname is not valid.") from exc
    if not ascii_host:
        raise ValueError("URL must include a hostname.")
    try:
        ipaddress.ip_address(ascii_host)
        is_ip_host = True
    except ValueError:
        is_ip_host = False
    if ":" in ascii_host and is_ip_host:
        canonical_host = f"[{ascii_host}]"
    else:
        canonical_host = ascii_host
    netloc = canonical_host + (f":{port}" if port is not None else "")
    normalized = urlunsplit(
        (scheme, netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized, parsed, ascii_host


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def extract_url_features(value: str) -> dict[str, float]:
    normalized, parsed, hostname = parse_http_url(value)
    try:
        ipaddress.ip_address(hostname)
        has_ip_host = 1.0
    except ValueError:
        has_ip_host = 0.0
    labels = hostname.split(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is not valid.") from exc
    url_text = normalized.lower()
    tokens = set(_TOKEN_PATTERN.findall(url_text))
    return {
        "url_length": float(len(normalized)),
        "host_length": float(len(hostname)),
        "dot_count": float(hostname.count(".")),
        "subdomain_depth": float(max(0, len(labels) - 2)),
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "hyphen_count": float(normalized.count("-")),
        "digit_count": float(sum(character.isdigit() for character in normalized)),
        "at_count": float(normalized.count("@")),
        "percent_count": float(normalized.count("%")),
        "has_ip_host": has_ip_host,
        "has_https": float(parsed.scheme.lower() == "https"),
        "has_punycode": float("xn--" in hostname),
        "has_nonstandard_port": float(
            port is not None
            and port != (443 if parsed.scheme.lower() == "https" else 80)
        ),
        "suspicious_token_count": float(
            sum(token in tokens for token in SUSPICIOUS_TOKENS)
        ),
        "character_entropy": _entropy(normalized),
    }


def redact_url(value: str) -> str:
    normalized, parsed, _ = parse_http_url(value)
    path = parsed.path or "/"
    clipped_path = path if len(path) <= 64 else path[:61] + "..."
    return urlunsplit((parsed.scheme, parsed.netloc, clipped_path, "", ""))


def url_hash(value: str) -> str:
    import hashlib

    normalized, _, _ = parse_http_url(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def rule_evidence(features: dict[str, float]) -> list[dict[str, str | int]]:
    evidence: list[dict[str, str | int]] = []
    if features["has_ip_host"]:
        evidence.append(
            {
                "type": "rule",
                "severity": "high",
                "points": 30,
                "title": "IP address used as hostname",
                "description": "The destination uses a numeric IP address instead of a domain name.",
            }
        )
    if features["has_punycode"]:
        evidence.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 20,
                "title": "Punycode hostname",
                "description": "The hostname contains an encoded internationalized label; verify it carefully.",
            }
        )
    if features["url_length"] > 180:
        evidence.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 15,
                "title": "Unusually long URL",
                "description": "Long URLs can obscure their destination; length alone is not proof of phishing.",
            }
        )
    elif features["url_length"] > 100:
        evidence.append(
            {
                "type": "rule",
                "severity": "low",
                "points": 7,
                "title": "Long URL",
                "description": "The URL is longer than typical; length alone is a weak signal.",
            }
        )
    if features["subdomain_depth"] > 3:
        evidence.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 12,
                "title": "Deep subdomain chain",
                "description": "The hostname contains several subdomain labels.",
            }
        )
    if features["suspicious_token_count"]:
        evidence.append(
            {
                "type": "rule",
                "severity": "low",
                "points": min(12, int(features["suspicious_token_count"]) * 4),
                "title": "Sensitive-action wording",
                "description": "The URL contains terms commonly used in account or sign-in flows.",
            }
        )
    if features["at_count"]:
        evidence.append(
            {
                "type": "rule",
                "severity": "medium",
                "points": 12,
                "title": "At-sign in URL",
                "description": "An at-sign appears outside the hostname and may make a URL harder to read.",
            }
        )
    if features["percent_count"] > 2:
        evidence.append(
            {
                "type": "rule",
                "severity": "low",
                "points": 5,
                "title": "Encoded characters",
                "description": "The URL contains repeated percent-encoded characters.",
            }
        )
    if not features["has_https"]:
        evidence.append(
            {
                "type": "rule",
                "severity": "low",
                "points": 2,
                "title": "HTTP without TLS",
                "description": "The URL uses HTTP. HTTPS alone would not prove a site is safe.",
            }
        )
    return evidence
