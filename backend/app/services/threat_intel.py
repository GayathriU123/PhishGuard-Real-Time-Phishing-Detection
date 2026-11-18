import csv
import logging
from functools import lru_cache
from pathlib import Path

from backend.app.config import THREAT_FEED_PATH
from ml.src.features import parse_http_url, url_hash

logger = logging.getLogger(__name__)


@lru_cache(maxsize=3)
def _feed_index(path_text: str, modified_ns: int) -> frozenset[str]:
    del modified_ns
    path = Path(path_text)
    if not path.is_file():
        return frozenset()
    matches: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as feed:
        reader = csv.DictReader(feed)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError("Threat feed CSV must contain a 'url' column.")
        for row in reader:
            value = row.get("url")
            if not value:
                continue
            try:
                matches.add(url_hash(value))
            except ValueError:
                logger.warning("Skipped a malformed URL in the local threat feed.")
    return frozenset(matches)


def lookup_url(value: str) -> dict[str, object]:
    path = THREAT_FEED_PATH
    if not path.is_file():
        return {
            "status": "unavailable",
            "provider": "PhishTank local feed",
            "matched": False,
            "checked_at": None,
            "message": "No local feed is installed.",
        }
    matches = _feed_index(str(path.resolve()), path.stat().st_mtime_ns)
    return {
        "status": "available",
        "provider": "PhishTank local feed",
        "matched": url_hash(value) in matches,
        "checked_at": None,
        "message": "Exact URL match checked against the local verified feed.",
    }


def feed_status() -> dict[str, object]:
    path = THREAT_FEED_PATH
    if not path.is_file():
        return {
            "provider": "PhishTank",
            "status": "unavailable",
            "feed_file_present": False,
            "records_loaded": 0,
            "last_synced": None,
            "note": "Download an approved verified feed and configure THREAT_FEED_PATH.",
        }
    matches = _feed_index(str(path.resolve()), path.stat().st_mtime_ns)
    return {
        "provider": "PhishTank",
        "status": "available",
        "feed_file_present": True,
        "records_loaded": len(matches),
        "last_synced": path.stat().st_mtime,
        "note": "Local feed lookups are exact-URL matches; no network request is made.",
    }
