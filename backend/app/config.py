import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass


def configured_path(variable: str, default: str) -> Path:
    value = Path(os.getenv(variable, default)).expanduser()
    return value if value.is_absolute() else PROJECT_ROOT / value


DATABASE_PATH = configured_path("DATABASE_PATH", "phishguard.sqlite3")
MODEL_PATH = configured_path("MODEL_PATH", "ml/models/url_model.joblib")
THREAT_FEED_PATH = configured_path(
    "THREAT_FEED_PATH", "ml/data/raw/online-valid.csv"
)
MAX_EMAIL_BYTES = int(os.getenv("MAX_EMAIL_BYTES", str(1024 * 1024)))
