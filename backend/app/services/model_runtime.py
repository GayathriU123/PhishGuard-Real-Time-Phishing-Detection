import json
import logging
import pickle
from functools import lru_cache
from pathlib import Path

from backend.app.config import MODEL_PATH
from ml.src.features import FEATURE_COLUMNS

logger = logging.getLogger(__name__)


@lru_cache(maxsize=2)
def _load_artifact(path_text: str, modified_ns: int) -> dict[str, object]:
    del modified_ns
    import joblib

    path = Path(path_text)
    try:
        artifact = joblib.load(path)
    except (OSError, ValueError, EOFError, ImportError, ModuleNotFoundError, pickle.UnpicklingError):
        logger.exception("Could not load the configured URL model artifact.")
        raise RuntimeError(
            "The configured model artifact could not be loaded. Retrain it or remove the invalid artifact."
        ) from None
    if not isinstance(artifact, dict) or not {
        "estimator",
        "threshold",
        "version",
        "metrics",
    }.issubset(artifact):
        raise RuntimeError("The configured model artifact is missing required metadata.")
    if tuple(artifact.get("features", ())) != FEATURE_COLUMNS:
        raise RuntimeError("The configured model artifact uses an incompatible feature schema.")
    return artifact


def model_artifact() -> dict[str, object] | None:
    if not MODEL_PATH.is_file():
        return None
    return _load_artifact(str(MODEL_PATH.resolve()), MODEL_PATH.stat().st_mtime_ns)


def predict_url(features: dict[str, float]) -> dict[str, object]:
    artifact = model_artifact()
    if artifact is None:
        return {
            "status": "not_trained",
            "prediction": None,
            "score": None,
            "threshold": None,
            "model_version": None,
            "note": "Train an approved URL dataset before using supervised predictions.",
        }
    ordered = {name: features[name] for name in FEATURE_COLUMNS}
    estimator = artifact["estimator"]
    try:
        import pandas as pd
        input_data = pd.DataFrame([ordered])
    except Exception:
        input_data = [[ordered[name] for name in FEATURE_COLUMNS]]
    score = float(estimator.predict_proba(input_data)[0][1])
    threshold = float(artifact["threshold"])
    return {
        "status": "available",
        "prediction": "phishing" if score >= threshold else "non_phishing",
        "score": score,
        "threshold": threshold,
        "model_version": artifact["version"],
        "note": "Calibrated model estimate, not certainty.",
    }


def model_card() -> dict[str, object]:
    artifact = model_artifact()
    if artifact is None:
        return {
            "status": "not_trained",
            "model_version": None,
            "algorithm": None,
            "trained_at": None,
            "threshold": None,
            "features": list(FEATURE_COLUMNS),
            "metrics": None,
            "dataset": None,
            "note": "No trained model artifact is installed.",
        }
    return {
        "status": "available",
        "model_version": artifact["version"],
        "algorithm": artifact.get("algorithm"),
        "trained_at": artifact.get("trained_at"),
        "threshold": artifact["threshold"],
        "features": list(artifact["features"]),
        "metrics": artifact["metrics"],
        "dataset": artifact.get("dataset"),
        "note": "Metrics are from the held-out URL test split.",
    }


def metrics_json(artifact: dict[str, object]) -> str:
    return json.dumps(artifact["metrics"], sort_keys=True)
