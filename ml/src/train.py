import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression

from ml.src.features import FEATURE_COLUMNS, extract_url_features, parse_http_url

LOGGER = logging.getLogger("phishguard.train")
RANDOM_SEED = 42
MULTI_LABEL_SUFFIXES = {
    "ac.uk",
    "co.in",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.sg",
    "com.tr",
    "com.tw",
    "gov.uk",
    "net.au",
    "org.uk",
}


def _domain_group(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return host.lower().strip(".")
    suffix = ".".join(labels[-2:])
    suffix_size = 3 if suffix in MULTI_LABEL_SUFFIXES and len(labels) >= 3 else 2
    return ".".join(labels[-suffix_size:])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_phishtank_urls(path: Path) -> tuple[list[str], int]:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    columns = {column.lower(): column for column in frame.columns}
    if "url" not in columns:
        raise ValueError("PhishTank CSV must include a 'url' column.")
    if "verified" in columns:
        frame = frame[frame[columns["verified"]].str.lower() == "yes"]
    if "online" in columns:
        frame = frame[frame[columns["online"]].str.lower() == "yes"]
    raw_urls = frame[columns["url"]].tolist()
    accepted: list[str] = []
    for raw_url in raw_urls:
        try:
            normalized, _, _ = parse_http_url(raw_url)
            accepted.append(normalized)
        except ValueError:
            continue
    return accepted, len(raw_urls) - len(accepted)


def _tranco_domains(path: Path) -> tuple[list[str], int]:
    frame = pd.read_csv(
        path,
        header=None,
        names=["rank", "domain"],
        dtype=str,
        compression="infer",
        keep_default_na=False,
    )
    domains: list[str] = []
    rejected = 0
    for raw_domain in frame["domain"]:
        domain = raw_domain.strip().lower().rstrip(".")
        if not domain or "/" in domain or ":" in domain or " " in domain:
            rejected += 1
            continue
        try:
            normalized, _, _ = parse_http_url(f"https://{domain}/")
            domains.append(normalized)
        except ValueError:
            rejected += 1
    return domains, rejected


def build_dataset(
    phishtank_path: Path, tranco_path: Path, max_negative: int
) -> tuple[pd.DataFrame, dict[str, Any]]:
    phishing_urls, invalid_phishing = _verified_phishtank_urls(phishtank_path)
    candidate_urls, invalid_candidates = _tranco_domains(tranco_path)
    positive_rows: list[dict[str, Any]] = []
    positive_groups: set[str] = set()
    seen_urls: set[tuple[int, str]] = set()
    for value in phishing_urls:
        normalized, _, host = parse_http_url(value)
        key = (1, normalized)
        if key in seen_urls:
            continue
        seen_urls.add(key)
        positive_groups.add(_domain_group(host))
        positive_rows.append(
            {"url": normalized, "label": 1, "domain_group": _domain_group(host)}
        )

    negative_rows: list[dict[str, Any]] = []
    for value in candidate_urls:
        normalized, _, host = parse_http_url(value)
        group = _domain_group(host)
        if group in positive_groups:
            continue
        key = (0, normalized)
        if key in seen_urls:
            continue
        seen_urls.add(key)
        negative_rows.append({"url": normalized, "label": 0, "domain_group": group})

    if max_negative > 0 and len(negative_rows) > max_negative:
        negative_frame = pd.DataFrame(negative_rows).sample(
            n=max_negative, random_state=RANDOM_SEED
        )
        negative_rows = negative_frame.to_dict(orient="records")
    rows = positive_rows + negative_rows
    if len(positive_rows) < 3 or len(negative_rows) < 3:
        raise ValueError(
            "Training needs at least 3 unique URLs in each class after filtering. "
            "Check both source files and instructor-approved label assumptions."
        )

    feature_rows: list[dict[str, float]] = []
    for row in rows:
        feature_rows.append(extract_url_features(str(row["url"])))
    frame = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    frame["label"] = [int(row["label"]) for row in rows]
    frame["domain_group"] = [str(row["domain_group"]) for row in rows]
    frame["url"] = [str(row["url"]) for row in rows]
    manifest = {
        "snapshot_date": datetime.now(timezone.utc).date().isoformat(),
        "sources": {
            "phishtank": {
                "filename": phishtank_path.name,
                "sha256": _sha256(phishtank_path),
                "file_modified_at": datetime.fromtimestamp(
                    phishtank_path.stat().st_mtime, timezone.utc
                ).isoformat(),
                "verified_url_rows": len(positive_rows),
                "excluded_malformed_rows": invalid_phishing,
            },
            "tranco": {
                "filename": tranco_path.name,
                "sha256": _sha256(tranco_path),
                "file_modified_at": datetime.fromtimestamp(
                    tranco_path.stat().st_mtime, timezone.utc
                ).isoformat(),
                "candidate_url_rows": len(negative_rows),
                "excluded_malformed_rows": invalid_candidates,
                "warning": "Popularity-ranked domains are proxy negative labels, not verified benign URLs.",
            },
        },
        "class_counts": {
            "phishing": len(positive_rows),
            "candidate_non_phishing": len(negative_rows),
        },
        "unique_domain_groups": int(frame["domain_group"].nunique()),
        "split_seed": RANDOM_SEED,
        "feature_columns": list(FEATURE_COLUMNS),
        "split_note": "Grouped by a built-in common-suffix heuristic, not a complete Public Suffix List.",
    }
    return frame, manifest


def _grouped_split(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    indices = np.arange(len(frame))
    groups = frame["domain_group"].to_numpy()
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_SEED)
    train_validation, test = next(outer.split(indices, frame["label"], groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=RANDOM_SEED)
    train_relative, validation_relative = next(
        inner.split(
            train_validation,
            frame["label"].iloc[train_validation],
            groups[train_validation],
        )
    )
    train = train_validation[train_relative]
    validation = train_validation[validation_relative]
    for name, split in (("train", train), ("validation", validation), ("test", test)):
        if frame["label"].iloc[split].nunique() != 2:
            raise ValueError(
                f"The grouped {name} split does not contain both classes. "
                "Collect more distinct phishing and candidate negative domains."
            )
    return train, validation, test


def _candidate_estimators() -> dict[str, Any]:
    return {
        "DummyClassifier": CalibratedClassifierCV(
            estimator=DummyClassifier(strategy="prior"), method="sigmoid", cv=3
        ),
        "LogisticRegression": CalibratedClassifierCV(
            estimator=make_pipeline(
                StandardScaler(),
                LogisticRegression(
                    class_weight="balanced", max_iter=2000, random_state=RANDOM_SEED
                ),
            ),
            method="sigmoid",
            cv=3,
        ),
        "RandomForest": CalibratedClassifierCV(
            estimator=RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced_subsample",
                random_state=RANDOM_SEED,
                n_jobs=-1,
            ),
            method="sigmoid",
            cv=3,
        ),
        "LinearSVM": CalibratedClassifierCV(
            estimator=make_pipeline(
                StandardScaler(),
                LinearSVC(
                    class_weight="balanced",
                    random_state=RANDOM_SEED,
                    dual="auto",
                ),
            ),
            method="sigmoid",
            cv=3,
        ),
    }


def _select_threshold(labels: np.ndarray, scores: np.ndarray) -> float:
    candidates = np.arange(0.05, 0.96, 0.01)
    return float(
        max(
            candidates,
            key=lambda threshold: (
                fbeta_score(labels, scores >= threshold, beta=2, zero_division=0),
                threshold,
            ),
        )
    )


def _evaluation_metrics(
    labels: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, Any]:
    predictions = (scores >= threshold).astype(int)
    return {
        "threshold": threshold,
        "precision_phishing": float(precision_score(labels, predictions, zero_division=0)),
        "recall_phishing": float(recall_score(labels, predictions, zero_division=0)),
        "f1_phishing": float(f1_score(labels, predictions, zero_division=0)),
        "macro_f1": float(f1_score(labels, predictions, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "accuracy": float(accuracy_score(labels, predictions)),
        "pr_auc": float(average_precision_score(labels, scores)),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "brier_score": float(brier_score_loss(labels, scores)),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=[0, 1]).tolist(),
        "confusion_matrix_labels": {
            "rows_true": ["non_phishing", "phishing"],
            "columns_predicted": ["non_phishing", "phishing"],
        },
        "test_examples": int(len(labels)),
    }


def train(
    phishtank_path: Path,
    tranco_path: Path,
    max_negative: int = 50_000,
    model_path: Path | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
    frame, manifest = build_dataset(phishtank_path, tranco_path, max_negative)
    train_indices, validation_indices, test_indices = _grouped_split(frame)
    x = frame.loc[:, FEATURE_COLUMNS]
    y = frame["label"]
    x_train, y_train = x.iloc[train_indices], y.iloc[train_indices]
    x_validation, y_validation = x.iloc[validation_indices], y.iloc[validation_indices]
    x_test, y_test = x.iloc[test_indices], y.iloc[test_indices]

    leaderboard: list[dict[str, object]] = []
    fitted: dict[str, Any] = {}
    for name, estimator in _candidate_estimators().items():
        estimator.fit(x_train, y_train)
        validation_scores = estimator.predict_proba(x_validation)[:, 1]
        leaderboard.append(
            {
                "algorithm": name,
                "validation_pr_auc": float(
                    average_precision_score(y_validation, validation_scores)
                ),
                "validation_f2_at_0_5": float(
                    fbeta_score(
                        y_validation,
                        validation_scores >= 0.5,
                        beta=2,
                        zero_division=0,
                    )
                ),
            }
        )
        fitted[name] = estimator

    leaderboard.sort(key=lambda result: float(result["validation_pr_auc"]), reverse=True)
    selected_name = str(leaderboard[0]["algorithm"])
    estimator = fitted[selected_name]
    validation_scores = estimator.predict_proba(x_validation)[:, 1]
    threshold = _select_threshold(y_validation.to_numpy(), validation_scores)
    test_scores = estimator.predict_proba(x_test)[:, 1]
    test_metrics = _evaluation_metrics(y_test.to_numpy(), test_scores, threshold)
    trained_at = datetime.now(timezone.utc).isoformat()
    version = "url-v1-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest["split_counts"] = {
        "train": int(len(train_indices)),
        "validation": int(len(validation_indices)),
        "test": int(len(test_indices)),
    }
    artifact = {
        "estimator": estimator,
        "threshold": threshold,
        "version": version,
        "algorithm": selected_name,
        "trained_at": trained_at,
        "features": list(FEATURE_COLUMNS),
        "metrics": test_metrics,
        "dataset": manifest,
        "calibrated": True,
    }
    report = {
        "model_version": version,
        "selected_algorithm": selected_name,
        "selection_metric": "validation PR-AUC",
        "threshold_selection": "F2 maximization on validation split; test split untouched",
        "candidate_comparison": leaderboard,
        "test_metrics": test_metrics,
        "dataset": manifest,
    }
    destination = model_path or Path("ml/models/url_model.joblib")
    report_destination = report_path or Path("ml/reports/model-evaluation.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    report_destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_model = destination.with_suffix(destination.suffix + ".tmp")
    joblib.dump(artifact, temporary_model)
    os.replace(temporary_model, destination)
    report_destination.write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    LOGGER.info(
        "Saved %s model using %s; held-out PR-AUC=%.3f and F1=%.3f",
        version,
        selected_name,
        test_metrics["pr_auc"],
        test_metrics["f1_phishing"],
    )
    return report


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Train and evaluate the URL model on approved local datasets."
    )
    parser.add_argument("--phishtank", required=True, type=Path)
    parser.add_argument("--tranco", required=True, type=Path)
    parser.add_argument("--max-negative", type=int, default=50_000)
    parser.add_argument("--model-out", type=Path, default=Path("ml/models/url_model.joblib"))
    parser.add_argument(
        "--report-out", type=Path, default=Path("ml/reports/model-evaluation.json")
    )
    arguments = parser.parse_args(argv)
    if not arguments.phishtank.is_file() or not arguments.tranco.is_file():
        parser.error("Both dataset paths must point to existing files.")
    try:
        train(
            arguments.phishtank,
            arguments.tranco,
            max_negative=arguments.max_negative,
            model_path=arguments.model_out,
            report_path=arguments.report_out,
        )
    except (OSError, ValueError, pd.errors.ParserError) as exc:
        LOGGER.error("Training failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
