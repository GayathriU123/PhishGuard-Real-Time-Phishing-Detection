import csv
import json
import math
import os
import pickle
from datetime import datetime, timezone
from pathlib import Path
from ml.src.features import FEATURE_COLUMNS, extract_url_features, parse_http_url
from ml.src.model_types import PureLogisticModel

def train_pure():
    phishtank_path = Path("ml/data/raw/online-valid.csv")
    tranco_path = Path("ml/data/raw/tranco.csv")

    pos_urls = []
    with phishtank_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            u = row.get("url")
            if u:
                pos_urls.append(u)

    neg_urls = []
    with tranco_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                neg_urls.append(f"https://{row[1]}")

    print(f"Loaded {len(pos_urls)} phishing URLs and {len(neg_urls)} Tranco domains.")

    # Extract features
    X = []
    y = []
    for u in pos_urls:
        try:
            feats = extract_url_features(u)
            X.append([feats[col] for col in FEATURE_COLUMNS])
            y.append(1)
        except Exception:
            continue

    for u in neg_urls:
        try:
            feats = extract_url_features(u)
            X.append([feats[col] for col in FEATURE_COLUMNS])
            y.append(0)
        except Exception:
            continue

    # Simple Train/Test Split (70/30)
    split_idx = int(0.7 * len(X))
    X_train, y_train = X[:split_idx], y[:split_idx]
    X_test, y_test = X[split_idx:], y[split_idx:]

    # Standardize features
    num_features = len(FEATURE_COLUMNS)
    means = [sum(row[j] for row in X_train) / len(X_train) for j in range(num_features)]
    stds = [math.sqrt(sum((row[j] - means[j]) ** 2 for row in X_train) / len(X_train)) or 1.0 for j in range(num_features)]

    def scale_row(row):
        return [(row[j] - means[j]) / stds[j] for j in range(num_features)]

    X_train_scaled = [scale_row(row) for row in X_train]
    X_test_scaled = [scale_row(row) for row in X_test]

    # Logistic Regression Gradient Descent
    weights = [0.0] * num_features
    bias = 0.0
    lr = 0.05
    epochs = 400

    for _ in range(epochs):
        grad_w = [0.0] * num_features
        grad_b = 0.0
        n = len(X_train_scaled)
        for row, target in zip(X_train_scaled, y_train):
            z = bias + sum(w * x for w, x in zip(weights, row))
            pred = 1.0 / (1.0 + math.exp(-max(min(z, 20), -20)))
            err = pred - target
            grad_b += err
            for j in range(num_features):
                grad_w[j] += err * row[j]
        bias -= lr * (grad_b / n)
        for j in range(num_features):
            weights[j] -= lr * (grad_w[j] / n)

    # Convert back to unscaled space so model takes raw features directly
    unscaled_weights = [weights[j] / stds[j] for j in range(num_features)]
    unscaled_bias = bias - sum((weights[j] * means[j]) / stds[j] for j in range(num_features))

    model = PureLogisticModel(unscaled_weights, unscaled_bias, list(FEATURE_COLUMNS))

    # Evaluate on held-out test split
    preds = model.predict(X_test, threshold=0.5)
    tp = sum(1 for p, act in zip(preds, y_test) if p == 1 and act == 1)
    fp = sum(1 for p, act in zip(preds, y_test) if p == 1 and act == 0)
    tn = sum(1 for p, act in zip(preds, y_test) if p == 0 and act == 0)
    fn = sum(1 for p, act in zip(preds, y_test) if p == 0 and act == 1)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 1.0
    accuracy = (tp + tn) / len(y_test) if len(y_test) > 0 else 1.0

    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "test_size": len(y_test),
        "train_size": len(y_train),
    }

    artifact = {
        "estimator": model,
        "threshold": 0.50,
        "version": "v1.0.0-supervised",
        "metrics": metrics,
        "features": list(FEATURE_COLUMNS),
        "algorithm": "Supervised Logistic Classifier",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "phishtank_file": "online-valid.csv",
            "tranco_file": "tranco.csv",
            "records": len(X),
        }
    }

    out_model = Path("ml/models/url_model.joblib")
    out_model.parent.mkdir(parents=True, exist_ok=True)
    with out_model.open("wb") as f:
        pickle.dump(artifact, f)

    out_report = Path("ml/reports/model-evaluation.json")
    out_report.parent.mkdir(parents=True, exist_ok=True)
    out_report.write_text(json.dumps(artifact["metrics"], indent=2), encoding="utf-8")

    print(f"Successfully trained model and saved to {out_model}!")
    print(f"Metrics: Accuracy={accuracy:.2%}, Precision={precision:.2%}, Recall={recall:.2%}, F1={f1:.2%}")

if __name__ == "__main__":
    train_pure()
