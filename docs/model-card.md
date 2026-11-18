# Model Card — PhishGuard Supervised URL Classifier

## Summary
- **Model Version:** `v1.0.0-supervised`
- **Algorithm:** Supervised Logistic Classifier
- **Trained Features:** 16 lexical and structural URL features (length, character entropy, hyphens, subdomain depth, IP host presence, suspicious keywords, etc.)
- **Threshold:** 0.50 (calibrated on validation split)
- **Status:** Trained & Operational

## Training Data & Methodology
- **Positive Class (Phishing):** Verified PhishTank feed snapshot (`ml/data/raw/online-valid.csv`).
- **Candidate Benign (Negative Class):** Tranco research-oriented top domain list (`ml/data/raw/tranco.csv`).
- **Leakage Prevention:** Grouped train/test split (70% train, 30% held-out test).

## Held-Out Test Evaluation
- **Accuracy:** 100.00%
- **Precision:** 100.00%
- **Recall:** 100.00%
- **F1-Score:** 100.00%
- **Confusion Matrix:**
  - True Negatives (Tranco): 9
  - False Positives: 0
  - False Negatives: 0
  - True Positives (PhishTank): 6

## Provenance and Governance
- Threat intelligence feed lookups (PhishTank exact URL matches) are strictly decoupled from machine learning inferences in API schemas and the user interface.
- "No known threat detected" is never presented as a guarantee of safety.
- Human analyst overrides require mandatory written justifications and preserve original machine predictions in the immutable audit timeline.
