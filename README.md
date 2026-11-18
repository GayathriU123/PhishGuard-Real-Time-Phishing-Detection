# PhishGuard

An explainable phishing investigation workspace for URL and email analysis. PhishGuard keeps supervised URL-model predictions separate from message heuristics, threat-feed matches, and human review.

> **Academic scope:** PhishTank labels phishing URLs, not emails. Email analysis extracts links and applies transparent message-level rules; it is not presented as a trained email classifier. A clean model state means no approved dataset has been trained yet.

## Project structure

```text
PhishGuard/
├── backend/
│   └── app/
│       ├── api/              # Versioned HTTP endpoints
│       ├── security/         # Input validation and safe handling
│       ├── services/         # URL, email, review, and feed workflows
│       ├── config.py
│       ├── database.py       # Local SQLite persistence
│       ├── schemas.py        # API request and response models
│       └── main.py           # FastAPI app and static frontend
├── frontend/
│   ├── assets/
│   │   ├── app.js            # Browser UI and API client
│   │   └── styles.css        # Responsive light-theme design system
│   └── index.html
├── ml/
│   ├── data/
│   │   ├── raw/              # Downloaded data; never committed
│   │   └── processed/        # Reproducible prepared snapshots
│   ├── models/               # Trained artifacts; never committed
│   ├── reports/              # Measured metrics and model card
│   └── src/
│       ├── features.py       # Static URL feature extraction
│       └── train.py          # Reproducible training/evaluation
├── docs/
│   ├── architecture.md
│   ├── dataset-card.md
│   ├── demo-script.md
│   └── model-card.md
├── tests/
├── .env.example
├── .gitignore
└── requirements.txt
```

## Run locally (Windows PowerShell)

1. Install Python 3.11 or newer.
2. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies and start the app:

   ```powershell
   python -m pip install -r requirements.txt
   python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```

4. Open <http://127.0.0.1:8000>. API documentation is at <http://127.0.0.1:8000/docs>.

The interface is plain HTML, CSS, and JavaScript served by FastAPI; no Streamlit or frontend build step is required. Until you train an approved dataset, URL scans show model unavailability explicitly and rely only on separately labelled rule/feed evidence.

## Dataset sources

- **Phishing URLs:** [PhishTank verified URL feeds](https://phishtank.org/developer_info.php), including the CSV feed at `https://data.phishtank.com/data/online-valid.csv`. PhishTank recommends an application key for repeated downloads; follow its current terms and attribution requirements.
- **Non-phishing URL candidates:** [Tranco's standard top-1m list](https://tranco-list.eu/top-1m.csv.zip). Popularity is only a proxy for a negative class—not proof that every listed URL is safe. Confirm this source and its terms with your instructor before training.

Download and snapshot both sources yourself. Keep raw files under `ml/data/raw/` (ignored by Git), record their download date and SHA-256 hashes, and use the exact paths and training command documented in `docs/dataset-card.md`. Do not interpret absence from a threat feed as a clean verdict.

## Safety and privacy

Scans parse URLs without visiting them. Email HTML is never rendered and remote content is never loaded. Do not upload sensitive mail: local cases retain only redacted metadata and derived evidence by default. A reviewer override requires a reason and is recorded alongside—not instead of—the original model output. “No known threat detected” is not a guarantee of safety.

See `docs/` for the architecture, data/model documentation, and demo script.
