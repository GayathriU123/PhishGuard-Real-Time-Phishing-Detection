# Architecture

PhishGuard is a local-first investigation app with a static browser frontend, a FastAPI API, SQLite case/audit storage, and an optional scikit-learn URL model.

```text
Browser (HTML/CSS/JS)
        │ same-origin REST
        ▼
FastAPI ─── URL feature extraction ─── optional trained URL model
   │      ├─ email parser + message rules
   │      └─ local PhishTank feed lookup (never visits submitted URLs)
   ▼
SQLite: cases, derived evidence, review events, audit trail
```

Evidence has distinct provenance: `model`, `rule`, and `threat_intel`. The model is trained only on labelled URLs. Email-level findings are deterministic rules and aggregated URL findings, not email-model predictions. When no model artifact exists, the API reports that state rather than manufacturing a score.

The local demo does not connect to a mailbox, quarantine messages, browse suspicious URLs, load remote email resources, or expose API keys to the browser. Review actions preserve the original recommendation and require a reason.
