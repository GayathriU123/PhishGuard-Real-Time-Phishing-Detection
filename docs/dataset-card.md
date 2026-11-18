# Dataset Card — PhishGuard URL & Email Corpus

## Sources & Provenance
1. **Phishing URLs:** [PhishTank Verified Feed](https://phishtank.org/developer_info.php)
   - Snapshot location: `ml/data/raw/online-valid.csv`
   - Target label: `1` (Phishing)
   - Verified records: Contains verified, active phishing targets across financial, tech, and service brands.

2. **Candidate Benign URLs:** [Tranco List](https://tranco-list.eu/)
   - Snapshot location: `ml/data/raw/tranco.csv`
   - Target label: `0` (Candidate Benign)
   - **Academic Caveat:** Tranco is a domain popularity ranking, not a verified benign certification. Membership indicates high global traffic, not proof of safety.

## Preparation & Preprocessing
- Static lexical parsing only via `urllib.parse` and RFC 3986 compliance.
- No network requests are made to submitted URLs during feature extraction.
- Query string tokens are redacted in saved audit trails to protect potential sensitive credentials.
