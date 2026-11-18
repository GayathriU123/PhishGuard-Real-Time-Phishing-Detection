import unittest
from ml.src.features import extract_url_features, parse_http_url, rule_evidence, redact_url

class TestFeatures(unittest.TestCase):
    def test_benign_url_parsing(self):
        url = "https://www.google.com/search?q=cybersecurity"
        normalized, parsed, ascii_host = parse_http_url(url)
        self.assertEqual(parsed.scheme, "https")
        self.assertIn("google.com", ascii_host)
        self.assertTrue(normalized.startswith("https://"))

    def test_feature_extraction_schema(self):
        url = "https://secure-login.bank-update.com/signin?ref=account"
        feats = extract_url_features(url)
        self.assertIn("url_length", feats)
        self.assertIn("character_entropy", feats)
        self.assertIn("hyphen_count", feats)
        self.assertIn("has_ip_host", feats)
        self.assertEqual(feats["has_ip_host"], 0.0)

    def test_ip_address_detection(self):
        url = "http://192.168.1.1/admin"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_ip_host"], 1.0)
        rules = rule_evidence(feats)
        rule_types = [r["title"] for r in rules]
        self.assertTrue(any("IP address used as hostname" in t for t in rule_types))

    def test_redact_url(self):
        url = "https://example.com/login?token=secret12345&user=john"
        redacted = redact_url(url)
        self.assertNotIn("secret12345", redacted)
        self.assertEqual(redacted, "https://example.com/login")

if __name__ == "__main__":
    unittest.main()
