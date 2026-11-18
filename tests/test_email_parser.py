import unittest
from backend.app.security.email_parser import parse_email

class TestEmailParser(unittest.TestCase):
    def test_safe_email_parsing(self):
        raw = b"""From: sender@bank.com
To: user@example.com
Reply-To: phisher@attacker.com
Subject: Action Required
Date: Wed, 18 Nov 2026 10:00:00 +0000

Dear customer, please click here: https://secure-login.attacker.com/auth
"""
        result = parse_email(raw)
        self.assertEqual(result["sender_domain"], "bank.com")
        self.assertEqual(result["reply_to_domain"], "attacker.com")
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(result["urls"][0], "https://secure-login.attacker.com/auth")
        signal_titles = [s["title"] for s in result["signals"]]
        self.assertTrue(any("From and Reply-To domains differ" in t for t in signal_titles))

    def test_strip_html_no_remote_assets(self):
        raw = b"""From: info@test.com
Subject: Test HTML
Content-Type: text/html

<html>
  <body>
    <script>alert('xss');</script>
    <p>Please review our site: http://example.org/verify</p>
  </body>
</html>
"""
        result = parse_email(raw)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(result["urls"][0], "http://example.org/verify")

if __name__ == "__main__":
    unittest.main()
