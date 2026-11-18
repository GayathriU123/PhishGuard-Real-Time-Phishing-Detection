import unittest
from backend.app.database import init_db, list_cases, get_case, review_case, operational_metrics
from backend.app.services.scanner import evaluate_url, evaluate_email, build_case
from backend.app.services.threat_intel import feed_status
from backend.app.services.model_runtime import model_card

class TestAPIWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_evaluate_url_and_case_lifecycle(self):
        url = "https://www.google.com/search?q=cybersecurity"
        eval_result = evaluate_url(url)
        self.assertIn("verdict", eval_result)
        self.assertIn("risk_band", eval_result)
        self.assertIn("features", eval_result)

        case = build_case("url", eval_result, None)
        from backend.app.database import create_case
        saved = create_case(case)
        self.assertEqual(saved["id"], case["id"])

        fetched = get_case(saved["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], saved["id"])

    def test_review_case_workflow(self):
        url = "https://test-analyst-review.example.org/verify"
        eval_result = evaluate_url(url)
        case = build_case("url", eval_result, None)
        from backend.app.database import create_case
        saved = create_case(case)

        reviewed = review_case(
            saved["id"],
            decision="confirmed_phishing",
            reason="Deceptive brand imitation confirmed via manual review."
        )
        self.assertIsNotNone(reviewed)
        self.assertEqual(reviewed["review_status"], "reviewed")
        self.assertEqual(reviewed["verdict"], "likely_phishing")

    def test_feed_status_contract(self):
        status = feed_status()
        self.assertIn("provider", status)
        self.assertIn("status", status)

    def test_model_card_contract(self):
        card = model_card()
        self.assertIn("status", card)
        self.assertIn("features", card)

    def test_operational_metrics(self):
        metrics = operational_metrics()
        self.assertIn("total_scans", metrics)
        self.assertIn("pending_reviews", metrics)

if __name__ == "__main__":
    unittest.main()
