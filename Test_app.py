import unittest

from app import create_app, db


class NumberLookupApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "VERIPHONE_API_KEY": "",
                "LOOKUP_AUDIT_PEPPER": "test-pepper",
                "RATE_LIMIT": "100 per minute",
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def test_health_check_returns_database_status(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["database"], "connected")

    def test_lookup_requires_authorisation_confirmation(self):
        response = self.client.post("/api/v1/lookup", json={"number": "+919876543210"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["code"], "CONSENT_REQUIRED")

    def test_invalid_number_is_rejected(self):
        response = self.client.post("/api/v1/lookup", json={"number": "123", "consent": True})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["code"], "INVALID_NUMBER")

    def test_valid_request_returns_technical_metadata_only(self):
        response = self.client.post("/api/v1/lookup", json={"number": "+14155552671", "consent": True})
        self.assertEqual(response.status_code, 200)
        result = response.json["result"]
        self.assertEqual(result["source"], "local_metadata")
        self.assertFalse(result["live"])
        self.assertIn("msisdn", result)
        self.assertNotIn("owner", result)
        self.assertNotIn("address", result)

    def test_batch_lookup_returns_per_item_outcomes(self):
        response = self.client.post(
            "/api/v1/lookup/batch",
            json={"numbers": ["+14155552671", "123"], "consent": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["summary"]["submitted"], 2)
        self.assertEqual(response.json["summary"]["successful"], 1)
        self.assertEqual(response.json["items"][0]["status"], "success")
        self.assertEqual(response.json["items"][1]["code"], "INVALID_NUMBER")

    def test_batch_lookup_requires_authorisation_confirmation(self):
        response = self.client.post("/api/v1/lookup/batch", json={"numbers": ["+14155552671"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["code"], "CONSENT_REQUIRED")

    def test_batch_lookup_rejects_more_than_configured_limit(self):
        response = self.client.post(
            "/api/v1/lookup/batch",
            json={"numbers": ["+14155552671"] * 16, "consent": True},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["code"], "BATCH_LIMIT_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
