from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from footprint.checks import CheckRunner
from tests.helpers import make_config


class CheckTests(unittest.TestCase):
    def test_xposedornot_creates_aggregate_breach_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            runner = CheckRunner(config, http=object())
            runner._json = lambda *args, **kwargs: (
                200,
                {
                    "BreachesSummary": {"site": "ExampleOne;ExampleTwo"},
                    "ExposedBreaches": {
                        "breaches_details": [
                            {
                                "breach": "ExampleOne",
                                "xposed_data": "Email addresses;Passwords",
                                "password_risk": "easy",
                                "xposed_date": "2020",
                                "xposed_records": 100,
                                "domain": "example.com",
                            }
                        ]
                    },
                },
            )
            runner._xposedornot()
            self.assertEqual(len(runner.outcome.findings), 1)
            finding = runner.outcome.findings[0]
            self.assertEqual(finding.severity, "critical")
            self.assertEqual(finding.details["breach_count"], 2)
            self.assertEqual(finding.source, "XposedOrNot")

    def test_github_commits_creates_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            runner = CheckRunner(config, http=object())
            email = config.profile.emails[0]
            runner._json = lambda *args, **kwargs: (
                200,
                {
                    "total_count": 3,
                    "items": [
                        {
                            "html_url": "https://github.com/example/repo/commit/abc",
                            "repository": {"full_name": "example/repo"},
                            "commit": {
                                "message": "Fix tests",
                                "author": {"email": email, "date": "2024-01-01T00:00:00Z"},
                            },
                        }
                    ],
                },
            )
            runner._github_commits()
            self.assertEqual(len(runner.outcome.findings), 1)
            finding = runner.outcome.findings[0]
            self.assertEqual(finding.details["total_count"], 3)
            self.assertIn("example/repo", finding.snippet)

    def test_breach_fingerprints_are_email_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.profile.emails = ["one@example.com", "two@example.com"]
            old = os.environ.get("HIBP_API_KEY")
            os.environ["HIBP_API_KEY"] = "test"
            try:
                runner = CheckRunner(config, http=object())
                runner._json = lambda *args, **kwargs: (
                    200,
                    [
                        {
                            "Name": "ExampleBreach",
                            "Title": "Example Breach",
                            "Domain": "example.com",
                            "BreachDate": "2021-01-01",
                            "PwnCount": 100,
                            "DataClasses": ["Email addresses", "Passwords"],
                            "IsSensitive": False,
                            "IsVerified": True,
                        }
                    ],
                )
                runner._breaches()
                self.assertEqual(len(runner.outcome.findings), 2)
                self.assertNotEqual(
                    runner.outcome.findings[0].fingerprint,
                    runner.outcome.findings[1].fingerprint,
                )
                self.assertEqual(runner.outcome.findings[0].severity, "critical")
            finally:
                if old is None:
                    os.environ.pop("HIBP_API_KEY", None)
                else:
                    os.environ["HIBP_API_KEY"] = old


if __name__ == "__main__":
    unittest.main()
