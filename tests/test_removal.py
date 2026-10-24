from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from footprint.db import Store
from footprint.http import HttpResponse
from footprint.models import Finding
from footprint.removal import RemovalManager
from footprint.report import render_report
from tests.helpers import make_config


class FakeHttp:
    def __init__(self, response: HttpResponse):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self.response

    def close(self):
        pass


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.config = make_config(self.base)
        self.store = Store(self.config.db_path)
        self.finding_id, _, _ = self.store.upsert_finding(
            Finding(
                kind="search",
                category="data_broker",
                source="duckduckgo",
                title="Jordan Example at Spokeo",
                url="https://www.spokeo.com/Jordan-Example",
                snippet="Jordan Example, Melbourne, phone and address available.",
                identifier="Jordan Example",
                identifier_type="name",
                severity="high",
                confidence=0.9,
                details={"domain": "spokeo.com", "broker_id": "spokeo"},
            )
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_create_request_prepares_broker_url_and_email(self):
        manager = RemovalManager(self.config, self.store)
        try:
            result = manager.create_for_finding(self.finding_id, notes="ready")
            self.assertTrue(result.created)
            request = result.request
            self.assertEqual(request["broker_id"], "spokeo")
            self.assertIn("spokeo.com/optout", request["url"])
            self.assertEqual(request["verify_url"], "https://www.spokeo.com/Jordan-Example")
            self.assertIn("email_body", request["details"])
            self.assertEqual(self.store.list_requests()[0]["id"], request["id"])
        finally:
            manager.close()

    def test_verification_still_listed_and_removed(self):
        manager = RemovalManager(
            self.config,
            self.store,
            http=FakeHttp(
                HttpResponse(
                    status=200,
                    text=(
                        "<html><body><h1>Jordan Example</h1>"
                        "<p>Jordan Example, Melbourne. Email jordan@example.com. "
                        "Phone and address available. This is a deliberately long public "
                        "directory page used to exercise the verifier.</p>"
                        "<p>More public listing text so the page is not treated as a "
                        "challenge or empty shell.</p></body></html>"
                    ),
                    url="https://www.spokeo.com/Jordan-Example",
                )
            ),
        )
        try:
            request = manager.create_for_finding(self.finding_id).request
            checked = manager.verify_request(request["id"])
            self.assertEqual(checked["status"], "still_listed")
            self.assertEqual(self.store.get_finding(self.finding_id)["status"], "confirmed")
        finally:
            manager.close()

        manager = RemovalManager(
            self.config,
            self.store,
            http=FakeHttp(HttpResponse(status=404, text="", url="https://www.spokeo.com/Jordan-Example")),
        )
        try:
            request = self.store.list_requests()[0]
            checked = manager.verify_request(request["id"])
            self.assertEqual(checked["status"], "removed")
            self.assertEqual(self.store.get_finding(self.finding_id)["status"], "removed")
        finally:
            manager.close()

    def test_report_includes_removal_tracker(self):
        request = RemovalManager(self.config, self.store).create_for_finding(self.finding_id).request
        self.store.update_request(
            request["id"], status="submitted", reference="REF-123", notes="Submitted"
        )
        output = render_report(self.store, self.config)
        text = output.read_text(encoding="utf-8")
        self.assertIn("Removal tracker", text)
        self.assertIn("REF-123", text)
        self.assertIn("Requests and follow-ups", text)

    def test_update_request(self):
        request = RemovalManager(self.config, self.store).create_for_finding(self.finding_id).request
        updated = self.store.update_request(
            request["id"],
            status="submitted",
            reference="REF-123",
            notes="Submitted by hand",
        )
        self.assertEqual(updated["status"], "submitted")
        self.assertEqual(updated["reference"], "REF-123")
        self.assertIn("Submitted", updated["notes"])


if __name__ == "__main__":
    unittest.main()
