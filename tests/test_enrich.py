from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from footprint.data_points import infer_data_points, inventory
from footprint.db import Store
from footprint.enrich import parse_page
from footprint.models import Finding
from tests.helpers import make_config


PAGE = """
<!doctype html>
<html><head>
<title>Jordan Example — Example Labs</title>
<meta name="description" content="Profile page for Jordan Example">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"Person","name":"Jordan Example",
 "email":"jordan@example.com","telephone":"+61 412 345 678",
 "jobTitle":"Product Engineer","worksFor":{"name":"Example Labs"},
 "address":{"streetAddress":"12 Example Street","addressLocality":"Melbourne"},
 "sameAs":["https://github.com/jordan-example"]}
</script>
</head><body>
<h1>Jordan Example</h1>
<p>Jordan Example works at Example Labs in Melbourne.</p>
<a href="mailto:jordan@example.com">Email Jordan</a>
<a href="tel:+61412345678">Call Jordan</a>
</body></html>
"""


class EnrichTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.config = make_config(self.base)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_page_extracts_structured_and_visible_fields(self):
        parsed = parse_page(PAGE, "https://example.com/jordan", self.config.profile)
        self.assertEqual(parsed["title"], "Jordan Example — Example Labs")
        self.assertIn("name", parsed["fields"])
        kinds = {point["kind"] for point in parsed["points"]}
        for kind in {"name", "email", "phone", "address", "job_title", "employer", "social"}:
            self.assertIn(kind, kinds)
        self.assertTrue(parsed["excerpts"])

    def test_inventory_groups_by_domain_and_marks_possibles(self):
        finding = {
            "id": 1,
            "kind": "manual",
            "category": "data_broker",
            "source": "Manual URL",
            "title": "Jordan Example — Example Broker",
            "url": "https://broker.example.com/jordan",
            "snippet": "Jordan Example, Product Engineer at Example Labs. Possible relatives.",
            "status": "new",
            "severity": "high",
            "details": {"domain": "broker.example.com", "broker_id": ""},
        }
        data = inventory([finding], self.config.profile)
        self.assertEqual(len(data["sites"]), 1)
        self.assertEqual(data["sites"][0]["domain"], "broker.example.com")
        self.assertGreaterEqual(data["counts"].get("employer", 0), 1)
        points = data["sites"][0]["points"]
        self.assertTrue(any(point["kind"] == "employer" for point in points))

    def test_store_roundtrip_preserves_enrichment(self):
        store = Store(self.config.db_path)
        try:
            finding = Finding(
                kind="manual",
                category="data_broker",
                source="Manual URL",
                title="Example",
                url="https://example.com/profile",
                details={"domain": "example.com"},
            )
            finding_id, _, _ = store.upsert_finding(finding, None)
            details = store.get_finding(finding_id)["details"]
            details["enrichment"] = {"status": "ok", "fields": {"name": "Jordan Example"}}
            store.update_finding_details(finding_id, details)
            loaded = store.get_finding(finding_id)
            self.assertEqual(loaded["details"]["enrichment"]["fields"]["name"], "Jordan Example")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
