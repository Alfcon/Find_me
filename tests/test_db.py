from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from footprint.db import Store
from footprint.models import Finding


def make_finding(url: str = "https://example.com/profile", **overrides) -> Finding:
    values = dict(
        kind="search",
        category="social",
        source="duckduckgo",
        title="Example profile",
        url=url,
        snippet="A public profile",
        identifier="jordan-example",
        identifier_type="username",
        severity="medium",
        confidence=0.8,
        matched="username:jordan-example",
        details={"query": "jordan-example"},
    )
    values.update(overrides)
    return Finding(**values)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / ".footprint" / "test.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_insert_and_update_preserves_user_status(self):
        finding = make_finding()
        finding_id, is_new, reappeared = self.store.upsert_finding(finding, None)
        self.assertTrue(is_new)
        self.assertFalse(reappeared)
        self.store.update_finding(finding_id, status="confirmed", notes="verified")
        again = make_finding(title="Updated title")
        second_id, is_new, reappeared = self.store.upsert_finding(again, None)
        self.assertEqual(second_id, finding_id)
        self.assertFalse(is_new)
        self.assertFalse(reappeared)
        stored = self.store.get_finding(finding_id)
        self.assertEqual(stored["status"], "confirmed")
        self.assertEqual(stored["title"], "Updated title")
        self.assertIn("verified", stored["notes"])

    def test_removed_finding_reappears(self):
        finding = make_finding()
        finding_id, _, _ = self.store.upsert_finding(finding, None)
        self.store.update_finding(finding_id, status="removed")
        _, _, reappeared = self.store.upsert_finding(finding, None)
        self.assertTrue(reappeared)
        self.assertEqual(self.store.get_finding(finding_id)["status"], "reappeared")

    def test_stats_exclude_false_positive_and_removed(self):
        first, _, _ = self.store.upsert_finding(make_finding("https://example.com/a", severity="high"), None)
        second, _, _ = self.store.upsert_finding(make_finding("https://example.com/b", severity="low"), None)
        self.store.upsert_finding(make_finding("https://example.com/c", severity="critical"), None)
        self.store.update_finding(first, status="false_positive")
        self.store.update_finding(second, status="removed")
        stats = self.store.stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["active"], 1)
        self.assertEqual(stats["removed"], 1)
        self.assertGreaterEqual(stats["score"], 30)

    def test_filters(self):
        self.store.upsert_finding(make_finding("https://example.com/a", severity="high"), None)
        self.store.upsert_finding(make_finding("https://example.com/b", category="code", severity="low"), None)
        self.assertEqual(len(self.store.list_findings(severity="high")), 1)
        self.assertEqual(len(self.store.list_findings(category="code")), 1)
        self.assertEqual(len(self.store.list_findings(status="active")), 2)

    def test_broker_status(self):
        row = self.store.update_broker("spokeo", "removal_requested", notes="submitted")
        self.assertEqual(row["status"], "removal_requested")
        row = self.store.update_broker("spokeo", "removed", notes="confirmed")
        self.assertEqual(row["status"], "removed")
        self.assertIn("submitted", row["notes"])
        self.assertIn("confirmed", row["notes"])
        with self.assertRaises(ValueError):
            self.store.update_broker("spokeo", "not-a-status")

    def test_run_lifecycle(self):
        run_id = self.store.start_run("scan")
        self.store.finish_run(run_id, "complete", {"queries_run": 2, "requests": 3, "errors": 0})
        runs = self.store.list_runs()
        self.assertEqual(runs[0]["status"], "complete")
        self.assertEqual(runs[0]["queries"], 2)


if __name__ == "__main__":
    unittest.main()
