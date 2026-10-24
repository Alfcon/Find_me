from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from bs4 import BeautifulSoup

from footprint.demo import demo_config, run_demo, seed_demo
from footprint.db import Store
from footprint.models import Finding
from footprint.report import render_report
from tests.helpers import make_config


class ReportTests(unittest.TestCase):
    def test_demo_report_is_valid_and_contains_core_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            output = run_demo(base)
            text = output.read_text(encoding="utf-8")
            soup = BeautifulSoup(text, "html.parser")
            self.assertEqual(soup.title.string, "Digital Footprint Audit — Demo")
            self.assertEqual(len(soup.select(".finding")), 11)
            self.assertGreaterEqual(len(soup.select(".action")), 8)
            self.assertGreaterEqual(len(soup.select("#broker-table tbody tr")), 10)
            self.assertIn("Results about you", text)
            self.assertIn("What each site appears to have", text)
            self.assertGreaterEqual(len(soup.select(".site-card")), 1)
            self.assertGreaterEqual(len(soup.select(".inventory-chip")), 1)
            self.assertGreaterEqual(len(soup.select(".finding-data")), 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            payload = json.loads(soup.select_one("#report-data").string)
            self.assertFalse(payload["redacted"])
            self.assertEqual(payload["profile"]["name"], "Jordan Example")
            self.assertGreater(payload["stats"]["score"], 0)
            self.assertIn("data_inventory", payload)
            self.assertGreaterEqual(len(payload["data_inventory"]["sites"]), 1)

    def test_redacted_report_masks_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = demo_config(base)
            config.report.redact = True
            store = seed_demo(config)
            try:
                output = render_report(store, config, redact=True)
            finally:
                store.close()
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("jordan.example@example.com", text)
            self.assertNotIn("+61 412 345 678", text)
            self.assertIn("Redacted report", text)
            soup = BeautifulSoup(text, "html.parser")
            payload = json.loads(soup.select_one("#report-data").string)
            self.assertTrue(payload["redacted"])
            self.assertIn("***", payload["profile"]["identifiers"][1]["value"])

    def test_html_escaping_of_untrusted_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            store = Store(config.db_path)
            try:
                store.upsert_finding(
                    Finding(
                        kind="search",
                        category="other",
                        source='<img src=x onerror="alert(1)">',
                        title='<script>alert("x")</script> Jordan',
                        url="https://example.com/x",
                        snippet='"><svg onload=alert(1)>',
                        identifier="jordan@example.com",
                        identifier_type="email",
                        severity="medium",
                        details={"reasons": ["<b>not bold</b>"]},
                    )
                )
                output = render_report(store, config)
            finally:
                store.close()
            text = output.read_text(encoding="utf-8")
            self.assertNotIn('<script>alert("x")</script>', text)
            self.assertNotIn("<svg onload=", text)
            self.assertIn("&lt;script&gt;", text)
            self.assertIn("&lt;img src=x", text)

    def test_empty_report_has_empty_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = make_config(base)
            store = Store(config.db_path)
            try:
                output = render_report(store, config)
            finally:
                store.close()
            text = output.read_text(encoding="utf-8")
            self.assertIn("No active public matches were stored", text)
            self.assertIn("No active removal actions", text)


if __name__ == "__main__":
    unittest.main()
