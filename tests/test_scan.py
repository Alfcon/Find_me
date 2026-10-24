from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from footprint.checks import CheckOutcome
from footprint.config import BrokersConfig
from footprint.db import Store
from footprint.models import Finding
from footprint.scan import Scanner
from tests.helpers import make_config


class ScannerTests(unittest.TestCase):
    def test_run_persists_search_and_check_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            config.brokers = BrokersConfig(regions=["AU", "GLOBAL"])
            store = Store(config.db_path)
            scanner = Scanner(config, store)
            try:
                scanner._run_search = lambda queries, availability: [
                    Finding(
                        kind="search",
                        category="news",
                        source="duckduckgo",
                        title="Jordan Example in the news",
                        url="https://example.com/news",
                        snippet="Melbourne",
                        identifier="Jordan Example",
                        identifier_type="name",
                        severity="medium",
                        details={"query": "q"},
                    ),
                    Finding(
                        kind="search",
                        category="news",
                        source="bing",
                        title="Jordan Example in the news",
                        url="https://example.com/news?utm_source=bing",
                        snippet="Melbourne and more",
                        identifier="Jordan Example",
                        identifier_type="name",
                        severity="medium",
                        details={"query": "q2"},
                    ),
                ]
                scanner._run_checks = lambda: CheckOutcome(
                    findings=[
                        Finding(
                            kind="profile",
                            category="code",
                            source="GitHub",
                            title="GitHub profile",
                            url="https://example.com/github",
                            snippet="profile",
                            identifier="jordan-example",
                            identifier_type="username",
                            severity="low",
                            details={"provider": "github"},
                        )
                    ],
                    checks_run=1,
                )
                result = scanner.run(only="all", max_queries=2)
                self.assertTrue(result.ok)
                self.assertEqual(result.stats.new_findings, 2)
                stats = store.stats()
                self.assertEqual(stats["total"], 2)
                runs = store.list_runs()
                self.assertEqual(runs[0]["status"], "complete")
                # The two search results canonicalise to one URL and one row.
                titles = [finding["title"] for finding in store.list_findings()]
                self.assertEqual(titles.count("Jordan Example in the news"), 1)
            finally:
                scanner.close()
                store.close()

    def test_dry_run_does_not_touch_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(Path(tmp))
            store = Store(config.db_path)
            scanner = Scanner(config, store)
            try:
                result = scanner.run(dry_run=True, max_queries=1)
                self.assertTrue(result.dry_run)
                self.assertEqual(store.list_runs(), [])
            finally:
                scanner.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
