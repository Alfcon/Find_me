from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from footprint.brokers import load_catalog
from footprint.config import BrokersConfig
from footprint.db import Store
from footprint.models import Finding
from footprint.playbook import build_plan, plan_markdown
from tests.helpers import make_config


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.config = make_config(self.base)
        self.config.brokers = BrokersConfig(regions=["AU", "US", "GLOBAL"])
        self.store = Store(self.config.db_path)
        self.catalog = load_catalog()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_broker_finding_creates_one_action(self):
        self.store.upsert_finding(
            Finding(
                kind="search",
                category="data_broker",
                source="duckduckgo",
                title="Jordan Example — Spokeo",
                url="https://www.spokeo.com/Jordan-Example",
                snippet="Melbourne address",
                identifier="Jordan Example",
                identifier_type="name",
                severity="high",
                confidence=0.9,
                details={"broker_id": "spokeo"},
            )
        )
        self.store.update_broker("spokeo", "removal_requested")
        plan = build_plan(self.store, self.config, self.catalog)
        broker_actions = [action for action in plan.actions if action.broker_id == "spokeo"]
        self.assertEqual(len(broker_actions), 1)
        self.assertEqual(broker_actions[0].status, "in_progress")
        self.assertIn("spokeo", broker_actions[0].url)

    def test_breach_is_priority_zero(self):
        self.store.upsert_finding(
            Finding(
                kind="breach",
                category="breach",
                source="Have I Been Pwned",
                title="Email exposed in Example breach",
                url="https://haveibeenpwned.com/",
                identifier="jordan@example.com",
                identifier_type="email",
                severity="critical",
                confidence=0.99,
                details={"breach": "Example"},
            )
        )
        plan = build_plan(self.store, self.config, self.catalog)
        action = next(action for action in plan.actions if action.category == "breach")
        self.assertEqual(action.priority, "P0")
        self.assertIn("Secure accounts", action.title)

    def test_removed_findings_are_not_active_actions(self):
        finding_id, _, _ = self.store.upsert_finding(
            Finding(
                kind="search",
                category="social",
                source="duckduckgo",
                title="Old profile",
                url="https://example.com/old",
                identifier="jordan-example",
                identifier_type="username",
                severity="low",
                details={},
            )
        )
        self.store.update_finding(finding_id, status="removed")
        plan = build_plan(self.store, self.config, self.catalog)
        self.assertFalse(any(action.finding_id == finding_id for action in plan.actions))
        self.assertGreaterEqual(plan.summary["done"], 1)

    def test_templates_and_hardening_exist(self):
        plan = build_plan(self.store, self.config, self.catalog)
        self.assertGreaterEqual(len(plan.hardening), 10)
        self.assertGreaterEqual(len(plan.templates), 4)
        self.assertTrue(any(template.id == "au-privacy" for template in plan.templates))

    def test_markdown_plan_renders(self):
        plan = build_plan(self.store, self.config, self.catalog)
        text = plan_markdown(plan)
        self.assertIn("# Digital footprint removal plan", text)
        self.assertIn("Hardening checklist", text)


if __name__ == "__main__":
    unittest.main()
