from __future__ import annotations

import unittest

from footprint.analyze import analyze_hit, merge_findings
from footprint.brokers import load_catalog
from footprint.config import Profile, SearchConfig
from footprint.models import Finding, SearchHit, SearchQuery, QueryAnchor
from footprint.queries import build_queries


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.profile = Profile.from_mapping(
            {
                "display_name": "Jordan Example",
                "emails": ["jordan@example.com"],
                "locations": ["Melbourne, Australia"],
                "usernames": ["jordan-example"],
            }
        )
        self.catalog = load_catalog()
        self.query = SearchQuery(
            text='"Jordan Example" "Melbourne"',
            anchors=[QueryAnchor("name", "Jordan Example"), QueryAnchor("location", "Melbourne")],
            label="Name + location",
            identifier_type="name",
            purpose="name_location",
        )

    def test_broker_result_is_high_risk(self):
        hit = SearchHit(
            engine="duckduckgo",
            title="Jordan Example in Melbourne — Spokeo",
            url="https://www.spokeo.com/Jordan-Example",
            snippet="Jordan Example, Melbourne. Phone and address available.",
        )
        finding = analyze_hit(self.query, hit, self.profile, self.catalog)
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.category, "data_broker")
        self.assertEqual(finding.details["broker_id"], "spokeo")
        self.assertEqual(finding.severity, "high")
        self.assertGreaterEqual(finding.confidence, 0.8)

    def test_excluded_domain_is_skipped(self):
        hit = SearchHit(
            engine="duckduckgo",
            title="Jordan Example in Melbourne",
            url="https://www.spokeo.com/Jordan-Example",
        )
        self.assertIsNone(
            analyze_hit(self.query, hit, self.profile, self.catalog, excluded_domains=["spokeo.com"])
        )

    def test_nonmatching_result_is_skipped(self):
        hit = SearchHit(engine="duckduckgo", title="Jordan Example", url="https://example.com/no-city")
        self.assertIsNone(analyze_hit(self.query, hit, self.profile, self.catalog))

    def test_low_signal_social_match_stays_low(self):
        query = next(q for q in build_queries(self.profile, SearchConfig()) if q.purpose == "username")
        hit = SearchHit(
            engine="duckduckgo",
            title="jordan-example",
            url="https://www.reddit.com/user/jordan-example",
            snippet="Jordan Example",
        )
        finding = analyze_hit(query, hit, self.profile, self.catalog)
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.category, "social")
        self.assertEqual(finding.severity, "low")

    def test_merge_same_url_keeps_highest_severity(self):
        base = dict(
            kind="search",
            category="social",
            source="duckduckgo",
            title="Profile",
            url="https://example.com/profile",
            snippet="short",
            severity="low",
            confidence=0.6,
            details={"queries": ["q1"]},
        )
        first = Finding(**base)
        second = Finding(
            **{
                **base,
                "title": "Profile and phone",
                "snippet": "a much longer snippet",
                "severity": "high",
                "confidence": 0.9,
                "details": {"queries": ["q2"], "reasons": ["phone"]},
            }
        )
        merged = merge_findings([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "high")
        self.assertEqual(merged[0].snippet, "a much longer snippet")
        self.assertEqual(sorted(merged[0].details["queries"]), ["q1", "q2"])

    def test_merge_profile_with_search_result(self):
        search = Finding(
            kind="search",
            category="code",
            source="duckduckgo",
            title="GitHub — Jordan",
            url="https://github.com/jordan-example",
            snippet="search snippet",
            severity="low",
            confidence=0.6,
        )
        profile = Finding(
            kind="profile",
            category="code",
            source="GitHub",
            title="GitHub profile: @jordan-example",
            url="https://github.com/jordan-example",
            snippet="direct profile",
            severity="medium",
            confidence=0.9,
            details={"provider": "github"},
        )
        merged = merge_findings([search, profile])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].kind, "profile")
        self.assertEqual(merged[0].source, "GitHub")
        self.assertEqual(merged[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
