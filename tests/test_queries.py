from __future__ import annotations

import unittest

from footprint.brokers import load_catalog
from footprint.config import Profile, SearchConfig
from footprint.queries import build_queries, match_query


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.profile = Profile.from_mapping(
            {
                "display_name": "Jordan Example",
                "emails": ["jordan@example.com"],
                "phones": ["+61 412 345 678"],
                "usernames": ["jordan-example"],
                "addresses": ["12 Example Street, Melbourne VIC 3000"],
                "locations": ["Melbourne, Australia"],
            }
        )

    def test_plan_contains_high_value_exact_queries(self):
        queries = build_queries(self.profile, SearchConfig(max_queries=20))
        texts = [query.text for query in queries]
        self.assertIn('"jordan@example.com"', texts)
        self.assertTrue(any("412" in text for text in texts))
        self.assertTrue(any('"jordan-example"' == text for text in texts))
        self.assertTrue(any('"Jordan Example" "Melbourne"' == text for text in texts))
        self.assertLessEqual(len(queries), 20)

    def test_max_queries_cap(self):
        queries = build_queries(self.profile, SearchConfig(max_queries=3))
        self.assertEqual(len(queries), 3)

    def test_name_location_requires_both_anchors(self):
        query = next(q for q in build_queries(self.profile, SearchConfig()) if q.purpose == "name_location")
        match = match_query(query, "Jordan Example, Melbourne", "A local profile", "https://example.com/a")
        self.assertIsNotNone(match)
        self.assertGreaterEqual(match.confidence, 0.7)
        self.assertIsNone(match_query(query, "Jordan Example", "No city here", "https://example.com/b"))

    def test_username_match_has_boundary(self):
        query = next(q for q in build_queries(self.profile, SearchConfig()) if q.purpose == "username")
        self.assertIsNotNone(match_query(query, "Profile", "jordan-example on a site", "https://example.com/x"))
        self.assertIsNone(match_query(query, "Profile", "jordan-example-extra", "https://example.com/x"))

    def test_phone_match_tolerates_formatting(self):
        query = next(q for q in build_queries(self.profile, SearchConfig()) if q.purpose == "phone")
        self.assertIsNotNone(
            match_query(query, "Contact", "Call +61 (0) 412 345 678 today", "https://example.com/x")
        )
        self.assertIsNone(match_query(query, "Contact", "Call +61 400 000 000", "https://example.com/x"))

    def test_name_email_profile_gets_broad_and_handle_queries(self):
        profile = Profile.from_mapping(
            {"display_name": "Alex Example", "email": "alex@example.com", "country": "Australia"}
        )
        queries = build_queries(profile, SearchConfig(max_queries=30))
        purposes = {query.purpose for query in queries}
        self.assertIn("name_email", purposes)
        self.assertIn("name_handle", purposes)
        self.assertIn("email_handle", purposes)
        self.assertIn("name_country", purposes)
        self.assertIn("platform_probe", purposes)
        self.assertIn("name_only", purposes)
        self.assertTrue(any(query.identifier_type == "username" for query in queries))

    def test_phone_profile_gets_variants_and_name_phone_query(self):
        profile = Profile.from_mapping(
            {"display_name": "Jordan Example", "phone": "0412 345 678"}
        )
        queries = build_queries(profile, SearchConfig(max_queries=30))
        phone_queries = [query for query in queries if query.purpose in {"phone", "name_phone"}]
        self.assertGreaterEqual(len(phone_queries), 2)
        self.assertTrue(any("0412345678" in query.text for query in phone_queries))

    def test_phone_broker_probes(self):
        profile = Profile.from_mapping({"phone": "0412 345 678"})
        catalog = load_catalog().filter_regions(["AU"])
        queries = build_queries(
            profile,
            SearchConfig(broker_probes=True, broker_probe_count=2, max_queries=50),
            catalog,
        )
        probes = [query for query in queries if query.purpose == "broker_probe"]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(query.identifier_type == "phone" for query in probes))

    def test_broker_probes_are_opt_in(self):
        catalog = load_catalog().filter_regions(["AU"])
        disabled = build_queries(self.profile, SearchConfig(broker_probes=False), catalog)
        self.assertFalse(any(query.purpose == "broker_probe" for query in disabled))
        enabled = build_queries(
            self.profile,
            SearchConfig(broker_probes=True, broker_probe_count=2, max_queries=50),
            catalog,
        )
        probes = [query for query in enabled if query.purpose == "broker_probe"]
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(query.text.startswith("site:") for query in probes))

    def test_name_only_profile_gets_safe_fallback(self):
        profile = Profile.from_mapping({"display_name": "Jordan Example", "locations": ["Melbourne"]})
        queries = build_queries(
            profile, SearchConfig(platform_probes=False, broad_name=False)
        )
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].purpose, "name_location")
        broad = build_queries(
            profile, SearchConfig(platform_probes=False, broad_name=True)
        )
        self.assertTrue(any(query.purpose == "name_only" for query in broad))


if __name__ == "__main__":
    unittest.main()
