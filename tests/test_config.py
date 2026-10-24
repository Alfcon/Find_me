from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from footprint.brokers import load_catalog
from footprint.config import (
    ConfigError,
    Profile,
    build_config,
    load_config,
    write_config,
)


class ConfigTests(unittest.TestCase):
    def test_profile_normalizes_and_rejects_empty(self):
        profile = Profile.from_mapping(
            {
                "name": "  Jordan   Example ",
                "email": "Jordan@Example.com",
                "username": "@Jordan-Example",
                "phone": "+61 412 345 678",
            }
        )
        self.assertEqual(profile.display_name, "Jordan Example")
        self.assertEqual(profile.emails, ["jordan@example.com"])
        self.assertEqual(profile.usernames, ["jordan-example"])
        with self.assertRaises(ConfigError):
            Profile.from_mapping({"emails": []})

    def test_invalid_email_username_and_phone(self):
        with self.assertRaises(ConfigError):
            Profile.from_mapping({"email": "not-an-email"})
        with self.assertRaises(ConfigError):
            Profile.from_mapping({"username": "not a handle"})
        with self.assertRaises(ConfigError):
            Profile.from_mapping({"phone": "123"})

    def test_websites_become_domains(self):
        profile = Profile.from_mapping({"email": "a@example.com", "websites": ["example.com"]})
        self.assertEqual(profile.websites, ["https://example.com/"])
        self.assertEqual(profile.domain_names, ["example.com"])

    def test_write_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.yaml"
            raw = build_config(name="Alex Example", emails=["alex@example.com"], locations=["Melbourne"])
            write_config(path, raw)
            config = load_config(path)
            self.assertEqual(config.profile.display_name, "Alex Example")
            self.assertEqual(config.profile.emails, ["alex@example.com"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(config.db_path.is_absolute())
            self.assertFalse(config.db_path.exists())
            self.assertEqual(config.report_path.name, "Alex-Example-footprint-report.html")

    def test_no_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.yaml"
            write_config(path, build_config(email="a@example.com"))
            with self.assertRaises(ConfigError):
                write_config(path, build_config(email="b@example.com"))

    def test_api_keys_come_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.yaml"
            write_config(path, build_config(email="a@example.com"))
            config = load_config(path)
            old = os.environ.get("HIBP_API_KEY")
            os.environ["HIBP_API_KEY"] = "test-key"
            try:
                self.assertEqual(config.api_keys["hibp"], "test-key")
            finally:
                if old is None:
                    os.environ.pop("HIBP_API_KEY", None)
                else:
                    os.environ["HIBP_API_KEY"] = old

    def test_email_derives_likely_usernames(self):
        profile = Profile.from_mapping(
            {"display_name": "John Smith", "email": "john.smith+tag@example.com"}
        )
        self.assertEqual(profile.email_locals, ["john.smith"])
        self.assertIn("john.smith", profile.derived_usernames)
        self.assertIn("johnsmith", profile.derived_usernames)
        self.assertIn("john-smith", profile.derived_usernames)
        self.assertEqual(profile.all_usernames, profile.derived_usernames)

    def test_country_sets_default_broker_regions(self):
        us = build_config(email="a@example.com", country="United States")
        uk = build_config(email="a@example.com", country="United Kingdom")
        au = build_config(email="a@example.com", country="Australia")
        self.assertEqual(us["brokers"]["regions"], ["US", "GLOBAL"])
        self.assertEqual(uk["brokers"]["regions"], ["UK", "GLOBAL"])
        self.assertEqual(au["brokers"]["regions"], ["AU", "GLOBAL"])
        self.assertEqual(us["search"]["region"], "us-en")
        self.assertEqual(uk["search"]["region"], "uk-en")
        self.assertEqual(au["search"]["region"], "au-en")

    def test_broker_catalog_loads_and_finds_domains(self):
        catalog = load_catalog()
        self.assertGreaterEqual(len(catalog.brokers), 20)
        self.assertEqual(catalog.find_by_domain("www.spokeo.com").id, "spokeo")
        self.assertIsNone(catalog.find_by_domain("example.com"))
        self.assertTrue(catalog.removal_channels())
        au = catalog.people_search(["AU"])
        self.assertTrue(any(broker.id == "whitepages-au" for broker in au))


if __name__ == "__main__":
    unittest.main()
