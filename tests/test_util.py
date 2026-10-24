from __future__ import annotations

import unittest

from footprint.util import (
    Redactor,
    canonical_url,
    domain_matches,
    mask_email,
    normalize_phone,
    normalize_text,
    phone_variants,
    safe_href,
    unwrap_redirect,
)


class UtilityTests(unittest.TestCase):
    def test_phone_variants_include_australian_international_form(self):
        variants = phone_variants("0412 345 678")
        self.assertIn("0412 345 678", variants)
        self.assertIn("+61 412345678", variants)
        self.assertIn("0412345678", variants)

    def test_phone_normalization(self):
        self.assertEqual(normalize_phone("+61 (0) 412-345-678"), "+610412345678")

    def test_domain_matching_is_boundary_aware(self):
        self.assertTrue(domain_matches("www.spokeo.com", "spokeo.com"))
        self.assertTrue(domain_matches("a.b.example.com", "example.com"))
        self.assertFalse(domain_matches("notspokeo.com", "spokeo.com"))

    def test_canonical_url_removes_tracking_and_fragment(self):
        url = canonical_url("HTTPS://Example.com:443/a/?utm_source=x&id=2#section")
        self.assertEqual(url, "https://example.com/a?id=2")

    def test_unsafe_urls_are_rejected_for_links(self):
        self.assertEqual(safe_href("javascript:alert(1)"), "")
        self.assertEqual(safe_href("http://127.0.0.1/admin"), "")
        self.assertEqual(safe_href("http://localhost/x"), "")
        self.assertTrue(safe_href("https://example.com/profile"))

    def test_redactor_masks_configured_values(self):
        redactor = Redactor(
            [("name", "Jordan Example"), ("email", "jordan@example.com"), ("phone", "+61412345678")],
            enabled=True,
        )
        result = redactor.text("Jordan Example jordan@example.com +61 412 345 678")
        self.assertNotIn("Jordan Example", result)
        self.assertNotIn("jordan@example.com", result)
        self.assertNotIn("412 345 678", result)
        self.assertIn("j***@example.com", result)

    def test_redactor_obj_recurses(self):
        redactor = Redactor([("email", "a@b.com")], enabled=True)
        data = {"email": "a@b.com", "items": ["a@b.com", 3]}
        self.assertEqual(redactor.obj(data)["email"], "a***@b.com")
        self.assertEqual(redactor.obj(data)["items"][1], 3)

    def test_text_normalization(self):
        self.assertEqual(normalize_text("  Café—Example! "), "cafe example")

    def test_mask_email(self):
        self.assertEqual(mask_email("jordan@example.com"), "j***@example.com")

    def test_google_redirect_is_unwrapped(self):
        url = "https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fprofile&sa=U"
        self.assertEqual(unwrap_redirect(url), "https://example.com/profile")

    def test_bing_redirect_is_unwrapped(self):
        import base64

        encoded = base64.urlsafe_b64encode(b"https://example.com/page?x=1").decode().rstrip("=")
        url = f"https://www.bing.com/ck/a?u=a1{encoded}"
        self.assertEqual(unwrap_redirect(url), "https://example.com/page?x=1")


if __name__ == "__main__":
    unittest.main()
