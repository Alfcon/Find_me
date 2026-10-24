from __future__ import annotations

import unittest

from footprint.search import (
    SearchEngineError,
    parse_bing,
    parse_brave,
    parse_duckduckgo,
    parse_google_cse,
    parse_serpapi,
    parse_serper,
)

DDG_HTML = """
<html><body>
<div class="result result--ad"><a class="result__a" href="https://ads.example.com/x">Ad</a></div>
<div class="result">
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fjordan%3Futm_source%3Dx&rut=1">Jordan Example — Profile</a>
  <a class="result__snippet">Jordan Example lives in <b>Melbourne</b>.</a>
</div>
<div class="result">
  <a class="result__a" href="https://duckduckgo.com/y.js?ad=1">Internal</a>
  <a class="result__snippet">Not a result.</a>
</div>
</body></html>
"""

BING_HTML = """
<html><body>
<ol id="b_results">
<li class="b_algo"><h2><a href="https://example.com/bing-result">Jordan Example</a></h2>
<div class="b_caption"><p>Melbourne based.</p></div></li>
</ol>
</body></html>
"""


class SearchParserTests(unittest.TestCase):
    def test_duckduckgo_unwraps_and_filters_ads(self):
        hits = parse_duckduckgo(DDG_HTML, "query", 8)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].url, "https://example.com/jordan")
        self.assertEqual(hits[0].title, "Jordan Example — Profile")
        self.assertIn("Melbourne", hits[0].snippet)

    def test_duckduckgo_bot_challenge_raises(self):
        with self.assertRaises(SearchEngineError):
            parse_duckduckgo("<html><form id='challenge-form'></form></html>", "q")

    def test_bing_parser(self):
        hits = parse_bing(BING_HTML, "query", 8)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].url, "https://example.com/bing-result")

    def test_brave_parser(self):
        hits = parse_brave(
            {"web": {"results": [{"title": "A", "url": "https://example.com/a", "description": "B"}]}},
            "q",
        )
        self.assertEqual(hits[0].title, "A")

    def test_google_cse_parser(self):
        hits = parse_google_cse(
            {"items": [{"title": "A", "link": "https://example.com/a", "snippet": "B"}]}, "q"
        )
        self.assertEqual(hits[0].url, "https://example.com/a")

    def test_serpapi_parser(self):
        hits = parse_serpapi(
            {"organic_results": [{"title": "A", "link": "https://example.com/a", "snippet": "B"}]},
            "q",
        )
        self.assertEqual(hits[0].snippet, "B")

    def test_serper_parser(self):
        hits = parse_serper(
            {"organic": [{"title": "A", "link": "https://example.com/a", "snippet": "B"}]},
            "q",
        )
        self.assertEqual(hits[0].title, "A")


if __name__ == "__main__":
    unittest.main()
