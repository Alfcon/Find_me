"""Search-engine adapters. Public results only; no login or CAPTCHA bypass."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

from bs4 import BeautifulSoup

from .http import HttpClient
from .models import SearchHit
from .util import canonical_url, domain_of, host_is_engine, normalize_space, unwrap_redirect


class SearchEngineError(RuntimeError):
    pass


REGION_MAP = {
    "au-en": ("AU", "en", "au-en"),
    "us-en": ("US", "en", "us-en"),
    "uk-en": ("GB", "en", "uk-en"),
    "ca-en": ("CA", "en", "ca-en"),
    "nz-en": ("NZ", "en", "nz-en"),
    "ie-en": ("IE", "en", "ie-en"),
}


class SearchClient:
    def __init__(
        self,
        http: HttpClient,
        engines: list[str],
        *,
        region: str = "au-en",
        api_keys: dict[str, str] | None = None,
        fallback_engine: str = "bing",
        logger=None,
    ):
        self.http = http
        self.engines = engines
        self.region = region if region in REGION_MAP else "au-en"
        self.api_keys = api_keys or {}
        self.fallback_engine = fallback_engine if fallback_engine not in engines else ""
        self.logger = logger

    def availability(self) -> list[tuple[str, bool, str]]:
        rows = []
        for engine in self.engines:
            ok, reason = True, "ready"
            if engine in {"brave"} and not self.api_keys.get("brave"):
                ok, reason = False, "set BRAVE_SEARCH_API_KEY"
            elif engine == "google_cse" and not (
                self.api_keys.get("google_cse_key") and self.api_keys.get("google_cse_id")
            ):
                ok, reason = False, "set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID"
            elif engine == "serpapi" and not self.api_keys.get("serpapi"):
                ok, reason = False, "set SERPAPI_API_KEY"
            elif engine == "serper" and not self.api_keys.get("serper"):
                ok, reason = False, "set SERPER_API_KEY"
            rows.append((engine, ok, reason))
        return rows

    def search(
        self, engine: str, query: str, count: int = 8, *, force: bool = False
    ) -> list[SearchHit]:
        if engine not in self.engines and not force:
            raise SearchEngineError(f"{engine} is not enabled in the profile")
        if engine == "duckduckgo":
            return self._duckduckgo(query, count)
        if engine == "bing":
            return self._bing(query, count)
        if engine == "brave":
            return self._brave(query, count)
        if engine == "google_cse":
            return self._google_cse(query, count)
        if engine == "serpapi":
            return self._serpapi(query, count)
        if engine == "serper":
            return self._serper(query, count)
        raise SearchEngineError(f"unsupported search engine: {engine}")

    # ------------------------------------------------------------------
    # Free HTML engines
    # ------------------------------------------------------------------
    def _duckduckgo(self, query: str, count: int) -> list[SearchHit]:
        country, language, kl = REGION_MAP[self.region]
        response = self.http.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query, "kl": kl, "kp": "-2"},
            headers={"Referer": "https://html.duckduckgo.com/"},
            ttl=8 * 3600,
        )
        if response.status == 403 or "anomaly" in response.text.casefold():
            raise SearchEngineError(
                "DuckDuckGo served a bot check. Wait a few minutes, lower max_queries, "
                "configure Brave/Serper/SerpAPI/Google CSE, or use `footprint searches`."
            )
        if response.status != 200:
            raise SearchEngineError(f"DuckDuckGo returned HTTP {response.status}")
        return parse_duckduckgo(response.text, query, count)

    def _bing(self, query: str, count: int) -> list[SearchHit]:
        country, language, _ = REGION_MAP[self.region]
        # Bing's HTML endpoint frequently returns zero results for quoted
        # person names. Local exact-match filtering still protects us, so ask
        # Bing without the quotes.
        query = query.replace('"', "").strip()
        response = self.http.get(
            "https://www.bing.com/search",
            params={
                "q": query,
                "count": min(20, count),
                "setlang": language,
                "cc": country,
                "safeSearch": "Moderate",
                "form": "QBLH",
            },
            headers={"Referer": "https://www.bing.com/"},
            ttl=8 * 3600,
        )
        if response.status != 200:
            raise SearchEngineError(f"Bing returned HTTP {response.status}")
        return parse_bing(response.text, query, count)

    # ------------------------------------------------------------------
    # Optional APIs
    # ------------------------------------------------------------------
    def _brave(self, query: str, count: int) -> list[SearchHit]:
        key = self.api_keys.get("brave", "")
        if not key:
            raise SearchEngineError("Brave Search API key is not configured")
        country, language, _ = REGION_MAP[self.region]
        response = self.http.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={
                "q": query,
                "count": max(1, min(20, count)),
                "country": country,
                "search_lang": language,
                "safesearch": "moderate",
                "text_decorations": "0",
            },
            headers={"Accept": "application/json", "X-Subscription-Token": key},
            ttl=8 * 3600,
        )
        if response.status == 401:
            raise SearchEngineError("Brave Search API rejected the key")
        if response.status == 429:
            raise SearchEngineError("Brave Search API rate limit reached")
        if response.status != 200:
            raise SearchEngineError(f"Brave Search returned HTTP {response.status}")
        return parse_brave(response.json(), query, count)

    def _google_cse(self, query: str, count: int) -> list[SearchHit]:
        key = self.api_keys.get("google_cse_key", "")
        cx = self.api_keys.get("google_cse_id", "")
        if not key or not cx:
            raise SearchEngineError("Google CSE key and engine ID are not configured")
        country, language, _ = REGION_MAP[self.region]
        response = self.http.get(
            "https://www.googleapis.com/customsearch/v1",
            params={
                "key": key,
                "cx": cx,
                "q": query,
                "num": max(1, min(10, count)),
                "gl": country.lower(),
                "hl": language,
                "safe": "active",
            },
            headers={"Accept": "application/json"},
            ttl=8 * 3600,
        )
        if response.status in {401, 403}:
            raise SearchEngineError("Google CSE rejected the API key or engine ID")
        if response.status == 429:
            raise SearchEngineError("Google CSE daily quota reached")
        if response.status != 200:
            raise SearchEngineError(f"Google CSE returned HTTP {response.status}")
        return parse_google_cse(response.json(), query, count)

    def _serper(self, query: str, count: int) -> list[SearchHit]:
        key = self.api_keys.get("serper", "")
        if not key:
            raise SearchEngineError("Serper API key is not configured")
        country, language, _ = REGION_MAP[self.region]
        response = self.http.post_json(
            "https://google.serper.dev/search",
            {
                "q": query,
                "gl": country.lower(),
                "hl": language,
                "num": max(1, min(10, count)),
            },
            headers={"X-API-KEY": key},
        )
        if response.status in {401, 403}:
            raise SearchEngineError("Serper rejected the API key")
        if response.status == 429:
            raise SearchEngineError("Serper quota or rate limit reached")
        if response.status != 200:
            raise SearchEngineError(f"Serper returned HTTP {response.status}")
        return parse_serper(response.json(), query, count)

    def _serpapi(self, query: str, count: int) -> list[SearchHit]:
        key = self.api_keys.get("serpapi", "")
        if not key:
            raise SearchEngineError("SerpAPI key is not configured")
        country, language, _ = REGION_MAP[self.region]
        response = self.http.get(
            "https://serpapi.com/search.json",
            params={
                "engine": "google",
                "q": query,
                "num": max(1, min(10, count)),
                "gl": country.lower(),
                "hl": language,
                "api_key": key,
                "safe": "active",
            },
            headers={"Accept": "application/json"},
            ttl=8 * 3600,
        )
        if response.status in {401, 403}:
            raise SearchEngineError("SerpAPI rejected the API key")
        if response.status == 429:
            raise SearchEngineError("SerpAPI quota or rate limit reached")
        if response.status != 200:
            raise SearchEngineError(f"SerpAPI returned HTTP {response.status}")
        return parse_serpapi(response.json(), query, count)


# ----------------------------------------------------------------------
# Parsers are separately testable so the tool can run its test suite offline.
# ----------------------------------------------------------------------
def _clean(value: str) -> str:
    value = value or ""
    # Avoid BeautifulSoup's filename warning for snippets that are just URLs
    # or short plain strings.
    if "<" in value and ">" in value:
        value = BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    return normalize_space(value)


def _acceptable(url: str) -> bool:
    if not url:
        return False
    host = domain_of(url)
    if not host or host_is_engine(host):
        return False
    if host.endswith("bing.com") or host.endswith("duckduckgo.com"):
        return False
    return True


def _dedupe(hits: list[SearchHit], count: int) -> list[SearchHit]:
    result: list[SearchHit] = []
    seen: set[str] = set()
    for hit in hits:
        url = canonical_url(unwrap_redirect(hit.url))
        if not url or not _acceptable(url) or url in seen:
            continue
        seen.add(url)
        hit.url = url
        result.append(hit)
        if len(result) >= count:
            break
    for index, hit in enumerate(result, 1):
        hit.rank = index
    return result


def parse_duckduckgo(html: str, query: str, count: int = 8) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    if soup.select_one("form#challenge-form") or "Unfortunately, bots use DuckDuckGo" in html:
        raise SearchEngineError("DuckDuckGo served a bot challenge")
    hits: list[SearchHit] = []
    for block in soup.select(".result, .web-result"):
        if "result--ad" in (block.get("class") or []):
            continue
        link = block.select_one(".result__a")
        if not link or not link.get("href"):
            continue
        snippet = block.select_one(".result__snippet")
        hits.append(
            SearchHit(
                engine="duckduckgo",
                title=_clean(link.get_text(" ", strip=True)),
                url=unwrap_redirect(link.get("href", "")),
                snippet=_clean(snippet.get_text(" ", strip=True)) if snippet else "",
                query=query,
            )
        )
    return _dedupe(hits, count)


def parse_bing(html: str, query: str, count: int = 8) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for block in soup.select("li.b_algo"):
        link = block.select_one("h2 a")
        if not link or not link.get("href"):
            continue
        snippet = block.select_one(".b_caption p, .b_snippet, p")
        hits.append(
            SearchHit(
                engine="bing",
                title=_clean(link.get_text(" ", strip=True)),
                url=link.get("href", ""),
                snippet=_clean(snippet.get_text(" ", strip=True)) if snippet else "",
                query=query,
            )
        )
    return _dedupe(hits, count)


def parse_brave(payload: dict[str, Any], query: str, count: int = 8) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for item in ((payload or {}).get("web") or {}).get("results") or []:
        hits.append(
            SearchHit(
                engine="brave",
                title=_clean(item.get("title", "")),
                url=item.get("url", ""),
                snippet=_clean(item.get("description", "")),
                query=query,
            )
        )
    return _dedupe(hits, count)


def parse_google_cse(payload: dict[str, Any], query: str, count: int = 8) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for item in (payload or {}).get("items") or []:
        hits.append(
            SearchHit(
                engine="google_cse",
                title=_clean(item.get("title", "")),
                url=item.get("link", ""),
                snippet=_clean(item.get("snippet", "")),
                query=query,
            )
        )
    return _dedupe(hits, count)


def parse_serper(payload: dict[str, Any], query: str, count: int = 8) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for item in (payload or {}).get("organic") or []:
        hits.append(
            SearchHit(
                engine="serper",
                title=_clean(item.get("title", "")),
                url=item.get("link", ""),
                snippet=_clean(item.get("snippet", "")),
                query=query,
            )
        )
    return _dedupe(hits, count)


def parse_serpapi(payload: dict[str, Any], query: str, count: int = 8) -> list[SearchHit]:
    hits: list[SearchHit] = []
    for item in (payload or {}).get("organic_results") or []:
        hits.append(
            SearchHit(
                engine="serpapi",
                title=_clean(item.get("title", "")),
                url=item.get("link", ""),
                snippet=_clean(item.get("snippet", "")),
                query=query,
            )
        )
    return _dedupe(hits, count)


def engine_label(engine: str) -> str:
    return {
        "duckduckgo": "DuckDuckGo",
        "bing": "Bing",
        "brave": "Brave Search API",
        "google_cse": "Google Programmable Search",
        "serpapi": "SerpAPI (Google)",
        "serper": "Serper (Google)",
    }.get(engine, engine)


def direct_search_url(engine: str, query: str, region: str = "au-en") -> str:
    country, language, kl = REGION_MAP.get(region, REGION_MAP["au-en"])
    if engine == "duckduckgo":
        return f"https://duckduckgo.com/?q={quote_plus(query)}&kl={kl}"
    if engine == "bing":
        return f"https://www.bing.com/search?q={quote_plus(query)}&cc={country}&setlang={language}"
    if engine == "google":
        return f"https://www.google.com/search?q={quote_plus(query)}&gl={country.lower()}&hl={language}"
    if engine == "brave":
        return f"https://search.brave.com/search?q={quote_plus(query)}"
    return ""
