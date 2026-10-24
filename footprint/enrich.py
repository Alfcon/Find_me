"""Enrich a finding with a public page's visible metadata and evidence.

This is deliberately opt-in: fetching a result page tells that site your IP
address. Only public, safe HTTP(S) pages are fetched; no login, CAPTCHA, or
access-control bypass is attempted. The full page is not stored. Only selected
fields and short excerpts are kept locally.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote

from bs4 import BeautifulSoup

from .brokers import BrokerCatalog, load_catalog
from .config import AppConfig, Profile
from .data_points import DataPoint, points_from_text
from .db import Store
from .http import HttpClient, HttpError, friendly_http_error
from .util import (
    compact,
    domain_of,
    is_safe_public_url,
    iso_now,
    normalize_space,
    normalize_text,
    safe_href,
)


@dataclass
class EnrichResult:
    finding_id: int
    url: str
    status: str
    title: str = ""
    points: list[DataPoint] = field(default_factory=list)
    excerpts: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class EnrichSummary:
    attempted: int = 0
    enriched: int = 0
    skipped: int = 0
    failed: int = 0
    results: list[EnrichResult] = field(default_factory=list)


class Enricher:
    def __init__(
        self,
        config: AppConfig,
        store: Store,
        *,
        http: HttpClient | None = None,
        catalog: BrokerCatalog | None = None,
        on_progress: Callable[[str], None] | None = None,
    ):
        self.config = config
        self.profile = config.profile
        self.store = store
        self.catalog = catalog or load_catalog()
        self.http = http or HttpClient(config.cache_dir, min_interval=1.5)
        self._owns_http = http is None
        self.on_progress = on_progress

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def enrich_finding(self, finding_id: int, *, force: bool = False) -> EnrichResult:
        finding = self.store.get_finding(finding_id)
        if not finding:
            return EnrichResult(finding_id, "", "missing", error=f"No finding with id {finding_id}")
        url = finding.get("url") or ""
        if not url or not is_safe_public_url(url):
            return EnrichResult(finding_id, url, "skipped", error="Finding has no safe public URL")
        host = domain_of(url)
        if any(
            host == engine or host.endswith("." + engine)
            for engine in (
                "google.com",
                "bing.com",
                "duckduckgo.com",
                "search.brave.com",
                "xposedornot.com",
                "haveibeenpwned.com",
            )
        ):
            return EnrichResult(
                finding_id,
                url,
                "skipped",
                error="Index/breach dashboard, not a source profile page",
            )
        details = finding.get("details") or {}
        previous = details.get("enrichment") or {}
        if previous.get("status") == "ok" and not force:
            return EnrichResult(
                finding_id,
                url,
                "ok",
                title=str(previous.get("title") or ""),
                points=[DataPoint(**item) for item in previous.get("data_points", []) if isinstance(item, dict)],
                excerpts=list(previous.get("excerpts") or []),
            )
        if self.on_progress:
            self.on_progress(f"Fetching #{finding_id} {host}")
        try:
            response = self.http.get(
                url,
                ttl=24 * 3600 if not force else 0,
                timeout=20,
                headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"},
            )
        except HttpError as exc:
            result = EnrichResult(finding_id, url, "error", error=friendly_http_error(exc))
            self._save(finding, result, details)
            return result
        content_type = (response.headers.get("content-type") or "").casefold()
        if response.status != 200:
            result = EnrichResult(finding_id, url, "error", error=f"HTTP {response.status}")
            self._save(finding, result, details)
            return result
        if content_type and "html" not in content_type and "text/plain" not in content_type:
            result = EnrichResult(finding_id, url, "skipped", error=f"Unsupported content type: {content_type}")
            self._save(finding, result, details)
            return result
        parsed = parse_page(response.text, url, self.profile, finding)
        result = EnrichResult(
            finding_id=finding_id,
            url=url,
            status="ok",
            title=str(parsed.get("title") or finding.get("title") or ""),
            points=[DataPoint(**item) for item in parsed.get("points", [])],
            excerpts=list(parsed.get("excerpts") or []),
        )
        self._save(finding, result, details, parsed)
        return result

    def enrich_many(
        self,
        finding_ids: list[int] | None = None,
        *,
        limit: int | None = None,
        force: bool = False,
        status: str = "active",
    ) -> EnrichSummary:
        if finding_ids:
            findings = [self.store.get_finding(finding_id) for finding_id in finding_ids]
            findings = [item for item in findings if item]
        else:
            findings = self.store.list_findings(status=status, limit=limit or 1000)
        summary = EnrichSummary()
        for finding in findings:
            summary.attempted += 1
            result = self.enrich_finding(int(finding["id"]), force=force)
            summary.results.append(result)
            if result.status == "ok":
                summary.enriched += 1
            elif result.status == "skipped":
                summary.skipped += 1
            else:
                summary.failed += 1
        return summary

    def _save(
        self,
        finding: dict[str, Any],
        result: EnrichResult,
        details: dict[str, Any],
        parsed: dict[str, Any] | None = None,
    ) -> None:
        parsed = parsed or {}
        enrichment = {
            "status": result.status,
            "url": result.url,
            "fetched_at": iso_now(),
            "http_error": result.error,
            "title": result.title,
            "meta_description": parsed.get("meta_description", ""),
            "h1": parsed.get("h1", ""),
            "fields": parsed.get("fields", {}),
            "excerpts": result.excerpts,
            "observed_identifiers": parsed.get("observed_identifiers", []),
            "data_points": [point.as_dict() for point in result.points],
        }
        details["enrichment"] = enrichment
        if result.points:
            existing = details.get("data_points")
            if not isinstance(existing, list):
                existing = []
            merged = {(
                str(item.get("kind")),
                str(item.get("value") or "").casefold(),
            ): item for item in existing if isinstance(item, dict)}
            for point in result.points:
                item = point.as_dict()
                merged[(item["kind"], item["value"].casefold())] = item
            details["data_points"] = list(merged.values())[:40]
        self.store.update_finding_details(int(finding["id"]), details)
        if parsed.get("title"):
            current_title = str(finding.get("title") or "")
            host = domain_of(result.url)
            if not current_title or host.casefold() in current_title.casefold():
                self.store.update_finding_title(int(finding["id"]), str(parsed["title"])[:250])
        if result.status == "ok" and self.on_progress:
            self.on_progress(
                f"  {result.title or result.url[:60]} — {len(result.points)} data point(s)"
            )


def parse_page(html: str, url: str, profile: Profile, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse public HTML into selected fields, evidence excerpts, and data points."""
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        # Keep JSON-LD scripts; remove executable/style content later.
        if tag.name == "script" and (tag.get("type") or "").casefold() == "application/ld+json":
            continue
        tag.decompose()
    title = normalize_space(soup.title.get_text(" ", strip=True)) if soup.title else ""
    description = ""
    meta = soup.select_one('meta[name="description"], meta[property="og:description"]')
    if meta and meta.get("content"):
        description = normalize_space(str(meta["content"]))
    h1 = ""
    if soup.select_one("h1"):
        h1 = normalize_space(soup.select_one("h1").get_text(" ", strip=True))
    text = normalize_space(soup.get_text(" ", strip=True))
    text = text[:30000]

    jsonld = _jsonld_fields(soup)
    fields: dict[str, str] = {}
    for key in ("name", "email", "telephone", "address", "jobTitle", "worksFor", "birthDate", "image", "url"):
        value = jsonld.get(key)
        if value:
            fields[key] = compact(str(value), 300)
    if description:
        fields["meta_description"] = compact(description, 300)
    if h1:
        fields["heading"] = compact(h1, 200)
    for item in soup.select("[itemprop]"):
        prop = str(item.get("itemprop") or "").casefold()
        if prop in {"name", "email", "telephone", "address", "jobtitle", "worksfor", "birthdate"}:
            value = normalize_space(item.get_text(" ", strip=True))
            if value:
                fields.setdefault(prop, compact(value, 200))

    points: list[DataPoint] = []
    structured_map = {
        "name": "name",
        "email": "email",
        "telephone": "phone",
        "address": "address",
        "jobTitle": "job_title",
        "worksFor": "employer",
        "birthDate": "dob",
        "image": "photo",
    }
    core_values = {
        "name": [profile.display_name] if profile.display_name else [],
        "email": profile.emails,
        "phone": profile.phones,
        "address": profile.addresses,
    }
    for field_name, kind in structured_map.items():
        value = fields.get(field_name)
        if not value:
            continue
        observed = _value_matches(field_name, value, core_values.get(kind, []))
        # Employer/title/photo are useful only when the page also names the user.
        user_named = bool(profile.display_name and profile.display_name.casefold() in text.casefold())
        if kind in {"job_title", "employer", "photo"} and not user_named and not observed:
            continue
        points.append(
            DataPoint(
                kind=kind,
                label=_kind_label(kind),
                value=compact(value, 200),
                evidence=compact(f"{field_name}: {value}", 300),
                confidence=0.9 if observed else 0.55,
                source=domain_of(url),
                observed=observed,
            )
        )
    for link in soup.select('a[href^="mailto:"], a[href^="tel:"]'):
        href = unquote(str(link.get("href") or ""))
        if href.startswith("mailto:"):
            email = href.split(":", 1)[1].split("?", 1)[0].strip()
            if email.casefold() in {item.casefold() for item in profile.emails}:
                points.append(DataPoint("email", "Email address", email, "mailto link", 0.95, domain_of(url), True))
        elif href.startswith("tel:"):
            phone = href.split(":", 1)[1].strip()
            if _value_matches("phone", phone, profile.phones):
                points.append(DataPoint("phone", "Phone number", phone, "tel link", 0.8, domain_of(url), True))
    user_named = bool(profile.display_name and profile.display_name.casefold() in text.casefold())
    if user_named:
        for value in jsonld.get("sameAs", []) if isinstance(jsonld.get("sameAs"), list) else []:
            if value:
                points.append(
                    DataPoint(
                        "social",
                        "Social profile links",
                        str(value),
                        "structured data sameAs",
                        0.7,
                        domain_of(url),
                        True,
                    )
                )
    text_points = points_from_text(text, profile, source=domain_of(url), evidence=compact(text, 300))
    if not user_named:
        # Generic phrases such as "phone number" on a login/help page are not
        # evidence that the site holds the user's phone number.
        text_points = [point for point in text_points if point.observed]
    points.extend(text_points)
    points = _dedupe_points(points)
    excerpts = _excerpts(text, profile)
    return {
        "title": title,
        "meta_description": description,
        "h1": h1,
        "fields": fields,
        "points": [point.as_dict() for point in points[:24]],
        "excerpts": excerpts,
        "observed_identifiers": [
            value for value in _profile_values(profile) if value.casefold() in text.casefold()
        ],
    }


def _jsonld_fields(soup: BeautifulSoup) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for script in soup.select('script[type="application/ld+json"]'):
        raw = script.string or script.get_text() or ""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        _walk_jsonld(data, result)
    return result


def _walk_jsonld(value: Any, result: dict[str, Any]) -> None:
    if isinstance(value, list):
        for item in value:
            _walk_jsonld(item, result)
        return
    if not isinstance(value, dict):
        return
    for key in ("name", "email", "telephone", "address", "jobTitle", "worksFor", "birthDate", "image", "sameAs", "url"):
        if key in value and key not in result:
            item = value[key]
            if isinstance(item, dict):
                item = " ".join(str(part) for part in item.values() if isinstance(part, (str, int)))
            if isinstance(item, list):
                item = [str(part) for part in item if part]
            if item:
                result[key] = item
    for item in value.values():
        if isinstance(item, (dict, list)):
            _walk_jsonld(item, result)


def _profile_values(profile: Profile) -> list[str]:
    values = []
    for _, value in profile.identifiers():
        if value:
            values.append(value)
    return values


def _value_matches(field_name: str, value: str, candidates: list[str]) -> bool:
    value_cf = normalize_text(value)
    for candidate in candidates:
        if not candidate:
            continue
        if field_name in {"telephone", "phone"}:
            digits = re.sub(r"\D", "", candidate)
            if len(digits) >= 7 and digits[-9:] in re.sub(r"\D", "", value):
                return True
        elif normalize_text(candidate) and normalize_text(candidate) in value_cf:
            return True
    return False


def _excerpts(text: str, profile: Profile, limit: int = 4) -> list[str]:
    excerpts: list[str] = []
    lowered = text.casefold()
    needles = _profile_values(profile) + [
        "date of birth",
        "relatives",
        "home address",
        "phone number",
        "job title",
        "employer",
    ]
    for needle in needles:
        if not needle:
            continue
        index = lowered.find(needle.casefold())
        if index < 0:
            continue
        start = max(0, index - 120)
        end = min(len(text), index + len(needle) + 180)
        excerpt = compact(text[start:end], 360)
        if excerpt and excerpt not in excerpts:
            excerpts.append(excerpt)
        if len(excerpts) >= limit:
            break
    return excerpts


def _kind_label(kind: str) -> str:
    from .data_points import LABELS

    return LABELS.get(kind, kind.replace("_", " ").title())


def _dedupe_points(points: list[DataPoint]) -> list[DataPoint]:
    merged: dict[tuple[str, str], DataPoint] = {}
    for point in points:
        key = (point.kind, point.value.casefold().strip())
        existing = merged.get(key)
        if not existing or point.confidence > existing.confidence:
            merged[key] = point
    return sorted(
        merged.values(),
        key=lambda item: (item.kind not in {"address", "phone", "dob", "government_id", "financial", "password"}, item.kind),
    )
