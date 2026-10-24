"""Classify public search results into risk categories and findings."""

from __future__ import annotations

from typing import Iterable

from .brokers import BrokerCatalog, category_label
from .config import Profile
from .models import Finding, SearchHit, SearchQuery
from .queries import match_query
from .util import domain_of, max_severity, normalize_text, phone_digits, severity_rank

SOCIAL_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "tiktok.com",
    "reddit.com",
    "youtube.com",
    "pinterest.com",
    "tumblr.com",
    "threads.net",
    "bsky.app",
    "mastodon.social",
    "snapchat.com",
    "discord.com",
    "t.me",
    "vk.com",
    "weibo.com",
    "xiaohongshu.com",
}
CODE_DOMAINS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "stackexchange.com",
    "npmjs.com",
    "pypi.org",
    "huggingface.co",
    "kaggle.com",
    "codepen.io",
    "replit.com",
    "sourceforge.net",
}
PROFESSIONAL_DOMAINS = {
    "about.me",
    "crunchbase.com",
    "wellfound.com",
    "angel.co",
    "behance.net",
    "dribbble.com",
    "medium.com",
    "substack.com",
}
PUBLIC_RECORD_DOMAINS = {
    "courtlistener.com",
    "opencorporates.com",
    "companieshouse.gov.uk",
    "asic.gov.au",
    "austlii.edu.au",
}
NEWS_DOMAINS = {
    "abc.net.au",
    "smh.com.au",
    "theage.com.au",
    "news.com.au",
    "theguardian.com",
    "bbc.co.uk",
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "washingtonpost.com",
    "reuters.com",
    "apnews.com",
}
FORUM_DOMAINS = {
    "news.ycombinator.com",
    "quora.com",
    "producthunt.com",
}

SENSITIVE_TERMS: dict[str, tuple[str, str]] = {
    "address": ("home address", "high"),
    "phone": ("phone number", "high"),
    "date of birth": ("date of birth", "high"),
    "dob": ("date of birth", "medium"),
    "relatives": ("relatives", "medium"),
    "criminal": ("criminal record", "critical"),
    "court": ("court record", "high"),
    "lawsuit": ("legal record", "high"),
    "bankrupt": ("financial record", "high"),
    "salary": ("salary", "medium"),
    "employer": ("employer", "medium"),
    "voter": ("voter record", "medium"),
    "breach": ("breach mention", "high"),
    "leaked": ("leak mention", "high"),
    "password": ("password mention", "critical"),
}


def _matches_domain(host: str, domains: Iterable[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def classify_domain(host: str, catalog: BrokerCatalog) -> tuple[str, str | None]:
    broker = catalog.find_by_domain(host)
    if broker:
        category = "search_engine" if broker.is_search_engine else "data_broker"
        if broker.category in {"people_search", "directory", "advertising", "credit_bureau", "data_broker"}:
            category = "data_broker"
        return category, broker.id
    if _matches_domain(host, SOCIAL_DOMAINS):
        return "social", None
    if _matches_domain(host, CODE_DOMAINS):
        return "code", None
    if _matches_domain(host, PROFESSIONAL_DOMAINS):
        return "professional", None
    if _matches_domain(host, PUBLIC_RECORD_DOMAINS) or host.endswith(".gov") or host.endswith(".gov.au") or host.endswith(".gov.uk"):
        return "public_record", None
    if _matches_domain(host, NEWS_DOMAINS):
        return "news", None
    if _matches_domain(host, FORUM_DOMAINS):
        return "forum", None
    if host.endswith("wikipedia.org"):
        return "other", None
    return "other", None


def _sensitive_hits(text: str) -> list[tuple[str, str]]:
    lowered = normalize_text(text)
    found: list[tuple[str, str]] = []
    for term, (label, severity) in SENSITIVE_TERMS.items():
        if term in lowered:
            found.append((label, severity))
    return found


def assess_search_risk(
    category: str,
    query: SearchQuery,
    title: str,
    snippet: str,
    url: str,
    broker_id: str | None,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    severity = "low"
    if category == "data_broker":
        severity = "high"
        reasons.append("A data-broker or people-search domain is publishing a matching record")
    elif category == "public_record":
        severity = "medium"
        reasons.append("A public-record source mentions the identifier")
    elif category == "social":
        severity = "low"
        reasons.append("A public social profile matches")
    elif category == "code":
        severity = "low"
        reasons.append("A public developer profile or repository matches")
    elif category == "professional":
        severity = "low"
        reasons.append("A professional profile matches")
    elif category == "news":
        severity = "medium"
        reasons.append("A news or media page matches")
    elif category == "forum":
        severity = "low"
        reasons.append("A public forum post matches")

    for kind in {anchor.kind for anchor in query.anchors}:
        if kind == "address":
            severity = max_severity([severity, "high"])
            reasons.append("The query matched an address")
        elif kind == "phone":
            severity = max_severity([severity, "high"])
            reasons.append("The query matched a phone number")
        elif kind == "email":
            severity = max_severity([severity, "medium"])
            reasons.append("The query matched an email address")

    for label, term_severity in _sensitive_hits(f"{title} {snippet} {url}"):
        severity = max_severity([severity, term_severity])
        reasons.append(f"Page appears to mention {label}")

    if broker_id:
        reasons.append(f"Matched removal directory entry: {broker_id}")
    if query.purpose == "broker_probe":
        severity = max_severity([severity, "high"])
        reasons.append("Matched a broker-targeted probe")
    if query.purpose == "name_only":
        reasons.append("Broad name-only match — verify this is you before acting")
    if query.purpose == "name_country":
        reasons.append("Name and country match — weak location corroboration")
    if query.purpose == "platform_probe":
        reasons.append("Platform-specific name match — verify the profile details")
    if query.purpose in {"email_handle", "username"} and query.identifier_type == "username":
        reasons.append("Username/handle match — handles are often reused by other people")
    if category == "data_broker" and any(
        anchor.kind in {"phone", "address", "email"} for anchor in query.anchors
    ):
        severity = max_severity([severity, "critical"]) if any(
            anchor.kind in {"phone", "address"} for anchor in query.anchors
        ) else severity
        reasons.append("A broker page matches a direct contact identifier")

    # A plain name/username match on a social site is weak evidence, even
    # though useful as a lead. Keep it out of "high" without corroboration.
    if category in {"social", "code", "professional"} and all(
        anchor.kind in {"name", "username", "location"} for anchor in query.anchors
    ):
        severity = "low"
    return severity, _dedupe(reasons)


def analyze_hit(
    query: SearchQuery,
    hit: SearchHit,
    profile: Profile,
    catalog: BrokerCatalog,
    excluded_domains: Iterable[str] = (),
) -> Finding | None:
    match = match_query(query, hit.title, hit.snippet, hit.url)
    if not match:
        return None
    host = domain_of(hit.url)
    if not host:
        return None
    for excluded in excluded_domains:
        if host == excluded or host.endswith("." + excluded):
            return None
    category, broker_id = classify_domain(host, catalog)
    severity, reasons = assess_search_risk(
        category, query, hit.title, hit.snippet, hit.url, broker_id
    )
    primary = query.anchors[0]
    identifier = primary.value
    identifier_type = primary.kind
    for anchor in query.anchors:
        if anchor.kind in {"email", "phone", "address"}:
            identifier = anchor.value
            identifier_type = anchor.kind
            break
    details = {
        "engine": hit.engine,
        "query": query.text,
        "query_label": query.label,
        "purpose": query.purpose,
        "domain": host,
        "broker_id": broker_id,
        "matched_fields": match.where,
        "rank": hit.rank,
        "reasons": reasons,
        "queries": [query.text],
        "category_label": category_label(category),
    }
    return Finding(
        kind="search",
        category=category,
        source=hit.engine,
        title=hit.title or host,
        url=hit.url,
        snippet=hit.snippet,
        identifier=identifier,
        identifier_type=identifier_type,
        severity=severity,
        confidence=match.confidence,
        matched=match.label,
        details=details,
    )


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge results that point to the same URL across queries/engines/checks."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        if not existing:
            merged[finding.fingerprint] = finding
            continue
        _combine(existing, finding)

    # A direct profile check and a web result can describe the same profile.
    # Keep both sets of evidence, but show one row.
    by_url: dict[str, Finding] = {}
    for finding in merged.values():
        if finding.url and finding.kind in {"profile", "search"}:
            key = finding.url
            if key in by_url:
                by_url[key] = _combine(by_url[key], finding, prefer_profile=True)
            else:
                by_url[key] = finding
        else:
            by_url[finding.fingerprint] = finding
    return sorted(
        by_url.values(),
        key=lambda item: (item.risk_rank, -item.confidence, item.title.casefold()),
    )


def _combine(existing: Finding, finding: Finding, prefer_profile: bool = False) -> Finding:
    if prefer_profile and finding.kind == "profile" and existing.kind != "profile":
        existing, finding = finding, existing
    if severity_rank(finding.severity) < severity_rank(existing.severity):
        existing.severity = finding.severity
    existing.confidence = max(existing.confidence, finding.confidence)
    if len(finding.snippet) > len(existing.snippet):
        existing.snippet = finding.snippet
    if finding.title and (not existing.title or len(finding.title) > len(existing.title)):
        existing.title = finding.title
    labels = [value for value in (existing.matched, finding.matched) if value]
    existing.matched = ", ".join(_dedupe(", ".join(labels).split(", ")))
    old_queries = existing.details.get("queries", [])
    new_queries = finding.details.get("queries", [])
    existing.details["queries"] = _dedupe([*old_queries, *new_queries])
    reasons = _dedupe([*existing.details.get("reasons", []), *finding.details.get("reasons", [])])
    if reasons:
        existing.details["reasons"] = reasons
    engines = _dedupe(
        [
            existing.details.get("engine", ""),
            finding.details.get("engine", ""),
            existing.source,
            finding.source,
        ]
    )
    existing.details["engines"] = [value for value in engines if value]
    if not existing.details.get("broker_id") and finding.details.get("broker_id"):
        existing.details["broker_id"] = finding.details["broker_id"]
    for key, value in finding.details.items():
        if key not in existing.details and value:
            existing.details[key] = value
    return existing


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def contains_direct_phone(text: str, phone: str) -> bool:
    digits = phone_digits(phone)
    return bool(digits) and digits[-9:] in phone_digits(text)
