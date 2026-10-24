"""Turn findings and fetched page evidence into a human-readable data inventory.

The goal is to answer one question: *what does this particular source appear to
know about me?* Everything here is derived from the public result snippet or a
page the user explicitly asked the tool to fetch. Inferred fields are marked
with lower confidence and labelled as possible rather than confirmed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import Profile
from .util import domain_of, normalize_text, phone_digits, severity_rank

LABELS = {
    "name": "Name",
    "email": "Email address",
    "phone": "Phone number",
    "address": "Home / postal address",
    "location": "Location",
    "age": "Age",
    "dob": "Date of birth",
    "relatives": "Relatives / associates",
    "employer": "Employer",
    "business": "Business / entity",
    "job_title": "Job title",
    "education": "Education",
    "social": "Social profile links",
    "username": "Username / handle",
    "photo": "Photo / image",
    "financial": "Financial information",
    "government_id": "Government identifier",
    "password": "Password or hash",
    "ip": "IP address",
    "device": "Device / browser data",
    "breach": "Breach record",
    "broker_listing": "Broker listing",
    "other": "Other personal data",
}
SENSITIVE_KINDS = {
    "address",
    "phone",
    "dob",
    "government_id",
    "financial",
    "password",
    "ip",
    "relatives",
    "employer",
}
SOURCE_LABELS = {
    "duckduckgo": "DuckDuckGo",
    "bing": "Bing",
    "brave": "Brave",
    "google_cse": "Google CSE",
    "serpapi": "SerpAPI",
    "serper": "Serper",
    "manual": "Manual URL",
    "manual annotation": "Manual annotation",
    "abn_lookup": "ABN Lookup",
    "github_search": "GitHub search",
    "github_commits": "GitHub commits",
    "xposedornot": "XposedOrNot",
    "hudsonrock": "Hudson Rock",
    "openpgp": "OpenPGP",
    "mastodon": "Mastodon",
}
POINT_ORDER = {
    "name": 0,
    "email": 1,
    "phone": 2,
    "address": 3,
    "location": 4,
    "employer": 5,
    "business": 6,
    "job_title": 7,
    "dob": 7,
    "relatives": 8,
    "government_id": 9,
    "username": 10,
    "password": 11,
    "financial": 12,
    "ip": 13,
    "device": 14,
    "social": 15,
    "photo": 16,
    "breach": 17,
    "other": 18,
}
BREACH_CLASS_MAP = {
    "email": "email",
    "email addresses": "email",
    "phone": "phone",
    "phone numbers": "phone",
    "address": "address",
    "physical addresses": "address",
    "home addresses": "address",
    "dates of birth": "dob",
    "date of birth": "dob",
    "names": "name",
    "usernames": "username",
    "passwords": "password",
    "password hints": "password",
    "ip addresses": "ip",
    "credit cards": "financial",
    "bank account numbers": "financial",
    "government issued ids": "government_id",
    "social security numbers": "government_id",
    "photos": "photo",
    "employers": "employer",
    "job titles": "job_title",
    "education": "education",
    "relatives": "relatives",
    "device information": "device",
}


@dataclass(slots=True)
class DataPoint:
    kind: str
    label: str
    value: str = ""
    evidence: str = ""
    confidence: float = 0.6
    source: str = ""
    observed: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "value": self.value,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "source": self.source,
            "observed": self.observed,
        }


def _point(
    kind: str,
    value: str = "",
    *,
    evidence: str = "",
    confidence: float = 0.6,
    source: str = "",
    observed: bool = True,
) -> DataPoint:
    return DataPoint(
        kind=kind,
        label=LABELS.get(kind, kind.replace("_", " ").title()),
        value=value,
        evidence=evidence,
        confidence=max(0.0, min(1.0, confidence)),
        source=source,
        observed=observed,
    )


def _point_key(point: DataPoint) -> tuple[str, str]:
    if point.kind == "phone":
        digits = phone_digits(point.value)
        if len(digits) >= 7:
            return ("phone", digits[-9:])
    if point.kind == "email":
        return ("email", normalize_text(point.value))
    if point.kind == "government_id":
        digits = re.sub(r"\D", "", point.value)
        if digits:
            return ("government_id", digits)
    return (point.kind, normalize_text(point.value))


def _dedupe(points: Iterable[DataPoint]) -> list[DataPoint]:
    merged: dict[tuple[str, str], DataPoint] = {}
    for point in points:
        key = _point_key(point)
        existing = merged.get(key)
        if not existing:
            merged[key] = point
            continue
        if point.confidence > existing.confidence:
            existing.confidence = point.confidence
        if point.evidence and not existing.evidence:
            existing.evidence = point.evidence
        existing.observed = existing.observed or point.observed
        if point.source and not existing.source:
            existing.source = point.source
    return sorted(
        merged.values(),
        key=lambda item: (
            0 if item.kind in SENSITIVE_KINDS else 1,
            item.kind,
            item.value.casefold(),
        ),
    )


def _snippet(finding: dict[str, Any]) -> str:
    return " \u00b7 ".join(
        part for part in [finding.get("title") or "", finding.get("snippet") or ""] if part
    )


def _extract_employment(text: str, evidence: str, source: str) -> list[DataPoint]:
    points = []
    # e.g. "ICT Business Support Officer at VenuesWest"
    match = re.search(
        r"([A-Z][A-Za-z0-9&/'\- ]{2,70}?)\s+at\s+([A-Z][A-Za-z0-9&/'\- ]{2,60})(?=[.,;|()]|$)",
        text,
    )
    if match:
        possible_title = re.sub(
            r"^(?:possible match for\s+(?:an?\s+)?|job title\s*[:\-]\s*)",
            "",
            match.group(1).strip(" -|,."),
            flags=re.I,
        )
        possible_employer = re.split(
            r"\s+(?:in|at|since|from)\s+", match.group(2).strip(" -|,."), maxsplit=1, flags=re.I
        )[0]
        title_lower = possible_title.casefold()
        if 3 <= len(possible_title) <= 70 and not any(
            marker in title_lower
            for marker in ("works", "worked", "working", "lives", "lived", "based", "met", "joined")
        ):
            points.append(
                _point(
                    "job_title",
                    possible_title,
                    evidence=evidence,
                    confidence=0.62,
                    source=source,
                    observed=False,
                )
            )
        if 2 <= len(possible_employer) <= 60:
            points.append(
                _point(
                    "employer",
                    possible_employer,
                    evidence=evidence,
                    confidence=0.62,
                    source=source,
                    observed=False,
                )
            )
    return points


def _extract_text(text: str, evidence: str, source: str) -> list[DataPoint]:
    points: list[DataPoint] = []
    lowered = text.casefold()
    for marker, kind, label in [
        ("phone number", "phone", "Phone number referenced"),
        ("phone numbers", "phone", "Phone number referenced"),
        ("home address", "address", "Address referenced"),
        ("current address", "address", "Address referenced"),
        ("previous address", "address", "Address referenced"),
        ("date of birth", "dob", "Date of birth referenced"),
        ("relatives", "relatives", "Relatives / associates referenced"),
        ("possible relatives", "relatives", "Relatives / associates referenced"),
        ("job title", "job_title", "Job title referenced"),
        ("employer", "employer", "Employer referenced"),
        ("credit card", "financial", "Financial information referenced"),
        ("bank account", "financial", "Financial information referenced"),
        ("password", "password", "Password data referenced"),
        ("ip address", "ip", "IP address referenced"),
    ]:
        if marker in lowered:
            points.append(
                _point(
                    kind,
                    label,
                    evidence=evidence,
                    confidence=0.45,
                    source=source,
                    observed=False,
                )
            )
    age = re.search(r"\b(?:age|aged)\s*[:\s]\s*(\d{1,3})\b", text, re.I)
    if age:
        points.append(
            _point("age", age.group(1), evidence=evidence, confidence=0.7, source=source)
        )
    dob = re.search(
        r"\b(?:dob|date of birth|born)\s*[:\-]?\s*((?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2})",
        text,
        re.I,
    )
    if dob:
        points.append(
            _point("dob", dob.group(1), evidence=evidence, confidence=0.8, source=source)
        )
    return points


def _point_for_breach_class(name: str, breach: str, evidence: str, source: str) -> DataPoint:
    kind = BREACH_CLASS_MAP.get(name.casefold().strip(), "other")
    return _point(
        kind,
        f"Exposed in {breach}" if breach else "Exposed in breach",
        evidence=evidence,
        confidence=0.9,
        source=source,
    )


def points_from_text(text: str, profile: Profile, *, source: str = "", evidence: str = "") -> list[DataPoint]:
    """Extract identifier and sensitive-field evidence from visible page text."""
    points: list[DataPoint] = []
    text = text or ""
    evidence = evidence or text[:500]
    text_cf = text.casefold()
    if profile.display_name and profile.display_name.casefold() in text_cf:
        points.append(
            _point("name", profile.display_name, evidence=evidence, confidence=0.85, source=source)
        )
    for email in profile.emails:
        if email.casefold() in text_cf:
            points.append(_point("email", email, evidence=evidence, confidence=0.9, source=source))
    for phone in profile.phones:
        digits = phone_digits(phone)
        if len(digits) >= 7 and digits[-9:] in phone_digits(text):
            points.append(_point("phone", phone, evidence=evidence, confidence=0.85, source=source))
    for address in profile.addresses:
        if address.casefold() in text_cf:
            points.append(
                _point("address", address, evidence=evidence, confidence=0.8, source=source)
            )
    points.extend(_extract_employment(text, evidence, source))
    points.extend(_extract_text(text, evidence, source))
    # Explicit contact links are stronger than prose inferences.
    for email in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text):
        if email.casefold() in {item.casefold() for item in profile.emails}:
            points.append(_point("email", email, evidence=evidence, confidence=0.95, source=source))
    return _dedupe(points)


def _known_value(kind: str, profile: Profile) -> str:
    if kind == "name":
        return profile.display_name
    if kind == "email" and profile.emails:
        return profile.emails[0]
    if kind == "phone" and profile.phones:
        return profile.phones[0]
    if kind == "address" and profile.addresses:
        return profile.addresses[0]
    if kind == "username" and profile.usernames:
        return profile.usernames[0]
    if kind == "location" and profile.locations:
        return profile.locations[0]
    return ""


def infer_data_points(
    finding: dict[str, Any],
    profile: Profile,
    *,
    source_name: str | None = None,
) -> list[DataPoint]:
    """Combine explicit check metadata, snippets, and fetched page evidence."""
    details = finding.get("details") or {}
    source = source_name or str(finding.get("source") or "")
    evidence = _snippet(finding)
    points: list[DataPoint] = []
    explicit = details.get("data_points")
    if isinstance(explicit, list):
        for item in explicit:
            if not isinstance(item, dict) or not item.get("kind"):
                continue
            points.append(
                _point(
                    str(item["kind"]),
                    str(item.get("value") or ""),
                    evidence=str(item.get("evidence") or evidence),
                    confidence=float(item.get("confidence") or 0.8),
                    source=str(item.get("source") or source),
                    observed=bool(item.get("observed", True)),
                )
            )

    category = str(finding.get("category") or "")
    if category == "breach":
        breaches = details.get("breaches")
        class_breaches: dict[str, list[str]] = {}
        class_evidence: dict[str, list[str]] = {}
        if isinstance(breaches, list):
            for breach in breaches:
                if not isinstance(breach, dict):
                    continue
                name = str(breach.get("breach") or breach.get("name") or "Breach")
                date = str(breach.get("date") or breach.get("breach_date") or "")
                data = breach.get("data") or []
                evidence_line = f"{name}{' (' + date + ')' if date else ''}: {', '.join(map(str, data))}"
                points.append(
                    _point(
                        "breach",
                        f"{name}{' (' + date + ')' if date else ''}",
                        evidence=evidence_line,
                        confidence=0.95,
                        source=source,
                    )
                )
                for data_class in data:
                    kind = BREACH_CLASS_MAP.get(str(data_class).casefold().strip(), "other")
                    class_breaches.setdefault(kind, []).append(name)
                    class_evidence.setdefault(kind, []).append(evidence_line)
        else:
            data_classes = details.get("data_classes") or []
            breach_name = str(details.get("breach") or details.get("title") or "Breach")
            evidence_line = f"{breach_name}: {', '.join(map(str, data_classes))}"
            points.append(
                _point(
                    "breach",
                    breach_name,
                    evidence=evidence_line,
                    confidence=0.95,
                    source=source,
                )
            )
            for data_class in data_classes:
                kind = BREACH_CLASS_MAP.get(str(data_class).casefold().strip(), "other")
                class_breaches.setdefault(kind, []).append(breach_name)
                class_evidence.setdefault(kind, []).append(evidence_line)
        for kind, breach_names in class_breaches.items():
            evidence_line = "; ".join(dict.fromkeys(class_evidence.get(kind, [])))
            value = _known_value(kind, profile)
            if not value:
                if kind in {"password", "other"}:
                    unique_breaches = len(set(breach_names))
                    value = f"Exposed in {unique_breaches} breach{'es' if unique_breaches != 1 else ''}"
                else:
                    value = "Exposed in " + ", ".join(list(dict.fromkeys(breach_names))[:3])
            points.append(
                _point(
                    kind,
                    value,
                    evidence=evidence_line,
                    confidence=0.9,
                    source=source,
                )
            )

    exposed_fields = details.get("exposed_fields")
    if isinstance(exposed_fields, dict):
        for field_name, value in exposed_fields.items():
            kind = {
                "name": "name",
                "email": "email",
                "phone": "phone",
                "address": "address",
                "organisation": "employer",
            }.get(str(field_name).casefold(), "other")
            points.append(
                _point(
                    kind,
                    str(value),
                    evidence=_snippet(finding),
                    confidence=0.9,
                    source=source,
                )
            )

    # Profile-check metadata.
    for key, kind in [
        ("public_name", "name"),
        ("display_name", "name"),
        ("public_email", "email"),
        ("email", "email"),
        ("company", "employer"),
        ("location", "location"),
        ("blog", "social"),
        ("website", "social"),
        ("twitter_username", "social"),
        ("handle", "username"),
    ]:
        value = details.get(key)
        if value and isinstance(value, (str, int)):
            points.append(
                _point(kind, str(value), evidence=evidence, confidence=0.85, source=source)
            )

    # A configured identifier appearing in the snippet is a direct observation.
    text = _snippet(finding)
    text_cf = text.casefold()
    if profile.display_name and profile.display_name.casefold() in text_cf:
        points.append(
            _point("name", profile.display_name, evidence=evidence, confidence=0.8, source=source)
        )
    for email in profile.emails:
        if email.casefold() in text_cf:
            points.append(_point("email", email, evidence=evidence, confidence=0.9, source=source))
    for phone in profile.phones:
        digits = phone_digits(phone)
        if len(digits) >= 7 and digits[-9:] in phone_digits(text):
            points.append(_point("phone", phone, evidence=evidence, confidence=0.8, source=source))
    for address in profile.addresses:
        if address.casefold() in text_cf:
            points.append(
                _point("address", address, evidence=evidence, confidence=0.75, source=source)
            )

    points.extend(_extract_employment(text, evidence, source))
    points.extend(_extract_text(text, evidence, source))

    observed_kinds = {point.kind for point in points if point.observed}
    points = [
        point for point in points
        if point.observed or point.kind not in observed_kinds
    ]
    return _dedupe(points)[:18]


def inventory(findings: Iterable[dict[str, Any]], profile: Profile) -> dict[str, Any]:
    """Aggregate data-point types and per-site summaries for the report."""
    all_points: dict[tuple[str, str], DataPoint] = {}
    point_sources: dict[tuple[str, str], set[str]] = {}
    point_findings: dict[tuple[str, str], set[int]] = {}
    sites: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.get("status") in {"false_positive", "removed"}:
            continue
        points = infer_data_points(finding, profile)
        for point in points:
            key = _point_key(point)
            existing = all_points.get(key)
            if not existing or point.confidence > existing.confidence:
                all_points[key] = point
            source = point.source or str(finding.get("source") or "")
            if source:
                point_sources.setdefault(key, set()).add(
                    SOURCE_LABELS.get(source.casefold(), source)
                )
            if finding.get("id"):
                point_findings.setdefault(key, set()).add(int(finding["id"]))
        domain = str((finding.get("details") or {}).get("domain") or domain_of(finding.get("url", "")))
        if not domain:
            domain = str(finding.get("source") or "Unknown")
        site = sites.setdefault(
            domain,
            {
                "domain": domain,
                "title": domain,
                "findings": [],
                "points": [],
                "severity": finding.get("severity") or "low",
                "categories": [],
                "statuses": [],
                "urls": [],
                "broker_id": "",
                "source": finding.get("source") or "",
            },
        )
        site["findings"].append(finding)
        site["points"].extend(points)
        if severity_rank(str(finding.get("severity") or "low")) < severity_rank(site["severity"]):
            site["severity"] = finding.get("severity") or "low"
        if finding.get("category") not in site["categories"]:
            site["categories"].append(finding.get("category"))
        if finding.get("status") not in site["statuses"]:
            site["statuses"].append(finding.get("status"))
        if finding.get("url"):
            site["urls"].append(finding["url"])
        broker_id = (finding.get("details") or {}).get("broker_id")
        if broker_id:
            site["broker_id"] = str(broker_id)
    for site in sites.values():
        site["points"] = [point.as_dict() for point in _dedupe(site["points"])]
        site["finding_count"] = len(site["findings"])
        site["kind_count"] = len({point["kind"] for point in site["points"]})
        site["data_labels"] = [point["label"] for point in site["points"]]
        site["summary"] = ", ".join(site["data_labels"][:5])
        site["findings"] = [
            {"id": item.get("id"), "title": item.get("title"), "url": item.get("url")}
            for item in site["findings"]
        ]
        site["urls"] = list(dict.fromkeys(site["urls"]))
    counts: dict[str, int] = {}
    for point in all_points.values():
        counts[point.kind] = counts.get(point.kind, 0) + 1
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    site_rows = sorted(
        sites.values(),
        key=lambda item: (
            severity_order.get(str(item["severity"]), 9),
            -item["kind_count"],
            item["domain"],
        ),
    )
    point_rows = []
    for key, point in all_points.items():
        item = point.as_dict()
        item["sources"] = sorted(point_sources.get(key, set()))
        item["finding_ids"] = sorted(point_findings.get(key, set()))
        point_rows.append(item)
    point_rows.sort(
        key=lambda item: (
            POINT_ORDER.get(item["kind"], 99),
            item["value"].casefold(),
        )
    )
    return {
        "points": point_rows,
        "counts": counts,
        "sites": site_rows,
    }
