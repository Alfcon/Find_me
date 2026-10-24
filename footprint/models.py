"""Domain models used across discovery, storage, and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .util import canonical_url, fingerprint as make_hash, iso_now, severity_rank


@dataclass(slots=True)
class Finding:
    kind: str
    category: str
    source: str
    title: str
    url: str = ""
    snippet: str = ""
    identifier: str = ""
    identifier_type: str = ""
    severity: str = "medium"
    confidence: float = 0.7
    matched: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    first_seen: str = field(default_factory=iso_now)
    last_seen: str = field(default_factory=iso_now)

    def __post_init__(self) -> None:
        self.url = canonical_url(self.url) if self.url else ""
        self.severity = (self.severity or "medium").casefold()
        if self.severity not in {"critical", "high", "medium", "low", "info"}:
            self.severity = "medium"
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.fingerprint:
            anchor = self.url or f"{self.identifier}:{self.title}"
            self.fingerprint = make_hash(self.kind, anchor)

    @property
    def risk_rank(self) -> int:
        return severity_rank(self.severity)

    def as_row(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "category": self.category,
            "source": self.source,
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "identifier": self.identifier,
            "identifier_type": self.identifier_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "matched": self.matched,
            "details": self.details,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class QueryAnchor:
    kind: str
    value: str


@dataclass(slots=True)
class SearchQuery:
    text: str
    anchors: list[QueryAnchor]
    label: str
    identifier_type: str
    priority: int = 50
    purpose: str = "general"

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "label": self.label,
            "identifier_type": self.identifier_type,
            "anchors": [{"kind": a.kind, "value": a.value} for a in self.anchors],
            "purpose": self.purpose,
        }


@dataclass(slots=True)
class SearchHit:
    engine: str
    title: str
    url: str
    snippet: str = ""
    rank: int = 0
    query: str = ""


@dataclass(slots=True)
class MatchInfo:
    matched: list[str]
    confidence: float
    where: list[str]

    @property
    def label(self) -> str:
        return ", ".join(self.matched)


@dataclass(slots=True)
class CheckEvent:
    kind: str
    message: str
    level: str = "info"


@dataclass
class ScanStats:
    run_id: int | None = None
    queries_planned: int = 0
    queries_run: int = 0
    requests: int = 0
    results_seen: int = 0
    results_matched: int = 0
    new_findings: int = 0
    updated_findings: int = 0
    checks_run: int = 0
    checks_skipped: int = 0
    errors: int = 0
    notes: list[CheckEvent] = field(default_factory=list)
    started_at: str = field(default_factory=iso_now)
    finished_at: str | None = None
    mode: str = "scan"

    def note(self, kind: str, message: str, level: str = "info") -> None:
        self.notes.append(CheckEvent(kind=kind, message=message, level=level))

    def as_dict(self) -> dict[str, Any]:
        return {
            "queries_planned": self.queries_planned,
            "queries_run": self.queries_run,
            "requests": self.requests,
            "results_seen": self.results_seen,
            "results_matched": self.results_matched,
            "new_findings": self.new_findings,
            "updated_findings": self.updated_findings,
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
            "errors": self.errors,
            "notes": [
                {"kind": note.kind, "message": note.message, "level": note.level}
                for note in self.notes
            ],
        }
