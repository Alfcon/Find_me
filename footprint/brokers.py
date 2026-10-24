"""Curated removal directory and broker lookups."""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import quote_plus

from .config import Profile, load_broker_catalog
from .util import domain_matches


@dataclass(slots=True)
class Broker:
    id: str
    name: str
    regions: list[str]
    category: str = "people_search"
    domains: list[str] = field(default_factory=list)
    optout_url: str = ""
    search_url: str = ""
    method: str = "web form"
    difficulty: str = "medium"
    minutes: int = 10
    requirements: str = ""
    notes: str = ""
    last_verified: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "Broker":
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name") or raw["id"]),
            regions=[str(value).upper() for value in raw.get("regions", ["GLOBAL"])],
            category=str(raw.get("category") or "people_search"),
            domains=[str(value).casefold().strip(".") for value in raw.get("domains", [])],
            optout_url=str(raw.get("optout_url") or ""),
            search_url=str(raw.get("search_url") or ""),
            method=str(raw.get("method") or "web form"),
            difficulty=str(raw.get("difficulty") or "medium"),
            minutes=int(raw.get("minutes") or 10),
            requirements=str(raw.get("requirements") or ""),
            notes=str(raw.get("notes") or ""),
            last_verified=str(raw.get("last_verified") or ""),
            raw=raw,
        )

    @property
    def is_search_engine(self) -> bool:
        return self.category == "search_engine"

    @property
    def region_label(self) -> str:
        return ", ".join(self.regions)


class BrokerCatalog:
    def __init__(self, entries: Iterable[dict[str, Any]] | None = None):
        entries = list(entries) if entries is not None else load_broker_catalog()
        self.brokers = [Broker.from_mapping(entry) for entry in entries if entry.get("id")]
        self.by_id = {broker.id: broker for broker in self.brokers}

    def filter_regions(self, regions: Iterable[str]) -> list[Broker]:
        wanted = {value.upper() for value in regions}
        wanted.add("GLOBAL")
        return [broker for broker in self.brokers if wanted.intersection(broker.regions)]

    def people_search(self, regions: Iterable[str]) -> list[Broker]:
        return [broker for broker in self.filter_regions(regions) if not broker.is_search_engine]

    def removal_channels(self) -> list[Broker]:
        return [broker for broker in self.brokers if broker.is_search_engine]

    def find_by_domain(self, host: str) -> Broker | None:
        for broker in self.brokers:
            for domain in broker.domains:
                if domain_matches(host, domain):
                    return broker
        return None

    def get(self, broker_id: str) -> Broker | None:
        return self.by_id.get(broker_id)

    def search_url_for(self, broker: Broker, profile: Profile) -> str:
        """Fill a broker's optional search template with name/location fields."""
        if not broker.search_url:
            return ""
        first, _, last = profile.display_name.partition(" ")
        values = {
            "name": quote_plus(profile.display_name),
            "first": quote_plus(first),
            "last": quote_plus(last),
            "city": quote_plus(profile.city),
            "state": "",
            "country": quote_plus(profile.country),
            "email": quote_plus(profile.emails[0] if profile.emails else ""),
            "phone": quote_plus(profile.phones[0] if profile.phones else ""),
        }
        try:
            return broker.search_url.format(**values)
        except (KeyError, ValueError):
            return broker.search_url


def load_catalog() -> BrokerCatalog:
    return BrokerCatalog(load_broker_catalog())


def category_label(category: str) -> str:
    return {
        "data_broker": "Data broker",
        "people_search": "People search",
        "credit_bureau": "Credit bureau",
        "directory": "Public directory",
        "advertising": "Advertising data",
        "search_engine": "Search engine",
        "social": "Social / profile",
        "code": "Code / developer",
        "professional": "Professional",
        "public_record": "Public record",
        "news": "News / media",
        "forum": "Forum / community",
        "breach": "Data breach",
        "domain": "Domain / WHOIS",
        "other": "Other public web",
    }.get(category, category.replace("_", " ").title())


def removal_link_html(url: str, label: str = "Open removal page") -> str:
    return f'<a href="{html.escape(url, quote=True)}" rel="noopener noreferrer nofollow">{html.escape(label)}</a>'


def search_links(profile: Profile, broker: Broker, catalog: BrokerCatalog) -> dict[str, str]:
    return {
        "search": catalog.search_url_for(broker, profile),
        "optout": broker.optout_url,
    }


