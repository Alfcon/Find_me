"""Configuration loading, validation, and first-run setup."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .util import (
    canonical_url,
    domain_of,
    ensure_private_file,
    is_safe_public_url,
    is_valid_email,
    is_valid_username,
    location_city,
    normalize_email,
    normalize_location,
    normalize_phone,
    normalize_space,
    normalize_username,
    write_private_text,
)

DEFAULT_CONFIG_NAME = "profile.yaml"
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "me.com",
    "yahoo.com",
    "yahoo.com.au",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "aol.com",
    "gmx.com",
    "mail.com",
    "fastmail.com",
    "hey.com",
}


class ConfigError(ValueError):
    """Raised when a profile configuration is missing or unusable."""


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return result


@dataclass(slots=True)
class Profile:
    display_name: str = ""
    previous_names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    websites: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    country: str = ""
    notes: str = ""

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "Profile":
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ConfigError("profile must be a mapping")
        display_name = normalize_space(str(raw.get("display_name") or raw.get("name") or ""))
        emails = _dedupe(
            normalize_email(value)
            for value in _as_list(raw.get("emails")) + _as_list(raw.get("email"))
            if normalize_email(value)
        )
        invalid_emails = [email for email in emails if not is_valid_email(email)]
        if invalid_emails:
            raise ConfigError(f"invalid email address: {invalid_emails[0]}")
        phones = _dedupe(normalize_phone(value) for value in _as_list(raw.get("phones")) + _as_list(raw.get("phone")))
        invalid_phones = [phone for phone in phones if not 7 <= len(re.sub(r"\D", "", phone)) <= 15]
        if invalid_phones:
            raise ConfigError(f"invalid phone number: {invalid_phones[0]}")
        usernames = _dedupe(
            normalize_username(value)
            for value in _as_list(raw.get("usernames")) + _as_list(raw.get("username"))
            if normalize_username(value)
        )
        invalid_usernames = [name for name in usernames if not is_valid_username(name)]
        if invalid_usernames:
            raise ConfigError(
                f"invalid username '{invalid_usernames[0]}' (use letters, numbers, dot, dash, underscore)"
            )
        addresses = _dedupe(normalize_location(value) for value in _as_list(raw.get("addresses")))
        locations = _dedupe(normalize_location(value) for value in _as_list(raw.get("locations")))
        websites: list[str] = []
        for value in _as_list(raw.get("websites")):
            value = value.strip()
            if not value:
                continue
            if "://" not in value:
                value = "https://" + value
            url = canonical_url(value)
            if not url or not is_safe_public_url(url):
                raise ConfigError(f"invalid or unsafe website URL: {value}")
            websites.append(url)
        websites = _dedupe(websites)
        domains = _dedupe(
            [domain_of(url) for url in websites]
            + [value.casefold().strip(".") for value in _as_list(raw.get("domains"))]
        )
        if not (display_name or emails or phones or usernames or addresses):
            raise ConfigError(
                "profile needs at least one identifier (a name, email, phone, username, or address)"
            )
        return cls(
            display_name=display_name,
            previous_names=_dedupe(normalize_space(value) for value in _as_list(raw.get("previous_names"))),
            emails=emails,
            phones=phones,
            usernames=usernames,
            addresses=addresses,
            locations=locations,
            websites=websites,
            domains=[domain for domain in domains if domain],
            country=normalize_space(str(raw.get("country") or "")),
            notes=str(raw.get("notes") or "").strip(),
        )

    @property
    def names(self) -> list[str]:
        return _dedupe([self.display_name, *self.previous_names])

    @property
    def city(self) -> str:
        return location_city(self.locations[0]) if self.locations else ""

    @property
    def domain_names(self) -> list[str]:
        return [domain for domain in self.domains if domain not in PUBLIC_EMAIL_DOMAINS]

    @property
    def email_locals(self) -> list[str]:
        """Likely handles derived from the local part of each email address."""
        generic = {
            "admin", "administrator", "contact", "hello", "info", "mail", "me",
            "noreply", "no-reply", "office", "postmaster", "sales", "support",
            "team", "webmaster", "accounts", "billing", "enquiries", "privacy",
        }
        result: list[str] = []
        for email in self.emails:
            local = normalize_email(email).split("@", 1)[0].split("+", 1)[0]
            local = re.sub(r"[^a-z0-9._-]", "", local).strip("._-")
            if len(local) >= 3 and local not in generic:
                result.append(local)
        return _dedupe(result)

    @property
    def derived_usernames(self) -> list[str]:
        """Username-shaped variants of email local parts, for discovery only."""
        result: list[str] = []
        for local in self.email_locals:
            variants = [local]
            if "." in local:
                variants.extend([
                    local.replace(".", ""),
                    local.replace(".", "-"),
                    local.replace(".", "_"),
                ])
            # A trailing number is often a signup suffix, not the handle.
            without_suffix = re.sub(r"\d{2,}$", "", local).strip("._-")
            if len(without_suffix) >= 4 and without_suffix != local:
                variants.append(without_suffix)
            for value in variants:
                value = normalize_username(value)
                if value and is_valid_username(value) and value not in self.usernames:
                    result.append(value)
        return _dedupe(result)[:8]

    @property
    def all_usernames(self) -> list[str]:
        return _dedupe([*self.usernames, *self.derived_usernames])

    def identifiers(self, include_locations: bool = False) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        result.extend(("name", value) for value in self.names)
        result.extend(("email", value) for value in self.emails)
        result.extend(("phone", value) for value in self.phones)
        result.extend(("username", value) for value in self.usernames)
        result.extend(("address", value) for value in self.addresses)
        if include_locations:
            result.extend(("location", value) for value in self.locations)
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "display_name": self.display_name,
            "emails": len(self.emails),
            "phones": len(self.phones),
            "usernames": len(self.usernames),
            "addresses": len(self.addresses),
            "locations": list(self.locations),
            "websites": list(self.websites),
            "country": self.country,
        }


@dataclass(slots=True)
class SearchConfig:
    engines: list[str] = field(default_factory=lambda: ["duckduckgo", "bing"])
    max_queries: int = 24
    results_per_query: int = 8
    delay_seconds: float = 2.0
    region: str = "au-en"
    exclude_domains: list[str] = field(default_factory=list)
    fallback_engine: str = "bing"
    broad_name: bool = True
    platform_probes: bool = True
    platform_probe_count: int = 4
    broker_probes: bool = False
    broker_probe_count: int = 6

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "SearchConfig":
        raw = raw or {}
        engines = [value.casefold().strip() for value in _as_list(raw.get("engines"))]
        known = {"duckduckgo", "bing", "brave", "google_cse", "serpapi", "serper"}
        if not engines:
            engines = ["duckduckgo", "bing"]
        unknown = [engine for engine in engines if engine not in known]
        if unknown:
            raise ConfigError(f"unknown search engine: {unknown[0]} (choose from {', '.join(sorted(known))})")
        max_queries = int(raw.get("max_queries", 24))
        results = int(raw.get("results_per_query", 8))
        delay = float(raw.get("delay_seconds", 2.0))
        if not 1 <= max_queries <= 100:
            raise ConfigError("search.max_queries must be between 1 and 100")
        if not 1 <= results <= 20:
            raise ConfigError("search.results_per_query must be between 1 and 20")
        if not 1.0 <= delay <= 30.0:
            raise ConfigError("search.delay_seconds must be between 1 and 30")
        fallback = str(raw.get("fallback_engine", "bing") or "").casefold().strip()
        if fallback and fallback not in {"bing", "duckduckgo"}:
            raise ConfigError("search.fallback_engine must be bing, duckduckgo, or empty")
        region = str(raw.get("region") or "au-en").strip()
        exclude = _dedupe(value.casefold().strip(".") for value in _as_list(raw.get("exclude_domains")))
        return cls(
            engines=_dedupe(engines),
            max_queries=max_queries,
            results_per_query=results,
            delay_seconds=delay,
            region=region,
            exclude_domains=exclude,
            fallback_engine=fallback,
            broad_name=bool(raw.get("broad_name", True)),
            platform_probes=bool(raw.get("platform_probes", True)),
            platform_probe_count=max(0, min(12, int(raw.get("platform_probe_count", 4)))),
            broker_probes=bool(raw.get("broker_probes", False)),
            broker_probe_count=max(0, min(20, int(raw.get("broker_probe_count", 6)))),
        )


@dataclass(slots=True)
class ChecksConfig:
    gravatar: bool = True
    github: bool = True
    gitlab: bool = True
    reddit: bool = True
    keybase: bool = True
    bluesky: bool = True
    npm: bool = True
    rdap: bool = True
    breaches: bool = True
    xposedornot: bool = True
    github_commits: bool = True
    github_search: bool = True
    openpgp: bool = True
    abn: bool = True
    hudsonrock: bool = True
    mastodon: bool = True

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "ChecksConfig":
        raw = raw or {}
        defaults = cls()
        for key in defaults.__dataclass_fields__:
            value = raw.get(key, getattr(defaults, key))
            setattr(defaults, key, bool(value))
        return defaults


@dataclass(slots=True)
class BrokersConfig:
    regions: list[str] = field(default_factory=lambda: ["AU", "GLOBAL"])

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "BrokersConfig":
        raw = raw or {}
        regions = [value.upper() for value in _as_list(raw.get("regions"))]
        if not regions:
            regions = ["AU", "GLOBAL"]
        return cls(regions=_dedupe(regions))


@dataclass(slots=True)
class ReportConfig:
    output: str = "reports/footprint-report.html"
    redact: bool = False
    title: str = "My Digital Footprint Audit"

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "ReportConfig":
        raw = raw or {}
        return cls(
            output=str(raw.get("output") or "reports/footprint-report.html"),
            redact=bool(raw.get("redact", False)),
            title=normalize_space(str(raw.get("title") or "My Digital Footprint Audit")),
        )


@dataclass(slots=True)
class StorageConfig:
    database: str = ".footprint/footprint.db"
    cache: str = ".footprint/cache"

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "StorageConfig":
        raw = raw or {}
        return cls(
            database=str(raw.get("database") or ".footprint/footprint.db"),
            cache=str(raw.get("cache") or ".footprint/cache"),
        )


@dataclass(slots=True)
class AppConfig:
    path: Path
    base_dir: Path
    profile: Profile
    search: SearchConfig = field(default_factory=SearchConfig)
    checks: ChecksConfig = field(default_factory=ChecksConfig)
    brokers: BrokersConfig = field(default_factory=BrokersConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return _resolve(self.base_dir, self.storage.database)

    @property
    def cache_dir(self) -> Path:
        return _resolve(self.base_dir, self.storage.cache)

    @property
    def report_path(self) -> Path:
        path = _resolve(self.base_dir, self.report.output)
        name = self.profile.display_name.strip()
        if not name:
            return path
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-._")
        if not safe_name:
            return path
        if path.stem.casefold().startswith(safe_name.casefold() + "-"):
            return path
        if path.stem.casefold() in {"footprint-report", "report"}:
            filename = f"{safe_name}-footprint-report{path.suffix or '.html'}"
        else:
            filename = f"{safe_name}-{path.name}"
        return path.with_name(filename)

    @property
    def api_keys(self) -> dict[str, str]:
        return {
            "hibp": os.environ.get("HIBP_API_KEY", "").strip(),
            "github": os.environ.get("GITHUB_TOKEN", "").strip(),
            "brave": (os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("BRAVE_API_KEY") or "").strip(),
            "google_cse_key": (os.environ.get("GOOGLE_CSE_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip(),
            "google_cse_id": (os.environ.get("GOOGLE_CSE_ID") or "").strip(),
            "serpapi": os.environ.get("SERPAPI_API_KEY", "").strip(),
            "serper": os.environ.get("SERPER_API_KEY", "").strip(),
        }

    def with_paths(self, db_path: str | Path | None = None, report_path: str | Path | None = None) -> "AppConfig":
        if db_path:
            self.storage.database = str(Path(db_path).expanduser().resolve())
        if report_path:
            self.report.output = str(Path(report_path).expanduser().resolve())
        return self

    @property
    def country(self) -> str:
        return self.profile.country or "Australia"

    def public_summary(self, redact: bool = False) -> dict[str, Any]:
        from .util import display_identifier

        return {
            "name": display_identifier(self.profile.display_name, "name", redact)
            if self.profile.display_name
            else "Unnamed profile",
            "identifiers": [
                {
                    "kind": kind,
                    "value": display_identifier(value, kind, redact),
                    "count": 1,
                }
                for kind, value in self.profile.identifiers()
            ],
            "locations": [
                display_identifier(value, "location", redact)
                for value in self.profile.locations
            ],
            "country": self.country,
        }


def _resolve(base: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def default_config_path() -> Path:
    return Path.cwd() / DEFAULT_CONFIG_NAME


def load_config(path: str | Path | None = None, db_path: str | Path | None = None) -> AppConfig:
    config_path = Path(path).expanduser() if path else default_config_path()
    if not config_path.is_absolute():
        config_path = (Path.cwd() / config_path).resolve()
    if not config_path.exists():
        raise ConfigError(
            f"no profile config found at {config_path}\n"
            "Run `python -m footprint init` to create one, or copy config.example.yaml."
        )
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {config_path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("the profile config root must be a mapping")
    version = raw.get("version", 1)
    if int(version) != 1:
        raise ConfigError(f"unsupported config version: {version}")
    base_dir = config_path.parent
    config = AppConfig(
        path=config_path,
        base_dir=base_dir,
        profile=Profile.from_mapping(raw.get("profile")),
        search=SearchConfig.from_mapping(raw.get("search")),
        checks=ChecksConfig.from_mapping(raw.get("checks")),
        brokers=BrokersConfig.from_mapping(raw.get("brokers")),
        report=ReportConfig.from_mapping(raw.get("report")),
        storage=StorageConfig.from_mapping(raw.get("storage")),
        raw=raw,
    )
    if db_path:
        config.storage.database = str(Path(db_path).expanduser().resolve())
    return config


def config_permission_warning(path: Path) -> str | None:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return None
    if mode & 0o077:
        return (
            f"{path} is readable by other users (mode {mode:o}). "
            "Run `chmod 600` on it because it contains personal identifiers."
        )
    return None


def build_config(
    *,
    name: str = "",
    emails: Iterable[str] = (),
    phones: Iterable[str] = (),
    usernames: Iterable[str] = (),
    addresses: Iterable[str] = (),
    locations: Iterable[str] = (),
    websites: Iterable[str] = (),
    country: str = "Australia",
    email: str | None = None,
    phone: str | None = None,
    username: str | None = None,
    address: str | None = None,
    location: str | None = None,
    website: str | None = None,
) -> dict[str, Any]:
    emails = list(emails) + ([email] if email else [])
    phones = list(phones) + ([phone] if phone else [])
    usernames = list(usernames) + ([username] if username else [])
    addresses = list(addresses) + ([address] if address else [])
    locations = list(locations) + ([location] if location else [])
    websites = list(websites) + ([website] if website else [])
    country_key = (country or "").casefold()
    if country_key in {"united states", "usa", "us"}:
        regions = ["US", "GLOBAL"]
        search_region = "us-en"
    elif country_key in {"united kingdom", "uk", "gb", "great britain", "england", "scotland", "wales"}:
        regions = ["UK", "GLOBAL"]
        search_region = "uk-en"
    elif country_key in {"australia", "au"}:
        regions = ["AU", "GLOBAL"]
        search_region = "au-en"
    elif country_key in {"canada", "ca"}:
        regions = ["GLOBAL"]
        search_region = "ca-en"
    elif country_key in {"new zealand", "nz"}:
        regions = ["GLOBAL"]
        search_region = "nz-en"
    elif country_key in {"ireland", "ie"}:
        regions = ["GLOBAL"]
        search_region = "ie-en"
    else:
        regions = ["GLOBAL"]
        search_region = "us-en"
    return {
        "version": 1,
        "profile": {
            "display_name": name,
            "previous_names": [],
            "emails": _dedupe(normalize_email(value) for value in emails if normalize_email(value)),
            "phones": _dedupe(normalize_phone(value) for value in phones if normalize_phone(value)),
            "usernames": _dedupe(normalize_username(value) for value in usernames if normalize_username(value)),
            "addresses": _dedupe(normalize_location(value) for value in addresses if normalize_location(value)),
            "locations": _dedupe(normalize_location(value) for value in locations if normalize_location(value)),
            "websites": list(websites),
            "domains": [],
            "country": country,
        },
        "search": {
            "engines": ["duckduckgo", "bing"],
            "fallback_engine": "bing",
            "max_queries": 24,
            "results_per_query": 8,
            "delay_seconds": 2.0,
            "region": search_region,
            "exclude_domains": [],
            "broad_name": True,
            "platform_probes": True,
            "platform_probe_count": 4,
            "broker_probes": False,
        },
        "checks": {
            "gravatar": True,
            "github": True,
            "gitlab": True,
            "reddit": True,
            "keybase": True,
            "bluesky": True,
            "npm": True,
            "rdap": True,
            "breaches": True,
            "xposedornot": True,
            "github_commits": True,
            "github_search": True,
            "openpgp": True,
            "abn": True,
            "hudsonrock": True,
            "mastodon": True,
        },
        "brokers": {"regions": regions},
        "report": {
            "output": "reports/footprint-report.html",
            "redact": False,
            "title": "My Digital Footprint Audit",
        },
        "storage": {
            "database": ".footprint/footprint.db",
            "cache": ".footprint/cache",
        },
    }


def dump_config(raw: dict[str, Any]) -> str:
    header = (
        "# Find My Footprint profile — contains personal data. Keep private (chmod 600).\n"
        "# API keys are read from environment variables, never from this file.\n"
        "# Docs: run `python -m footprint --help` or see README.md\n\n"
    )
    return header + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=100)


def write_config(path: Path, raw: dict[str, Any], force: bool = False) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if path.exists() and not force:
        raise ConfigError(f"{path} already exists; use --force to overwrite it")
    write_private_text(path, dump_config(raw))
    return path


def load_broker_catalog() -> list[dict[str, Any]]:
    catalog_path = Path(__file__).with_name("data") / "brokers.yaml"
    try:
        raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    entries = raw.get("brokers", []) if isinstance(raw, dict) else []
    return [entry for entry in entries if isinstance(entry, dict) and entry.get("id")]
