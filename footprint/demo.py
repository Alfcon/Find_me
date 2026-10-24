"""Generate a safe, clearly-labelled demo report without touching user data."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import (
    AppConfig,
    BrokersConfig,
    ChecksConfig,
    Profile,
    ReportConfig,
    SearchConfig,
    StorageConfig,
)
from .db import Store
from .models import Finding
from .report import render_report
from .util import ensure_private_dir, iso_now


def _days_ago(days: int) -> str:
    return (datetime.now().astimezone() - timedelta(days=days)).isoformat(timespec="seconds")


def demo_config(base_dir: Path) -> AppConfig:
    base_dir = base_dir.resolve()
    profile = Profile.from_mapping(
        {
            "display_name": "Jordan Example",
            "previous_names": ["Jordan Sample"],
            "emails": ["jordan.example@example.com"],
            "phones": ["+61 412 345 678"],
            "usernames": ["jordan-example"],
            "addresses": ["12 Example Street, Melbourne VIC 3000"],
            "locations": ["Melbourne, Australia"],
            "websites": ["https://example.com"],
            "country": "Australia",
        }
    )
    return AppConfig(
        path=base_dir / "demo-profile.yaml",
        base_dir=base_dir,
        profile=profile,
        search=SearchConfig(engines=["duckduckgo"], max_queries=16),
        checks=ChecksConfig(),
        brokers=BrokersConfig(regions=["AU", "US", "GLOBAL"]),
        report=ReportConfig(
            output=str(base_dir / "reports" / "demo-report.html"),
            title="Digital Footprint Audit — Demo",
        ),
        storage=StorageConfig(
            database=str(base_dir / ".footprint" / "demo.db"),
            cache=str(base_dir / ".footprint" / "demo-cache"),
        ),
    )


def seed_demo(config: AppConfig) -> Store:
    db_path = config.db_path
    ensure_private_dir(db_path.parent)
    if db_path.exists():
        db_path.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(db_path) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    store = Store(db_path)
    run_one = store.start_run("demo")
    run_two = store.start_run("demo")
    store.finish_run(
        run_one,
        "complete",
        {
            "queries_planned": 14,
            "queries_run": 14,
            "requests": 27,
            "results_seen": 104,
            "results_matched": 11,
            "new_findings": 11,
            "errors": 1,
            "notes": [],
        },
    )
    store.finish_run(
        run_two,
        "complete",
        {
            "queries_planned": 14,
            "queries_run": 14,
            "requests": 31,
            "results_seen": 112,
            "results_matched": 9,
            "new_findings": 0,
            "updated_findings": 9,
            "errors": 0,
            "notes": [],
        },
    )

    findings = [
        Finding(
            kind="search",
            category="data_broker",
            source="duckduckgo",
            title="Jordan Example, 34 — Melbourne, VIC — Phone, Address & Relatives",
            url="https://example.com/demo/spokeo-listing",
            snippet=(
                "Jordan Example, age 34, lives in Melbourne, VIC. Known phone numbers, "
                "current and previous addresses, and 4 possible relatives."
            ),
            identifier="Jordan Example",
            identifier_type="name",
            severity="high",
            confidence=0.93,
            matched="name:Jordan Example, location:Melbourne, phone:+61412345678",
            details={
                "engine": "duckduckgo",
                "query": '"Jordan Example" "Melbourne"',
                "query_label": "Name + location · Jordan Example / Melbourne",
                "purpose": "name_location",
                "domain": "example.com",
                "broker_id": "spokeo",
                "matched_fields": ["text"],
                "rank": 2,
                "reasons": [
                    "A data-broker or people-search domain is publishing a matching record",
                    "The query matched a phone number",
                    "Page appears to mention home address",
                    "Page appears to mention relatives",
                ],
                "queries": ['"Jordan Example" "Melbourne"', '"jordan-example" "Jordan Example"'],
                "engines": ["duckduckgo", "bing"],
                "category_label": "Data broker",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="breach",
            category="breach",
            source="Have I Been Pwned",
            title="Email exposed in the Adobe breach",
            url="https://haveibeenpwned.com/PwnedWebsites#Adobe",
            snippet=(
                "Breach date: 2013-10-04 · 152,445,165 accounts · Data: Email addresses, "
                "Password hints, Passwords, Usernames"
            ),
            identifier="jordan.example@example.com",
            identifier_type="email",
            severity="critical",
            confidence=0.99,
            matched="email:jordan.example@example.com",
            details={
                "provider": "hibp",
                "breach": "Adobe",
                "title": "Adobe",
                "domain": "adobe.com",
                "breach_date": "2013-10-04",
                "pwn_count": 152445165,
                "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                "is_sensitive": False,
                "is_verified": True,
                "is_spam_list": False,
                "reasons": ["A verified breach includes password data"],
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="whois",
            category="domain",
            source="RDAP / WHOIS",
            title="Public registrant data for example.com",
            url="https://example.com/demo/rdap",
            snippet="name: Jordan Example · email: jordan.example@example.com · phone: +61 412 345 678",
            identifier="example.com",
            identifier_type="domain",
            severity="high",
            confidence=0.9,
            matched="domain:example.com",
            details={
                "provider": "rdap",
                "registrar": "Example Registrar",
                "redacted": False,
                "exposed_fields": {
                    "name": "Jordan Example",
                    "email": "jordan.example@example.com",
                    "phone": "+61 412 345 678",
                },
                "reasons": ["Registrant contact fields are visible in public RDAP data"],
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="search",
            category="public_record",
            source="duckduckgo",
            title="Planning permit application — 12 Example Street, Melbourne",
            url="https://example.com/demo/council-record",
            snippet=(
                "Application details for 12 Example Street, Melbourne. Applicant: Jordan Example. "
                "Includes a site plan and contact address."
            ),
            identifier="12 Example Street, Melbourne VIC 3000",
            identifier_type="address",
            severity="medium",
            confidence=0.86,
            matched="address:12 Example Street, name:Jordan Example",
            details={
                "engine": "duckduckgo",
                "query": '"Jordan Example" "12 Example Street"',
                "query_label": "Name + address · Jordan Example",
                "purpose": "name_address",
                "domain": "example.com",
                "matched_fields": ["text"],
                "rank": 1,
                "reasons": [
                    "A public-record source mentions the identifier",
                    "The query matched an address",
                ],
                "queries": ['"Jordan Example" "12 Example Street"'],
                "category_label": "Public record",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="search",
            category="news",
            source="duckduckgo",
            title="Local startup raises seed round — Example Daily",
            url="https://example.com/demo/news-story",
            snippet=(
                "Jordan Example, founder of Example Labs, said the Melbourne team would hire "
                "five engineers. The company's registered address is listed at the bottom."
            ),
            identifier="Jordan Example",
            identifier_type="name",
            severity="low",
            confidence=0.78,
            matched="name:Jordan Example, location:Melbourne",
            details={
                "engine": "duckduckgo",
                "query": '"Jordan Example" "Melbourne"',
                "query_label": "Name + location · Jordan Example / Melbourne",
                "purpose": "name_location",
                "domain": "example.com",
                "matched_fields": ["text"],
                "rank": 4,
                "reasons": ["A news or media page matches"],
                "queries": ['"Jordan Example" "Melbourne"'],
                "category_label": "News / media",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="profile",
            category="code",
            source="GitHub",
            title="GitHub profile: @jordan-example",
            url="https://example.com/demo/github",
            snippet=(
                "Jordan Example · Melbourne · Building small tools for public data. "
                "Public email: jordan.example@example.com · 14 public repositories"
            ),
            identifier="jordan-example",
            identifier_type="username",
            severity="medium",
            confidence=0.9,
            matched="username:jordan-example, name:Jordan Example",
            details={
                "provider": "github",
                "login": "jordan-example",
                "public_name": "Jordan Example",
                "public_email": "jordan.example@example.com",
                "company": "Example Labs",
                "location": "Melbourne",
                "public_repos": 14,
                "created_at": "2016-03-11T03:16:22Z",
                "reason": "public email matches your profile exactly",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="profile",
            category="social",
            source="Reddit",
            title="Reddit profile: u/jordan-example",
            url="https://example.com/demo/reddit",
            snippet=(
                "Mostly posts in r/melbourne and r/australia · 4,218 post karma · "
                "31,507 comment karma"
            ),
            identifier="jordan-example",
            identifier_type="username",
            severity="low",
            confidence=0.6,
            matched="username:jordan-example",
            details={
                "provider": "reddit",
                "link_karma": 4218,
                "comment_karma": 31507,
                "reason": "username match only — verify ownership before acting",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="profile",
            category="social",
            source="Gravatar",
            title="Gravatar profile for jordan.example@example.com",
            url="https://example.com/demo/gravatar",
            snippet="Jordan Example · Melbourne · Product engineer. Links: example.com",
            identifier="jordan.example@example.com",
            identifier_type="email",
            severity="medium",
            confidence=0.9,
            matched="email:jordan.example@example.com",
            details={
                "provider": "gravatar",
                "display_name": "Jordan Example",
                "location": "Melbourne",
                "about": "Product engineer",
                "links": ["https://example.com"],
                "reason": "public name matches your profile",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="search",
            category="forum",
            source="duckduckgo",
            title="Anyone used Example Labs for data migration? — Forum",
            url="https://example.com/demo/forum-thread",
            snippet=(
                "I worked with Jordan Example at Example Labs in Melbourne a few years ago. "
                "DM me if you need the old setup."
            ),
            identifier="jordan-example",
            identifier_type="username",
            severity="low",
            confidence=0.71,
            matched="username:jordan-example, name:Jordan Example",
            details={
                "engine": "duckduckgo",
                "query": '"jordan-example" "Jordan Example"',
                "query_label": "Username + name · @jordan-example",
                "purpose": "username_name",
                "domain": "example.com",
                "matched_fields": ["text"],
                "rank": 3,
                "reasons": ["A public forum post matches"],
                "queries": ['"jordan-example" "Jordan Example"'],
                "category_label": "Forum / community",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="search",
            category="data_broker",
            source="duckduckgo",
            title="Jordan Example — Whitepages listing (removed)",
            url="https://example.com/demo/removed-listing",
            snippet="A cached people-search result that was removed after an opt-out request.",
            identifier="Jordan Example",
            identifier_type="name",
            severity="high",
            confidence=0.88,
            matched="name:Jordan Example, location:Melbourne",
            details={
                "engine": "duckduckgo",
                "query": '"Jordan Example" "Melbourne"',
                "query_label": "Name + location · Jordan Example / Melbourne",
                "domain": "example.com",
                "broker_id": "whitepages-us",
                "matched_fields": ["text"],
                "reasons": ["A data-broker or people-search domain is publishing a matching record"],
                "queries": ['"Jordan Example" "Melbourne"'],
                "category_label": "Data broker",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
        Finding(
            kind="search",
            category="social",
            source="bing",
            title="Jordan Example — possible old profile",
            url="https://example.com/demo/false-positive",
            snippet="A different Jordan Example in Melbourne, Ireland. Not the profile owner.",
            identifier="Jordan Example",
            identifier_type="name",
            severity="low",
            confidence=0.45,
            matched="name:Jordan Example, location:Melbourne",
            details={
                "engine": "bing",
                "query": '"Jordan Example" "Melbourne"',
                "query_label": "Name + location · Jordan Example / Melbourne",
                "domain": "example.com",
                "matched_fields": ["text"],
                "reasons": ["A public social profile matches"],
                "queries": ['"Jordan Example" "Melbourne"'],
                "category_label": "Social / profile",
            },
            first_seen=_days_ago(18),
            last_seen=_days_ago(2),
        ),
    ]
    # The demo deliberately uses reserved example.com URLs for clickable
    # links, but gives each source a realistic domain so the site inventory
    # is not one giant example.com bucket.
    demo_domains = {
        "spokeo": "spokeo.com",
        "whitepages-us": "whitepages.com",
    }
    for finding in findings:
        details = finding.details
        if not details.get("domain") or details.get("domain") == "example.com":
            broker_id = details.get("broker_id") or ""
            if broker_id in demo_domains:
                details["domain"] = demo_domains[broker_id]
            elif finding.category == "code":
                details["domain"] = "github.com"
            elif finding.source == "Reddit":
                details["domain"] = "reddit.com"
            elif finding.source == "Gravatar":
                details["domain"] = "gravatar.com"
            elif finding.category == "news":
                details["domain"] = "exampledaily.com"
            elif finding.category == "forum":
                details["domain"] = "forum.example.com"
            elif finding.category == "public_record":
                details["domain"] = "council.example.gov.au"
            elif finding.category == "social" and finding.source == "Gravatar":
                details["domain"] = "gravatar.com"
            else:
                details.setdefault("domain", "example.com")
    ids = {}
    for finding in findings:
        finding_id, _is_new, _reappeared = store.upsert_finding(finding, run_two)
        ids[finding.url] = finding_id

    store.update_finding(
        ids["https://example.com/demo/removed-listing"],
        status="removed",
        notes="Whitepages suppression confirmed by email on 12 October. Recheck in 30 days.",
    )
    store.update_finding(
        ids["https://example.com/demo/false-positive"],
        status="false_positive",
        notes="Different person — a namesake in Melbourne, Ireland.",
    )
    store.update_finding(
        ids["https://example.com/demo/spokeo-listing"],
        status="removal_requested",
        notes="Opt-out submitted; awaiting email confirmation.",
    )
    store.update_broker("spokeo", "removal_requested", notes="Opt-out submitted 21 October.")
    store.update_broker("whitepages-us", "removed", notes="Suppression confirmed 12 October.")
    store.update_broker("truepeoplesearch", "listed", notes="Listing found; opt-out not yet submitted.")
    store.update_broker("equifax-au", "no_listing", notes="Checked; no public people-search listing.")
    return store


def run_demo(base_dir: Path, output: Path | None = None) -> Path:
    config = demo_config(base_dir)
    if output:
        config.report.output = str(Path(output).expanduser().resolve())
    store = seed_demo(config)
    try:
        out = render_report(store, config, output_path=config.report.output, generated_at=iso_now())
    finally:
        store.close()
    return out
