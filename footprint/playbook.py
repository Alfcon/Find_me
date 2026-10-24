"""Turn findings into a concrete, prioritised removal and hardening plan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .brokers import BrokerCatalog
from .config import AppConfig, Profile
from .db import Store
from .util import compact, days_from_now, due_label

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
PRIORITY_LABEL = {
    "P0": "Act now",
    "P1": "This week",
    "P2": "This month",
    "P3": "Routine",
}
PRIORITY_DAYS = {"P0": 3, "P1": 14, "P2": 30, "P3": 90}


@dataclass(slots=True)
class Action:
    id: str
    priority: str
    title: str
    detail: str
    category: str
    steps: list[str] = field(default_factory=list)
    url: str = ""
    status: str = "todo"
    due_at: str = ""
    finding_id: int | None = None
    broker_id: str = ""
    command: str = ""
    evidence: str = ""

    @property
    def priority_label(self) -> str:
        return PRIORITY_LABEL.get(self.priority, self.priority)

    @property
    def due_label(self) -> str:
        return due_label(self.due_at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "title": self.title,
            "detail": self.detail,
            "category": self.category,
            "steps": self.steps,
            "url": self.url,
            "status": self.status,
            "due_at": self.due_at,
            "due_label": self.due_label,
            "finding_id": self.finding_id,
            "broker_id": self.broker_id,
            "command": self.command,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class ChecklistItem:
    id: str
    title: str
    detail: str
    group: str = "Hardening"
    url: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "detail": self.detail,
            "group": self.group,
            "url": self.url,
        }


@dataclass(slots=True)
class Template:
    id: str
    title: str
    when: str
    subject: str
    body: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "when": self.when,
            "subject": self.subject,
            "body": self.body,
        }


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)
    hardening: list[ChecklistItem] = field(default_factory=list)
    templates: list[Template] = field(default_factory=list)
    broker_rows: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "actions": [action.as_dict() for action in self.actions],
            "hardening": [item.as_dict() for item in self.hardening],
            "templates": [template.as_dict() for template in self.templates],
            "broker_rows": self.broker_rows,
            "summary": self.summary,
        }


def _priority_for(severity: str) -> str:
    return {
        "critical": "P0",
        "high": "P1",
        "medium": "P2",
        "low": "P3",
        "info": "P3",
    }.get(severity, "P2")


def _status_for_finding(status: str) -> str:
    return {
        "new": "todo",
        "confirmed": "todo",
        "removal_requested": "in_progress",
        "removed": "done",
        "reappeared": "todo",
        "monitoring": "monitoring",
        "false_positive": "dismissed",
    }.get(status, "todo")


def build_plan(store: Store, config: AppConfig, catalog: BrokerCatalog) -> Plan:
    findings = store.list_findings(limit=10000)
    actionable = [
        finding
        for finding in findings
        if finding["status"] not in {"false_positive", "removed"}
    ]
    actions: list[Action] = []
    for finding in actionable:
        actions.append(_finding_action(finding, config.profile, catalog, config))

    broker_status = store.get_broker_statuses()
    for action in actions:
        if not action.broker_id:
            continue
        state = broker_status.get(action.broker_id, {})
        state_status = state.get("status", "not_checked")
        if state_status == "removal_requested" and action.status == "todo":
            action.status = "in_progress"
            action.due_at = state.get("due_at") or action.due_at
        elif state_status == "removed":
            action.status = "done"
    covered_brokers = {action.broker_id for action in actions if action.broker_id}
    for broker in catalog.people_search(config.brokers.regions):
        if broker.id in covered_brokers:
            continue
        state = broker_status.get(broker.id, {})
        status = state.get("status", "not_checked")
        if status not in {"listed", "removal_requested", "blocked", "reappeared"}:
            continue
        priority = "P1" if status in {"listed", "reappeared"} else "P2"
        action_status = "in_progress" if status == "removal_requested" else "todo"
        actions.append(
            Action(
                id=f"broker:{broker.id}",
                priority=priority,
                title=f"{'Follow up' if action_status == 'in_progress' else 'Remove'} your {broker.name} listing",
                detail=(
                    f"{broker.notes} Requirements: {broker.requirements or 'see the opt-out page'}."
                ),
                category="data_broker",
                steps=[
                    "Open the operator's opt-out page and find the exact record.",
                    "Submit only the minimum information required; use a dedicated email.",
                    "Keep the confirmation page or email as evidence.",
                    "Re-scan and recheck the listing after the stated processing period.",
                ],
                url=broker.optout_url,
                status=action_status,
                due_at=state.get("due_at") or days_from_now(PRIORITY_DAYS[priority]),
                broker_id=broker.id,
                command=f"python -m footprint broker-update {broker.id} --status removal_requested",
            )
        )

    if actionable:
        actions.append(
            Action(
                id="channel:google-results-about-you",
                priority="P2",
                title="Set up Google ‘Results about you’ monitoring",
                detail=(
                    "Google can monitor for new results containing your name, address, phone "
                    "and email in supported countries. It removes results from Google Search, "
                    "not from the source website."
                ),
                category="search_engine",
                steps=[
                    "Open Results about you while signed in to the Google account you want to use.",
                    "Add the identifiers you want monitored and complete verification.",
                    "For each result, request removal and record the case.",
                ],
                url="https://myactivity.google.com/results-about-you",
                status="todo",
                due_at=days_from_now(14),
            )
        )

    actions = _dedupe_actions(actions)
    actions.sort(key=lambda item: (PRIORITY_ORDER.get(item.priority, 9), item.title.casefold()))
    broker_rows = _broker_rows(catalog, config, broker_status)
    hardening = _hardening_items(config)
    templates = _templates(config.profile, config.country)
    summary = {
        "total": len(actions),
        "p0": sum(action.priority == "P0" for action in actions),
        "p1": sum(action.priority == "P1" for action in actions),
        "p2": sum(action.priority == "P2" for action in actions),
        "p3": sum(action.priority == "P3" for action in actions),
        "in_progress": sum(action.status == "in_progress" for action in actions),
        "done": sum(finding["status"] == "removed" for finding in findings)
        + sum(state.get("status") == "removed" for state in broker_status.values()),
        "broker_count": len(broker_rows),
        "broker_actionable": sum(
            row["status"] in {"listed", "removal_requested", "blocked", "reappeared"}
            for row in broker_rows
        ),
    }
    return Plan(
        actions=actions,
        hardening=hardening,
        templates=templates,
        broker_rows=broker_rows,
        summary=summary,
    )


def _finding_action(
    finding: dict[str, Any], profile: Profile, catalog: BrokerCatalog, config: AppConfig
) -> Action:
    priority = _priority_for(finding["severity"])
    due = days_from_now(PRIORITY_DAYS[priority])
    status = _status_for_finding(finding["status"])
    category = finding["category"]
    details = finding.get("details") or {}
    broker = catalog.get(str(details.get("broker_id") or ""))
    title = finding["title"]
    url = finding.get("url", "")
    command = f"python -m footprint update {finding['id']} --status removal_requested"
    steps: list[str]
    detail: str

    if category == "data_broker":
        broker_name = broker.name if broker else "the data broker"
        title = f"Remove your listing from {broker_name}"
        detail = (
            "A public people-search or data-broker page appears to match your identifiers. "
            "Opt out at the operator's own page; do not pay a third-party removal service."
        )
        steps = [
            "Open the result and confirm it is genuinely you (not a namesake).",
            f"Use the {broker_name} opt-out page; submit the exact profile URL.",
            "Use a dedicated email alias and keep the confirmation.",
            "Recheck after 14–30 days; listings are often rebuilt from public sources.",
        ]
        if broker:
            url = broker.optout_url or url
        command = f"python -m footprint update {finding['id']} --status removal_requested"
    elif category == "breach":
        command = f"python -m footprint update {finding['id']} --status confirmed"
        breach = str(details.get("breach") or "").strip()
        breach_count = int(details.get("breach_count") or 0)
        breach_label = breach or (f"{breach_count} known breaches" if breach_count else "a known breach")
        title = f"Secure accounts exposed in {breach_label}"
        detail = (
            "Your email appears in a known breach. This does not mean the password is "
            "currently usable, but reused credentials are the main risk."
        )
        steps = [
            "Change the password for the breached service and any account that reused it.",
            "Turn on MFA/passkeys and revoke active sessions and app passwords.",
            "Check the account's recovery email and phone number for changes.",
            "Watch for targeted phishing; do not click links in breach notifications.",
            "If identity documents or financial data were exposed, consider a credit ban and monitor accounts.",
        ]
    elif category == "code":
        title = f"Review public developer exposure: {title}"
        detail = (
            "A code-hosting profile or package page is public. Developer profiles often "
            "leak a personal email through commits, package metadata, or old repositories."
        )
        steps = [
            "Open the profile and check name, bio, location, website, and public email.",
            "Set a GitHub/GitLab noreply commit email and rotate any secrets exposed in history.",
            "Remove personal email addresses from package metadata and old repositories.",
            "Delete or archive repositories and gists you no longer need.",
            "Consider a separate professional identity and username.",
        ]
    elif category == "social":
        title = f"Review public profile or post: {title}"
        detail = (
            "A social or profile page is publicly discoverable. Decide whether it needs to "
            "be public; the strongest fix is deletion, the next strongest is audience limits."
        )
        steps = [
            "Check the profile and posts while logged out or in a private window.",
            "Delete or restrict posts that reveal address, phone, workplace, school, or daily routine.",
            "Remove tags, old photos, check-ins, and third-party app posts.",
            "Review the platform's privacy settings and limit future posts.",
            "If you reused this username elsewhere, change it or separate the identities.",
        ]
    elif category == "public_record":
        title = f"Check whether this public record can be suppressed: {title}"
        detail = (
            "Public records are often lawful and cannot simply be deleted. Ask the custodian "
            "about redaction, suppression, or correction, and avoid paying a ‘record removal’ service."
        )
        steps = [
            "Open the record and verify it is yours, not a namesake's.",
            "Contact the agency or publisher and ask about correction, redaction, or suppression.",
            "If the record is inaccurate, use the formal correction route and keep evidence.",
            "If the information is sensitive and the law provides a removal right, make a written request.",
        ]
    elif category == "news":
        title = f"Ask the publisher to update or remove: {title}"
        detail = (
            "News archives may be accurate but still influence search results. Correction and "
            "privacy routes differ from asking for a rewrite."
        )
        steps = [
            "Identify the publisher, author, and date.",
            "Ask for a factual correction first if anything is wrong.",
            "If there is a safety or legal basis, make a specific removal or de-indexing request.",
            "If the page is removed or changed, use Google/Bing outdated-content tools to refresh the snippet.",
        ]
    elif category == "domain":
        title = f"Protect domain registration data for {finding.get('identifier', 'your domain')}"
        detail = (
            "Registrant contact fields are public in some registries. WHOIS privacy is usually "
            "cheap or free; check whether your registrar enables it by default."
        )
        steps = [
            "Open the RDAP record and see which fields are visible.",
            "Enable WHOIS privacy/redaction at the registrar.",
            "Use a role mailbox (not a personal address) for domain contacts.",
            "Review DNS, certificate transparency, and email DNS records for unnecessary exposure.",
        ]
    else:
        title = f"Review and request removal where appropriate: {title}"
        detail = (
            "This page is publicly indexed and matches your identifiers. Verify it is you, then "
            "decide whether to remove it at the source, update it, or ask a search engine to de-index it."
        )
        steps = [
            "Open the result and verify ownership/accuracy.",
            "Contact the site owner and request removal or correction.",
            "If the page is gone or changed, request a search-engine cache refresh.",
            "If the content is sensitive, use the search engine's personal-information removal route.",
        ]

    return Action(
        id=f"finding:{finding['id']}",
        priority=priority,
        title=title,
        detail=detail,
        category=category,
        steps=steps,
        url=url,
        status=status,
        due_at=due,
        finding_id=finding["id"],
        broker_id=broker.id if broker else "",
        command=command,
        evidence=compact(finding.get("snippet", ""), 260),
    )


def _dedupe_actions(actions: Iterable[Action]) -> list[Action]:
    seen: set[str] = set()
    result: list[Action] = []
    for action in actions:
        if action.id in seen:
            continue
        seen.add(action.id)
        result.append(action)
    return result


def _broker_rows(
    catalog: BrokerCatalog, config: AppConfig, broker_status: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = []
    for broker in catalog.people_search(config.brokers.regions):
        state = broker_status.get(broker.id, {})
        rows.append(
            {
                "id": broker.id,
                "name": broker.name,
                "regions": broker.regions,
                "region_label": broker.region_label,
                "category": broker.category,
                "optout_url": broker.optout_url,
                "search_url": catalog.search_url_for(broker, config.profile),
                "method": broker.method,
                "difficulty": broker.difficulty,
                "minutes": broker.minutes,
                "requirements": broker.requirements,
                "notes": broker.notes,
                "last_verified": broker.last_verified,
                "status": state.get("status", "not_checked"),
                "due_at": state.get("due_at", ""),
                "due_label": due_label(state.get("due_at")),
                "checked_at": state.get("updated_at", ""),
            }
        )
    return rows


def _hardening_items(config: AppConfig) -> list[ChecklistItem]:
    country = config.country.casefold()
    items = [
        ChecklistItem(
            "passwords",
            "Use a password manager and unique passwords",
            "One breach should not unlock other accounts. Generate a unique password or passkey per service.",
            "Accounts",
            "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
        ),
        ChecklistItem(
            "mfa",
            "Enable MFA, preferring passkeys or an authenticator app",
            "SMS is better than nothing but is vulnerable to SIM swap. Store recovery codes offline.",
            "Accounts",
        ),
        ChecklistItem(
            "sim-lock",
            "Add a port-out lock or SIM-swap PIN",
            "Ask your mobile carrier for a port-out PIN or number lock, and remove voicemail passwords/PINs that are easy to guess.",
            "Accounts",
        ),
        ChecklistItem(
            "aliases",
            "Use email aliases for signups",
            "Keep a private primary address for banking and government. Use per-service aliases so you can trace and disable leaks.",
            "Accounts",
        ),
        ChecklistItem(
            "social",
            "Audit social privacy and old posts",
            "Check your profile logged out. Remove location, workplace, school, relationships, and photos that reveal your routine.",
            "Content",
        ),
        ChecklistItem(
            "metadata",
            "Strip metadata from public files and photos",
            "Photos and PDFs can contain GPS, author names, and software paths. Remove metadata before publishing; keep originals private.",
            "Content",
        ),
        ChecklistItem(
            "dormant",
            "Close dormant accounts",
            "Old forums and shopping sites are breach magnets. Use a deletion directory, then remove the account and its content.",
            "Accounts",
            "https://justdeleteme.xyz/",
        ),
        ChecklistItem(
            "ads",
            "Turn off ad personalization",
            "Opt out of personalized ads in Google, Meta, Apple, Microsoft, and your mobile advertising ID settings.",
            "Data",
            "https://myadcenter.google.com/",
        ),
        ChecklistItem(
            "brokers",
            "Recheck data brokers every 90 days",
            "Broker records are rebuilt from public sources. Calendar a quarterly re-scan and keep confirmation emails.",
            "Data",
        ),
        ChecklistItem(
            "credit",
            "Consider a credit ban/freeze if identity data leaked",
            "A credit ban is not deletion. It restricts access to your credit file while active and is appropriate after identity theft.",
            "Identity",
            _credit_url(country),
        ),
        ChecklistItem(
            "google-monitor",
            "Set up ongoing search monitoring",
            "Use Google Results about you and a quarterly scan. Search while logged out and check image results too.",
            "Monitoring",
            "https://myactivity.google.com/results-about-you",
        ),
        ChecklistItem(
            "separate-identity",
            "Separate public and private identities",
            "Use different handles for professional, hobby, and private accounts. Do not reuse a handle that links all three.",
            "Identity",
        ),
        ChecklistItem(
            "permissions",
            "Review app permissions and third-party access",
            "Revoke old OAuth grants, delete unused apps, and remove contacts/photos/calendar access that is not needed.",
            "Accounts",
        ),
        ChecklistItem(
            "evidence",
            "Keep an evidence log",
            "Save screenshots, URLs, dates, and confirmation emails. You will need them for follow-ups and escalations.",
            "Process",
        ),
    ]
    return items


def _credit_url(country: str) -> str:
    if "australia" in country or country == "au":
        return "https://equifax.com.au/personal/help-centre/credit-report-ban"
    if "united kingdom" in country or country == "uk" or country == "gb":
        return "https://www.cifas.org.uk/secure/contentPORT/uploads/documents/CIFAS%20Protective%20Registration%20Leaflet.pdf"
    return "https://www.usa.gov/credit-freeze"


def _templates(profile: Profile, country: str) -> list[Template]:
    name = profile.display_name or "[your full name]"
    email = profile.emails[0] if profile.emails else "[your email]"
    address = profile.addresses[0] if profile.addresses else "[your address]"
    identifier = email or (profile.phones[0] if profile.phones else "[identifier]")
    common = (
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Address: {address}\n"
        f"Identifier affected: {identifier}\n"
    )
    return [
        Template(
            "publisher",
            "Publisher removal / correction request",
            "Use when a specific website page is inaccurate or you want it removed.",
            "Request to remove or correct personal information",
            (
                "Hello,\n\n"
                "I am writing about this page: [URL]\n\n"
                f"{common}\n"
                "The page contains my personal information and I would like it removed, "
                "or the following factual errors corrected: [describe].\n\n"
                "Please confirm what action you take and the date it takes effect. If you "
                "cannot remove it, please explain the basis for retention and any suppression "
                "or de-indexing option available.\n\n"
                "Thank you,\n"
                f"{name}\n"
            ),
        ),
        Template(
            "gdpr",
            "GDPR / UK GDPR erasure request",
            "Use for an organisation processing your data in the EU or UK.",
            "Request for erasure under Article 17 GDPR",
            (
                "To the Data Protection Officer,\n\n"
                f"{common}\n"
                "I request erasure of the personal data relating to me that you process, "
                "including [URLs / database records]. I am making this request under Article 17 "
                "of the UK/EU General Data Protection Regulation.\n\n"
                "Please confirm receipt within one month and tell me what has been erased, "
                "what (if anything) is retained and why, and whether the data was shared with "
                "third parties. If you need identity verification, tell me the minimum evidence required.\n\n"
                "I understand some data may be retained for legal obligations or defence of legal claims.\n\n"
                "Yours sincerely,\n"
                f"{name}\n"
            ),
        ),
        Template(
            "ccpa",
            "CCPA / CPRA deletion request",
            "Use for a business covered by California privacy law.",
            "Request to delete personal information (CCPA/CPRA)",
            (
                "To the Privacy Team,\n\n"
                f"{common}\n"
                "I request that you delete the personal information you have collected about me "
                "and direct service providers to do the same, under the California Consumer "
                "Privacy Act as amended by the CPRA. Please also correct inaccurate information "
                "and opt me out of the sale or sharing of my personal information.\n\n"
                "Please confirm receipt and respond within the statutory period. If you need "
                "verification, specify the minimum information required.\n\n"
                "Sincerely,\n"
                f"{name}\n"
            ),
        ),
        Template(
            "au-privacy",
            "Australian privacy request",
            "Use for an Australian organisation. Australia has no general right to erasure; ask for correction, access, and opt-out.",
            "Request to access, correct, or suppress my personal information",
            (
                "To the Privacy Officer,\n\n"
                f"{common}\n"
                "I request access to the personal information you hold about me and correction "
                "of any information that is inaccurate, out of date, incomplete, or misleading. "
                "I also ask you to stop using my information for direct marketing and to explain "
                "any suppression or deletion options available under the Privacy Act 1988 (Cth) "
                "and applicable state law.\n\n"
                "Please tell me what is retained, why, and who it has been disclosed to. If you "
                "need identity verification, specify the minimum evidence required.\n\n"
                "Yours sincerely,\n"
                f"{name}\n"
            ),
        ),
        Template(
            "search-engine",
            "Search-engine personal-information request",
            "Use after identifying a specific indexed URL that exposes sensitive information.",
            "Personal information removal request",
            (
                "To the Search Removal Team,\n\n"
                f"{common}\n"
                "I request removal of the following search result from your index: [URL]\n\n"
                "The page exposes [address / phone / email / identity document / other sensitive "
                "information] and creates a risk of [harassment / identity theft / safety]. "
                "The underlying page is [still live / now removed / changed]. I have [contacted "
                "the publisher / requested deletion] and attach evidence.\n\n"
                "Please confirm the outcome and the date the index or cache is updated.\n\n"
                "Sincerely,\n"
                f"{name}\n"
            ),
        ),
    ]


def plan_markdown(plan: Plan, limit: int | None = None) -> str:
    lines = ["# Digital footprint removal plan", ""]
    summary = plan.summary
    lines.append(
        f"{summary.get('total', 0)} actions · {summary.get('p0', 0)} act now · "
        f"{summary.get('p1', 0)} this week · {summary.get('p2', 0)} this month"
    )
    lines.append("")
    actions = plan.actions[:limit] if limit else plan.actions
    for action in actions:
        lines.append(f"## [{action.priority}] {action.title}")
        lines.append("")
        lines.append(action.detail)
        lines.append("")
        if action.evidence:
            lines.append(f"> {action.evidence}")
            lines.append("")
        for index, step in enumerate(action.steps, 1):
            lines.append(f"{index}. {step}")
        if action.url:
            lines.append("")
            lines.append(f"Open: {action.url}")
        if action.command:
            lines.append("")
            lines.append(f"Track: `{action.command}`")
        lines.append("")
    if plan.hardening:
        lines.append("## Hardening checklist")
        lines.append("")
        for item in plan.hardening:
            lines.append(f"- [ ] **{item.title}** — {item.detail}")
        lines.append("")
    return "\n".join(lines)
