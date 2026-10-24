"""Static, self-contained HTML report with an interactive removal checklist."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .brokers import category_label, load_catalog
from .config import AppConfig
from .data_points import LABELS, infer_data_points, inventory
from .db import Store
from .playbook import Plan, build_plan
from .queries import build_queries
from .search import direct_search_url, engine_label
from .util import (
    Redactor,
    compact,
    iso_now,
    parse_iso,
    safe_href,
    write_private_text,
)

STATUS_LABELS = {
    "new": "New",
    "confirmed": "Confirmed",
    "removal_requested": "Removal requested",
    "removed": "Removed",
    "reappeared": "Reappeared",
    "monitoring": "Monitoring",
    "false_positive": "False positive",
    "not_checked": "Not checked",
    "no_listing": "No listing",
    "listed": "Listed",
    "blocked": "Blocked",
    "todo": "To do",
    "in_progress": "In progress",
    "done": "Done",
    "dismissed": "Dismissed",
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

STATUS_CLASS = {
    "new": "status-new",
    "confirmed": "status-confirmed",
    "removal_requested": "status-progress",
    "removed": "status-done",
    "reappeared": "status-alert",
    "monitoring": "status-monitor",
    "false_positive": "status-muted",
}


def e(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _fmt_date(value: str | None, include_time: bool = False) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "—"
    return parsed.astimezone().strftime("%d %b %Y, %H:%M" if include_time else "%d %b %Y")


def _safe_link(url: str, label: str, css: str = "") -> str:
    href = safe_href(url)
    if not href:
        return f'<span class="{css}">{e(label)}</span>'
    return (
        f'<a class="{css}" href="{e(href)}" target="_blank" '
        f'rel="noopener noreferrer nofollow">{e(label)}</a>'
    )


def _severity_badge(severity: str) -> str:
    return f'<span class="sev sev-{e(severity)}">{e(SEVERITY_LABELS.get(severity, severity))}</span>'


def _status_badge(status: str) -> str:
    css = STATUS_CLASS.get(status, "status-muted")
    return f'<span class="status {css}">{e(STATUS_LABELS.get(status, status.replace("_", " ").title()))}</span>'


def _source_label(finding: dict[str, Any]) -> str:
    source = str(finding.get("source") or "")
    if finding.get("kind") == "search":
        return engine_label(source)
    return source


def _score_class(band: str) -> str:
    return {"Low": "score-low", "Moderate": "score-moderate", "High": "score-high", "Severe": "score-severe"}.get(
        band, "score-moderate"
    )


def render_report(
    store: Store,
    config: AppConfig,
    output_path: str | Path | None = None,
    *,
    redact: bool | None = None,
    generated_at: str | None = None,
) -> Path:
    catalog = load_catalog()
    plan = build_plan(store, config, catalog)
    stats = store.stats()
    findings = store.list_findings(limit=10000)
    runs = store.list_runs(limit=6)
    redacted = config.report.redact if redact is None else redact
    redactor = Redactor(config.profile.identifiers(include_locations=True), enabled=redacted)
    data_inventory = inventory(findings, config.profile)
    generated = generated_at or iso_now()
    output = Path(output_path).expanduser() if output_path else config.report_path
    if not output.is_absolute():
        output = (config.base_dir / output).resolve()

    profile = config.public_summary(redact=redacted)
    queries = [] if redacted else build_queries(
        config.profile, config.search, catalog.filter_regions(config.brokers.regions)
    )
    payload = _report_payload(
        config, stats, findings, plan, runs, redacted, redactor, generated
    )
    body = _render_body(
        config,
        stats,
        findings,
        plan,
        runs,
        profile,
        redactor,
        generated,
        redacted,
        queries,
        data_inventory,
        catalog,
    )
    document = _document(config.report.title, body, payload, generated)
    write_private_text(output, document)
    return output


def _document(title: str, body: str, payload: dict[str, Any], generated: str) -> str:
    payload_json = (
        json.dumps(payload, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<meta name="color-scheme" content="light">
<title>{e(title)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
<script id="report-data" type="application/json">{payload_json}</script>
<script>{JS}</script>
</body>
</html>
"""


def _render_body(
    config: AppConfig,
    stats: dict[str, Any],
    findings: list[dict[str, Any]],
    plan: Plan,
    runs: list[dict[str, Any]],
    profile: dict[str, Any],
    redactor: Redactor,
    generated: str,
    redacted: bool,
    queries: list | None = None,
    data_inventory: dict[str, Any] | None = None,
    catalog=None,
) -> str:
    score = int(stats.get("score", 0))
    band = str(stats.get("band", "Low"))
    score_class = _score_class(band)
    active = int(stats.get("active", 0))
    high_count = int(stats.get("by_severity", {}).get("critical", 0)) + int(
        stats.get("by_severity", {}).get("high", 0)
    )
    broker_count = sum(
        1 for finding in findings if (finding.get("details") or {}).get("broker_id")
    )
    removed = int(stats.get("removed", 0))
    next_action = plan.actions[0] if plan.actions else None
    chips = _identity_chips(profile, redacted)
    finding_cards = _render_findings(findings, redactor, config)
    categories = _render_categories(stats)
    severity_cards = _render_severities(stats)
    actions_html = _render_actions(plan, redactor)
    brokers_html = _render_brokers(plan, config)
    removal_channels = _render_removal_channels(plan, config)
    hardening_html = _render_hardening(plan, redactor)
    templates_html = _render_templates(plan, redactor)
    runs_html = _render_runs(runs)
    empty = _empty_state(active) if active == 0 else ""
    manual_queries = _render_manual_queries(queries or [], config.search.region)
    data_section = _render_data_inventory(
        data_inventory or {"points": [], "counts": {}, "sites": []},
        redactor,
        catalog,
    )
    exposed_section = _render_exposed_data(
        data_inventory or {"points": [], "counts": {}, "sites": []},
        redactor,
    )
    redact_banner = (
        '<div class="banner banner-info"><strong>Redacted report.</strong> Identifiers and snippets are masked, '
        "but result URLs may still contain personal details. Review before sharing.</div>"
        if redacted
        else '<div class="banner"><strong>This report contains personal data.</strong> Keep it local or encrypt it before sharing. '
        "It is written with owner-only permissions where the filesystem supports it.</div>"
    )
    action_label = "View the cleanup plan" if active else "Review hardening checklist"
    action_href = "#plan" if active else "#hardening"
    next_title = redactor.text(next_action.title) if next_action else "Keep your exposure low"
    next_detail = (
        redactor.text(next_action.detail)
        if next_action
        else "No active matches were stored. Re-scan quarterly and after changing jobs, moving, or changing phone numbers."
    )
    next_meta = (
        f"{next_action.priority_label} · due {next_action.due_label}"
        if next_action
        else "Ongoing · quarterly"
    )
    generated_label = _fmt_date(generated, include_time=True)

    return f"""
<header class="hero">
  <div class="hero-grid">
    <div class="hero-copy">
      <div class="eyebrow"><span class="dot"></span> Local privacy audit <span class="sep">/</span> {generated_label}</div>
      <h1>{e(config.report.title)}</h1>
      <p class="lede">A map of what the public web can find about you — and a prioritised plan to reduce it.</p>
      <div class="identity-chips">{chips}</div>
      <div class="hero-actions">
        <a class="button button-primary" href="{action_href}">{action_label}</a>
        <button class="button" type="button" onclick="window.print()">Print / save PDF</button>
        <button class="button" type="button" data-download>Download data</button>
      </div>
    </div>
    <div class="score-panel">
      <div class="score-ring {score_class}" style="--score:{score}">
        <div class="score-inner">
          <span class="score-value">{score}</span>
          <span class="score-denom">/ 100</span>
          <span class="score-label">exposure</span>
        </div>
      </div>
      <div class="score-meta">
        <span class="score-band {score_class}">{e(band)}</span>
        <p>Weighted by severity and number of active findings. A low score is not a guarantee of privacy.</p>
      </div>
    </div>
  </div>
  <div class="ticker">
    <div><strong>{active}</strong><span>active exposures</span></div>
    <div><strong>{high_count}</strong><span>high or critical</span></div>
    <div><strong>{broker_count}</strong><span>broker matches</span></div>
    <div><strong>{removed}</strong><span>marked removed</span></div>
    <div><strong>{plan.summary.get("total", 0)}</strong><span>removal actions</span></div>
  </div>
</header>

<main>
  {redact_banner}

  <section class="next-card">
    <div class="next-kicker">Start here</div>
    <div class="next-grid">
      <div>
        <h2>{e(next_title)}</h2>
        <p>{e(compact(next_detail, 420))}</p>
      </div>
      <div class="next-meta">
        <span>{e(next_meta)}</span>
        {_safe_link(next_action.url, "Open next step", "text-link") if next_action and next_action.url else '<a class="text-link" href="#plan">See the plan</a>'}
      </div>
    </div>
  </section>

  <section id="overview" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Overview</div>
        <h2>Your public exposure at a glance</h2>
      </div>
      <span class="section-note">{len(findings)} stored findings · {len(plan.broker_rows)} brokers in scope</span>
    </div>
    <div class="overview-grid">
      <div class="panel">
        <h3>Exposure mix</h3>
        <div class="category-bars">{categories}</div>
      </div>
      <div class="panel">
        <h3>Severity</h3>
        <div class="severity-grid">{severity_cards}</div>
        <p class="panel-note">Severity reflects the sensitivity of the exposed data and the type of source — not a legal conclusion about the page.</p>
      </div>
      <div class="panel panel-accent">
        <h3>Your identifiers</h3>
        <div class="identity-list">{chips}</div>
        <p class="panel-note">Queries are sent directly from this machine to the search provider. No account identifiers or API keys are written to the report.</p>
      </div>
    </div>
  </section>

  {exposed_section}
  {data_section}

  <section id="findings" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Findings</div>
        <h2>What the public web can see</h2>
      </div>
      <span class="section-note">Verify every match before contacting a site.</span>
    </div>
    {empty}
    <div class="finding-tools" {"" if findings else 'style="display:none"'}>
      <label class="search-box">
        <span class="sr-only">Search findings</span>
        <input id="finding-search" type="search" placeholder="Search title, domain, identifier…" autocomplete="off">
      </label>
      <label><span class="sr-only">Filter severity</span>
        <select id="filter-severity">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label><span class="sr-only">Filter category</span>
        <select id="filter-category">
          <option value="all">All categories</option>
          {_category_options(findings)}
        </select>
      </label>
      <label><span class="sr-only">Filter status</span>
        <select id="filter-status">
          <option value="all">All statuses</option>
          <option value="active">Active only</option>
          <option value="new">New</option>
          <option value="confirmed">Confirmed</option>
          <option value="removal_requested">Removal requested</option>
          <option value="reappeared">Reappeared</option>
          <option value="removed">Removed</option>
          <option value="false_positive">False positive</option>
        </select>
      </label>
      <button class="button button-small" type="button" id="clear-filters">Clear</button>
      <span class="filter-count" id="filter-count">{len(findings)} shown</span>
    </div>
    <div class="findings-list" id="findings-list">
      {finding_cards}
    </div>
    <div class="no-results" id="no-results" hidden>No findings match those filters.</div>
    {manual_queries}
  </section>

  <section id="plan" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Removal plan</div>
        <h2>Take it back, one action at a time</h2>
      </div>
      <span class="section-note">{plan.summary.get("in_progress", 0)} in progress · {plan.summary.get("done", 0)} done</span>
    </div>
    <div class="plan-summary">
      <div class="progress-block">
        <div class="progress-label"><span>Actions by priority</span><strong>{plan.summary.get("total", 0)} total</strong></div>
        <div class="priority-bar">
          {_priority_bar(plan)}
        </div>
        <div class="priority-legend">
          <span><i class="p0"></i>{plan.summary.get("p0", 0)} act now</span>
          <span><i class="p1"></i>{plan.summary.get("p1", 0)} this week</span>
          <span><i class="p2"></i>{plan.summary.get("p2", 0)} this month</span>
          <span><i class="p3"></i>{plan.summary.get("p3", 0)} routine</span>
        </div>
      </div>
      <div class="plan-note">
        <strong>Truthful removal is slow.</strong> Start with critical contact data, then brokers, then profiles.
        Checkbox state on this page is stored in your browser only; use the CLI command on each action to persist status.
      </div>
    </div>
    <div class="actions">{actions_html}</div>
  </section>

  <section id="brokers" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Data brokers</div>
        <h2>Opt out at the source</h2>
      </div>
      <span class="section-note">Never pay an unverified “removal” service.</span>
    </div>
    <p class="section-intro">These are operators' own opt-out and privacy pages for the regions in your profile.
      A broker can recreate a record from public sources, so recheck after roughly 30 days and again quarterly.</p>
    {removal_channels}
    {brokers_html}
  </section>

  <section id="hardening" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Hardening</div>
        <h2>Make the next scan boring</h2>
      </div>
      <span class="section-note" id="hardening-count"></span>
    </div>
    <div class="hardening-grid">{hardening_html}</div>
  </section>

  <section id="templates" class="section">
    <div class="section-head">
      <div>
        <div class="kicker">Templates</div>
        <h2>Ready-to-edit removal requests</h2>
      </div>
      <span class="section-note">Not legal advice. Adapt the facts and jurisdiction.</span>
    </div>
    <div class="templates">{templates_html}</div>
  </section>

  <section id="method" class="section method">
    <div class="section-head">
      <div>
        <div class="kicker">Method & limits</div>
        <h2>What this audit did — and did not do</h2>
      </div>
    </div>
    <div class="method-grid">
      <div>
        <h3>Sources checked</h3>
        <ul>
          <li>Public web search results for exact identifiers you supplied.</li>
          <li>Public profile APIs: Gravatar, GitHub, GitLab, Reddit, Keybase, Bluesky, npm.</li>
          <li>Have I Been Pwned when an API key is configured; otherwise the free XposedOrNot index.</li>
          <li>Public GitHub commit history, OpenPGP key directories, and email-derived usernames.</li>
          <li>RDAP/WHOIS registration data for domains you listed.</li>
          <li>A curated directory of data-broker and search-engine removal channels.</li>
        </ul>
      </div>
      <div>
        <h3>Blind spots</h3>
        <ul>
          <li>Private accounts, login-gated pages, paid people-search reports, and unindexed databases.</li>
          <li>Mobile apps, loyalty programs, government records, and data sold offline.</li>
          <li>Search engines return a sample, not a complete index. Run more queries or use each engine directly.</li>
          <li>Username matches can be a different person. Verify identity before acting.</li>
        </ul>
      </div>
      <div>
        <h3>Privacy of this audit</h3>
        <ul>
          <li>The database and report stay on this machine; there is no telemetry.</li>
          <li>Queries expose your identifiers to the search provider you choose. Consider a VPN or a private window if that matters.</li>
          <li>HIBP receives your email address when enabled. RDAP queries expose the domain, not your whole profile.</li>
          <li>No opt-out forms are submitted automatically. This tool opens official pages and prepares text; you stay in control.</li>
        </ul>
      </div>
      <div>
        <h3>Scan metadata</h3>
        <div class="metadata">
          <div><span>Generated</span><strong>{generated_label}</strong></div>
          <div><span>Tool</span><strong>Find My Footprint {e(__version__)}</strong></div>
          <div><span>Profile</span><strong>{e(config.path.name)}</strong></div>
          <div><span>Database</span><strong>{e(config.db_path.name)}</strong></div>
        </div>
        {runs_html}
      </div>
    </div>
    <div class="legal">This tool provides privacy research and template language, not legal advice. Removal rights vary by
      jurisdiction and by the sensitivity of the data. For doxxing, stalking, identity theft, or threats, contact local support
      services and, where appropriate, police. Keep evidence and prioritize your safety over deleting a page.</div>
  </section>
</main>

<footer class="footer">
  <div>
    <strong>Find My Footprint</strong>
    <span>Local-first public exposure audit</span>
  </div>
  <div>
    <span>{generated_label}</span>
    <span class="sep">/</span>
    <span>{e(__version__)}</span>
  </div>
</footer>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
"""


def _identity_chips(profile: dict[str, Any], redacted: bool) -> str:
    identifiers = profile.get("identifiers") or []
    if not identifiers:
        return '<span class="chip chip-muted">No identifiers configured</span>'
    labels = {
        "name": "name",
        "email": "email",
        "phone": "phone",
        "username": "handle",
        "address": "address",
        "location": "place",
    }
    chips = []
    for item in identifiers:
        chips.append(
            f'<span class="chip"><span>{e(labels.get(item["kind"], item["kind"]))}</span>{e(item["value"])}</span>'
        )
    return "".join(chips)


def _category_options(findings: Iterable[dict[str, Any]]) -> str:
    categories = sorted({finding["category"] for finding in findings})
    return "".join(
        f'<option value="{e(category)}">{e(category_label(category))}</option>' for category in categories
    )


def _render_manual_queries(queries: list, region: str = "au-en") -> str:
    if not queries:
        return ""
    rows = []
    for index, query in enumerate(queries, 1):
        google = safe_href(direct_search_url("google", query.text, region))
        bing = safe_href(direct_search_url("bing", query.text, region))
        ddg = safe_href(direct_search_url("duckduckgo", query.text, region))
        links = "".join(
            f'<a href="{e(url)}" target="_blank" rel="noopener noreferrer nofollow">{label}</a>'
            for label, url in (("Google", google), ("Bing", bing), ("DDG", ddg))
            if url
        )
        rows.append(
            f'<tr><td class="manual-index">{index}</td><td><code>{e(query.text)}</code></td>'
            f'<td class="manual-links">{links}</td></tr>'
        )
    return f"""
<details class="manual-searches">
  <summary><span><strong>Run the same searches yourself</strong><small>Search engines index different pages. These links open the exact query in each engine; Google often catches what DuckDuckGo misses.</small></span><span class="template-arrow manual-toggle">Show</span></summary>
  <div class="manual-body">
    <table class="manual-table"><thead><tr><th>#</th><th>Query</th><th>Open in</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
    <p class="panel-note">These links send the query directly to the search provider. They are hidden in redacted reports. Found something? Track it with <code>python -m footprint add-url "&lt;url&gt;"</code>.</p>
  </div>
</details>
"""


def _render_categories(stats: dict[str, Any]) -> str:
    by_category = stats.get("by_category") or {}
    if not by_category:
        return '<p class="muted">No findings stored yet.</p>'
    total = sum(by_category.values()) or 1
    rows = []
    for category, count in by_category.items():
        percent = max(3, round(count / total * 100))
        rows.append(
            f'<div class="bar-row"><div class="bar-label"><span>{e(category_label(category))}</span>'
            f'<strong>{count}</strong></div><div class="bar-track"><span style="width:{percent}%"></span></div></div>'
        )
    return "".join(rows)


def _render_severities(stats: dict[str, Any]) -> str:
    by_severity = stats.get("by_severity") or {}
    cards = []
    for key in ["critical", "high", "medium", "low"]:
        count = int(by_severity.get(key, 0))
        cards.append(
            f'<div class="severity-card sev-card-{key}"><strong>{count}</strong>'
            f'<span>{SEVERITY_LABELS[key]}</span></div>'
        )
    return "".join(cards)


def _render_exposed_data(data: dict[str, Any], redactor: Redactor) -> str:
    points = data.get("points") or []
    if not points:
        return ""
    rows = []
    for point in points[:30]:
        value = redactor.text(str(point.get("value") or ""))
        sources = ", ".join(str(source) for source in (point.get("sources") or [])[:4])
        observed = bool(point.get("observed", True))
        confidence = int(round(float(point.get("confidence") or 0) * 100))
        rows.append(
            f'<div class="exposed-row">'
            f'<span class="exposed-kind">{e(point.get("label") or point.get("kind") or "")}</span>'
            f'<strong>{e(value or "Referenced")}</strong>'
            f'<span class="exposed-meta">{e(sources or "unknown source")} · '
            f'{"observed" if observed else "possible"} · {confidence}%</span>'
            f'</div>'
        )
    more = (
        f'<p class="section-note">{len(points) - 30} more field entries are listed in the site dossiers and findings below.</p>'
        if len(points) > 30
        else ""
    )
    return f"""
<section id="facts" class="section">
  <div class="section-head">
    <div>
      <div class="kicker">What was found</div>
      <h2>Your exposed data</h2>
    </div>
    <span class="section-note">Actual values and references, collected from active sources.</span>
  </div>
  <p class="section-intro">This is the short answer: the data points found about you across all sources. Values marked <strong>possible</strong> are inferred and need verification; breach and broker records are evidence from an index, not proof that the data is current.</p>
  <div class="exposed-list">{''.join(rows)}</div>
  {more}
</section>
"""


def _render_data_inventory(
    data: dict[str, Any], redactor: Redactor, catalog
) -> str:
    counts = data.get("counts") or {}
    sites = data.get("sites") or []
    if not sites:
        return ""
    count_items = sorted(counts.items(), key=lambda item: (-item[1], LABELS.get(item[0], item[0])))
    count_html = "".join(
        f'<span class="inventory-chip"><strong>{count}</strong>{e(LABELS.get(kind, kind.replace("_", " ").title()))}</span>'
        for kind, count in count_items[:14]
    )
    cards = []
    for site in sites[:14]:
        broker = catalog.get(site.get("broker_id", "")) if catalog and site.get("broker_id") else None
        domain_name = str(site.get("domain", "Unknown"))
        if broker:
            name = broker.name
        elif domain_name == "xposedornot.com":
            name = "XposedOrNot breach index"
        elif domain_name == "haveibeenpwned.com":
            name = "Have I Been Pwned"
        else:
            name = domain_name
        points = site.get("points") or []
        point_html = []
        for point in points[:7]:
            value = redactor.text(str(point.get("value") or ""))
            label = str(point.get("label") or point.get("kind") or "")
            possible = not bool(point.get("observed", True))
            point_html.append(
                f'<span class="data-point{" possible" if possible else ""}">'
                f'<span>{e(label)}</span>{f": {e(value)}" if value else ""}'
                f'{" (possible)" if possible else ""}</span>'
            )
        if len(points) > 7:
            point_html.append(f'<span class="data-point more">+{len(points) - 7} more</span>')
        finding_links = " ".join(
            f'<a href="#finding-{item.get("id")}">#{item.get("id")}</a>'
            for item in (site.get("findings") or [])[:5]
            if item.get("id")
        )
        optout = (
            _safe_link(broker.optout_url, "Opt out", "text-link") if broker and broker.optout_url else ""
        )
        categories = ", ".join(
            category_label(str(category)) for category in (site.get("categories") or [])[:2]
        )
        cards.append(
            f"""
<article class="site-card">
  <div class="site-head">
    <div>
      <h3>{e(name)}</h3>
      <div class="site-meta">{_severity_badge(str(site.get("severity") or "low"))}<span>{e(categories)}</span><span>{site.get("finding_count", 1)} finding(s)</span></div>
    </div>
    <span class="site-count">{site.get("kind_count", 0)} data types</span>
  </div>
  <div class="site-points">{''.join(point_html) or '<span class="muted">No specific fields detected in the snippet yet.</span>'}</div>
  <div class="site-foot"><div class="site-links">{finding_links}</div>{optout}</div>
</article>
"""
        )
    more = f'<p class="section-note">{len(sites) - 14} more sites are listed in the findings below.</p>' if len(sites) > 14 else ""
    return f"""
<section id="sites" class="section">
  <div class="section-head">
    <div>
      <div class="kicker">Data inventory</div>
      <h2>What each site appears to have</h2>
    </div>
    <span class="section-note">Derived from result metadata, structured data, and public pages you chose to fetch.</span>
  </div>
  <p class="section-intro">This is a source-by-source view of the fields visible in the finding. <strong>Observed</strong> fields appeared in the result metadata or a fetched page; <strong>possible</strong> fields were inferred from wording and need verification. A breach record means a data class was exposed in an indexed breach — not that the data is still current or usable. Run <code>footprint enrich --all</code> to fetch selected public pages for more detail.</p>
  <div class="inventory-strip">{count_html or '<span class="muted">No fields detected yet.</span>'}</div>
  <div class="site-grid">{''.join(cards)}</div>
  {more}
</section>
"""


def _render_point_chips(points, redactor: Redactor, limit: int = 12) -> str:
    if not points:
        return ""
    chips = []
    for point in points[:limit]:
        value = redactor.text(str(getattr(point, "value", "") or ""))
        label = str(getattr(point, "label", "") or "")
        possible = not bool(getattr(point, "observed", True))
        chips.append(
            f'<span class="data-point{" possible" if possible else ""}">'
            f'<span>{e(label)}</span>{f": {e(value)}" if value else ""}'
            f'{" (possible)" if possible else ""}</span>'
        )
    return f'<div class="finding-data"><div class="finding-data-label">What this source appears to show</div><div class="data-points">{"".join(chips)}</div></div>'


def _render_breach_details(details: dict[str, Any], redactor: Redactor) -> str:
    breaches = details.get("breaches")
    if isinstance(breaches, list) and breaches:
        rows = []
        for breach in breaches[:12]:
            if not isinstance(breach, dict):
                continue
            data = breach.get("data") or []
            data_text = ", ".join(redactor.text(str(item)) for item in data[:10])
            rows.append(
                f"<tr><td>{e(redactor.text(str(breach.get('breach') or breach.get('name') or 'Breach')))}</td>"
                f"<td>{e(str(breach.get('date') or breach.get('breach_date') or '—'))}</td>"
                f"<td>{e(str(breach.get('records') or breach.get('pwn_count') or '—'))}</td>"
                f"<td>{e(data_text or '—')}</td></tr>"
            )
        if rows:
            return f"""<div class="detail-block"><span>Breach detail</span>
<div class="table-wrap compact-table"><table><thead><tr><th>Breach</th><th>Date</th><th>Records</th><th>Data exposed</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div>"""
    classes = details.get("data_classes") or details.get("exposed_data") or []
    if isinstance(classes, list) and classes:
        chips = "".join(f'<span class="data-point">{e(redactor.text(str(item)))}</span>' for item in classes[:16])
        return f'<div class="detail-block"><span>Data exposed</span><div class="data-points">{chips}</div></div>'
    return ""


def _render_enrichment(details: dict[str, Any], redactor: Redactor) -> str:
    enrichment = details.get("enrichment")
    if not isinstance(enrichment, dict):
        return ""
    status = str(enrichment.get("status") or "")
    if status != "ok":
        error = redactor.text(str(enrichment.get("http_error") or "Page could not be read"))
        return f'<div class="detail-block enrichment-note"><span>Page enrichment</span><p>{e(error)}</p></div>'
    fields = enrichment.get("fields") or {}
    field_rows = []
    for key, value in list(fields.items())[:10]:
        field_rows.append(
            f"<div><span>{e(str(key))}</span><strong>{e(redactor.text(str(value)))}</strong></div>"
        )
    excerpts = enrichment.get("excerpts") or []
    excerpt_html = "".join(
        f'<blockquote>{e(redactor.text(str(excerpt)))}</blockquote>' for excerpt in excerpts[:4]
    )
    return f"""<div class="detail-block enrichment-note"><span>Fetched public page · {e(str(enrichment.get('fetched_at') or 'unknown date'))}</span>
{f'<div class="enrich-fields">{"".join(field_rows)}</div>' if field_rows else ''}
{excerpt_html}
</div>"""


def _render_findings(
    findings: list[dict[str, Any]], redactor: Redactor, config: AppConfig
) -> str:
    if not findings:
        return ""
    cards = []
    for finding in findings:
        details = finding.get("details") or {}
        category = str(finding.get("category") or "other")
        severity = str(finding.get("severity") or "medium")
        status = str(finding.get("status") or "new")
        title = redactor.text(str(finding.get("title") or "Untitled result"))
        snippet = redactor.text(str(finding.get("snippet") or ""))
        identifier = redactor.text(str(finding.get("identifier") or ""))
        domain = str(details.get("domain") or "")
        source = _source_label(finding)
        confidence = int(round(float(finding.get("confidence") or 0) * 100))
        url = str(finding.get("url") or "")
        reasons = details.get("reasons") or []
        queries = details.get("queries") or ([details.get("query")] if details.get("query") else [])
        engines = details.get("engines") or ([details.get("engine")] if details.get("engine") else [])
        broker_id = details.get("broker_id") or ""
        broker = ""
        if broker_id:
            catalog = load_catalog()
            entry = catalog.get(str(broker_id))
            if entry:
                broker = entry.name
        title_link = _safe_link(url, title, "finding-title-link") if url else e(title)
        snippet_html = f'<p class="finding-snippet">{e(snippet)}</p>' if snippet else ""
        reason_html = "".join(f"<li>{e(redactor.text(str(reason)))}</li>" for reason in reasons)
        query_html = "".join(f"<code>{e(redactor.text(str(query)))}</code>" for query in queries if query)
        engine_html = "".join(f"<span>{e(engine_label(str(engine)) if finding.get('kind') == 'search' else engine)}</span>" for engine in engines if engine)
        broker_html = (
            f'<div><span>Broker</span><strong>{e(broker)}</strong></div>' if broker else ""
        )
        search_text = " ".join(
            [
                title,
                snippet,
                str(finding.get("source") or ""),
                category,
                identifier,
                domain,
                broker,
            ]
        ).casefold()
        notes = redactor.text(str(finding.get("notes") or ""))
        notes_html = f'<p class="finding-notes"><strong>Notes:</strong> {e(notes)}</p>' if notes else ""
        points = infer_data_points(finding, config.profile)
        point_html = _render_point_chips(points, redactor)
        breach_html = _render_breach_details(details, redactor)
        enrichment_html = _render_enrichment(details, redactor)
        cards.append(
            f"""
<article class="finding sev-border-{e(severity)}" id="finding-{finding.get("id")}" data-category="{e(category)}" data-severity="{e(severity)}" data-status="{e(status)}" data-search="{e(search_text)}">
  <div class="finding-top">
    <div class="finding-badges">{_severity_badge(severity)}{_status_badge(status)}</div>
    <span class="finding-source">{e(source)}</span>
  </div>
  <div class="finding-main">
    <h3>{title_link}</h3>
    {snippet_html}
    {point_html}
    <div class="finding-meta">
      <span class="meta-category">{e(category_label(category))}</span>
      {f'<span>{e(domain)}</span>' if domain else ''}
      <span>{confidence}% match</span>
      {f'<span>{e(identifier)}</span>' if identifier else ''}
    </div>
  </div>
  <details class="finding-details">
    <summary>Evidence, source and tracking</summary>
    <div class="finding-detail-grid">
      <div><span>First seen</span><strong>{_fmt_date(finding.get("first_seen"))}</strong></div>
      <div><span>Last seen</span><strong>{_fmt_date(finding.get("last_seen"))}</strong></div>
      <div><span>Category</span><strong>{e(category_label(category))}</strong></div>
      <div><span>Matched on</span><strong>{e(redactor.text(str(finding.get("matched") or "—")))}</strong></div>
      {broker_html}
    </div>
    {f'<div class="detail-block"><span>Found by</span><div class="tag-list">{engine_html}</div></div>' if engine_html else ''}
    {f'<div class="detail-block"><span>Queries</span><div class="code-list">{query_html}</div></div>' if query_html else ''}
    {f'<div class="detail-block"><span>Why it was flagged</span><ul>{reason_html}</ul></div>' if reason_html else ''}
    {breach_html}
    {enrichment_html}
    {notes_html}
    <div class="detail-block">
      <span>Track this finding</span>
      <div class="command-row"><code>python -m footprint update {finding.get("id")} --status removal_requested</code>
      <button class="copy-button" type="button" data-copy-text="python -m footprint update {finding.get('id')} --status removal_requested">Copy</button></div>
    </div>
  </details>
</article>
"""
        )
    return "".join(cards)


def _render_actions(plan: Plan, redactor: Redactor) -> str:
    if not plan.actions:
        return '<div class="empty-panel"><h3>No active removal actions</h3><p>Your stored findings are marked removed or false positive. Keep monitoring and work through the hardening list.</p></div>'
    cards = []
    for action in plan.actions:
        checked = action.status in {"done", "monitoring"}
        status_label = STATUS_LABELS.get(action.status, action.status)
        steps = "".join(f"<li>{e(redactor.text(step))}</li>" for step in action.steps)
        link = _safe_link(action.url, "Open official page", "button button-small") if action.url else ""
        command = (
            f'<div class="command-row"><code>{e(action.command)}</code>'
            f'<button class="copy-button" type="button" data-copy-text="{e(action.command)}">Copy</button></div>'
            if action.command
            else ""
        )
        evidence = (
            f'<blockquote>{e(redactor.text(action.evidence))}</blockquote>' if action.evidence else ""
        )
        cards.append(
            f"""
<article class="action priority-{e(action.priority)}" data-action-id="{e(action.id)}">
  <div class="action-head">
    <label class="check-wrap">
      <input type="checkbox" data-check="{e(action.id)}" {'checked' if checked else ''}>
      <span class="checkmark"></span>
      <span class="sr-only">Mark done</span>
    </label>
    <div class="action-title">
      <div class="action-kicker"><span class="priority">{e(action.priority)}</span> {e(action.priority_label)} <span class="sep">/</span> due {e(action.due_label)}</div>
      <h3>{e(redactor.text(action.title))}</h3>
    </div>
    <span class="action-status">{e(status_label)}</span>
  </div>
  <p>{e(redactor.text(action.detail))}</p>
  {evidence}
  <ol>{steps}</ol>
  <div class="action-foot">
    <div class="action-tags"><span>{e(category_label(action.category))}</span>{f'<span>{e(action.broker_id)}</span>' if action.broker_id else ''}</div>
    <div class="action-links">{link}</div>
  </div>
  {command}
</article>
"""
        )
    return "".join(cards)


def _render_brokers(plan: Plan, config: AppConfig) -> str:
    if not plan.broker_rows:
        return '<div class="empty-panel">No brokers in the configured regions.</div>'
    region_options = sorted({str(region) for row in plan.broker_rows for region in row.get("regions", [])})
    options = "".join(f'<option value="{e(region)}">{e(region)}</option>' for region in region_options)
    rows = []
    for row in plan.broker_rows:
        status = str(row.get("status") or "not_checked")
        search = _safe_link(row.get("search_url", ""), "Search", "text-link") if row.get("search_url") else ""
        optout = _safe_link(row.get("optout_url", ""), "Opt out", "text-link")
        rows.append(
            f"""
<tr data-region="{e(" ".join(row.get("regions", [])))}" data-broker-status="{e(status)}">
  <td><strong>{e(row["name"])}</strong><span class="table-sub">{e(row["region_label"])} · {e(category_label(row["category"]))}</span></td>
  <td><span class="status {STATUS_CLASS.get(status, "status-muted")}">{e(STATUS_LABELS.get(status, status.replace("_", " ").title()))}</span></td>
  <td>{e(row["method"])}<span class="table-sub">~{e(row["minutes"])} min · {e(row["difficulty"])}</span></td>
  <td class="table-links">{search}{optout}</td>
</tr>
"""
        )
    return f"""
<div class="broker-tools">
  <label><span class="sr-only">Filter region</span>
    <select id="filter-region"><option value="all">All regions</option>{options}</select>
  </label>
  <label><span class="sr-only">Filter broker status</span>
    <select id="filter-broker-status">
      <option value="all">All statuses</option>
      <option value="not_checked">Not checked</option>
      <option value="listed">Listed</option>
      <option value="removal_requested">Removal requested</option>
      <option value="no_listing">No listing</option>
      <option value="removed">Removed</option>
      <option value="blocked">Blocked</option>
    </select>
  </label>
  <span class="section-note">{len(plan.broker_rows)} entries</span>
</div>
<div class="table-wrap">
<table class="broker-table" id="broker-table">
  <thead><tr><th>Broker</th><th>Status</th><th>Process</th><th>Links</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
</div>
<div class="broker-help">
  <strong>Tracking a broker:</strong> update the row with
  <code>python -m footprint broker-update &lt;id&gt; --status listed</code>.
  Run <code>python -m footprint brokers</code> to list IDs.
</div>
"""


def _render_removal_channels(plan: Plan, config: AppConfig) -> str:
    catalog = load_catalog()
    channels = catalog.removal_channels()
    if not channels:
        return ""
    cards = []
    for broker in channels[:6]:
        cards.append(
            f"""
<a class="channel-card" href="{e(safe_href(broker.optout_url) or "#")}" target="_blank" rel="noopener noreferrer nofollow">
  <span class="channel-kicker">{e(broker.method)}</span>
  <strong>{e(broker.name)}</strong>
  <span>{e(compact(broker.notes, 150))}</span>
</a>
"""
        )
    return f'<div class="channels"><div class="channels-head"><h3>Search engines and indexes</h3><span>{len(channels)} official routes</span></div><div class="channel-grid">{"".join(cards)}</div></div>'


def _render_hardening(plan: Plan, redactor: Redactor) -> str:
    cards = []
    for item in plan.hardening:
        link = _safe_link(item.url, "Guide", "text-link") if item.url else ""
        cards.append(
            f"""
<div class="check-item" data-check-id="{e(item.id)}">
  <label class="check-wrap">
    <input type="checkbox" data-check="{e(item.id)}">
    <span class="checkmark"></span>
    <span class="sr-only">Mark done</span>
  </label>
  <div>
    <h3>{e(redactor.text(item.title))}</h3>
    <p>{e(redactor.text(item.detail))}</p>
    <div class="check-foot"><span>{e(item.group)}</span>{link}</div>
  </div>
</div>
"""
        )
    return "".join(cards)


def _render_templates(plan: Plan, redactor: Redactor) -> str:
    blocks = []
    for template in plan.templates:
        body = redactor.text(template.body)
        subject = redactor.text(template.subject)
        blocks.append(
            f"""
<details class="template">
  <summary>
    <span><strong>{e(template.title)}</strong><small>{e(template.when)}</small></span>
    <span class="template-arrow">View</span>
  </summary>
  <div class="template-body">
    <div class="template-subject"><span>Subject</span><code>{e(subject)}</code>
      <button class="copy-button" type="button" data-copy-text="{e(subject)}">Copy</button>
    </div>
    <pre>{e(body)}</pre>
    <button class="button button-small" type="button" data-copy-text="{e(body)}">Copy full request</button>
  </div>
</details>
"""
        )
    return "".join(blocks)


def _render_runs(runs: list[dict[str, Any]]) -> str:
    if not runs:
        return ""
    rows = []
    for run in runs:
        rows.append(
            f"<tr><td>#{run['id']}</td><td>{_fmt_date(run.get('started_at'), True)}</td>"
            f"<td>{e(run.get('status', ''))}</td><td>{run.get('queries', 0)}</td>"
            f"<td>{run.get('requests', 0)}</td><td>{run.get('errors', 0)}</td></tr>"
        )
    return (
        '<div class="runs"><h4>Recent scans</h4><table><thead><tr><th>#</th><th>Started</th>'
        "<th>Status</th><th>Queries</th><th>Requests</th><th>Errors</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _priority_bar(plan: Plan) -> str:
    total = max(1, plan.summary.get("total", 0))
    parts = []
    for priority in ["p0", "p1", "p2", "p3"]:
        count = int(plan.summary.get(priority, 0))
        if not count:
            continue
        percent = max(2, round(count / total * 100))
        parts.append(f'<span class="{priority}" style="width:{percent}%" title="{count} {priority}"></span>')
    return "".join(parts) or '<span class="p3" style="width:100%"></span>'


def _empty_state(active: int) -> str:
    if active:
        return ""
    return (
        '<div class="empty-panel"><div class="empty-icon">○</div><h3>No active public matches were stored.</h3>'
        "<p>That is a useful result, not proof of invisibility. Private databases, paid brokers, apps, and "
        "non-indexed records are outside this scan. Re-run with more identifiers and review the broker directory.</p></div>"
    )


def _report_payload(
    config: AppConfig,
    stats: dict[str, Any],
    findings: list[dict[str, Any]],
    plan: Plan,
    runs: list[dict[str, Any]],
    redacted: bool,
    redactor: Redactor,
    generated: str,
) -> dict[str, Any]:
    safe_findings = []
    for finding in findings:
        item = dict(finding)
        item["title"] = redactor.text(str(item.get("title") or ""))
        item["snippet"] = redactor.text(str(item.get("snippet") or ""))
        item["identifier"] = redactor.text(str(item.get("identifier") or ""))
        item["notes"] = redactor.text(str(item.get("notes") or ""))
        item["matched"] = redactor.text(str(item.get("matched") or ""))
        item["details"] = redactor.obj(item.get("details") or {})
        safe_findings.append(item)
    plan_payload = plan.as_dict()
    for action in plan_payload["actions"]:
        action["title"] = redactor.text(action["title"])
        action["detail"] = redactor.text(action["detail"])
        action["evidence"] = redactor.text(action["evidence"])
        action["steps"] = [redactor.text(step) for step in action["steps"]]
    for template in plan_payload["templates"]:
        template["body"] = redactor.text(template["body"])
    if redacted:
        for row in plan_payload.get("broker_rows", []):
            row["search_url"] = ""
    safe_inventory = inventory(safe_findings, config.profile)
    return {
        "generated_at": generated,
        "tool": f"Find My Footprint {__version__}",
        "redacted": redacted,
        "profile": config.public_summary(redact=redacted),
        "stats": stats,
        "findings": safe_findings,
        "data_inventory": redactor.obj(safe_inventory),
        "plan": plan_payload,
        "runs": runs,
    }


CSS = r"""
:root {
  --bg: #f3f0e9;
  --paper: #fbf9f4;
  --ink: #12211d;
  --muted: #5d6b65;
  --line: #d9d4c8;
  --green: #0d3b2e;
  --green-2: #1f6f52;
  --lime: #c7f36b;
  --amber: #d98a2b;
  --red: #b33a2b;
  --critical: #8f1d1d;
  --shadow: 0 18px 50px rgba(18, 33, 29, 0.08);
  --radius: 16px;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(circle at 85% -10%, rgba(199,243,107,.22), transparent 32rem),
    radial-gradient(circle at -5% 10%, rgba(13,59,46,.08), transparent 28rem),
    var(--bg);
  color: var(--ink);
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.55;
  font-size: 15px;
}
a { color: var(--green-2); text-underline-offset: 3px; }
a:hover { color: var(--green); }
button, select, input { font: inherit; }
.sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
.sep { color: #9daaa3; padding: 0 .35em; }
.hero {
  background: var(--green);
  color: #f4f1e8;
  padding: clamp(28px, 5vw, 64px) clamp(20px, 5vw, 72px) 0;
  position: relative;
  overflow: hidden;
}
.hero::before {
  content:""; position:absolute; inset:0;
  background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: 36px 36px; pointer-events:none;
  mask-image: linear-gradient(to bottom, rgba(0,0,0,.8), transparent 85%);
}
.hero-grid { display:grid; grid-template-columns: minmax(0,1.55fr) minmax(260px,.65fr); gap: 48px; align-items:center; max-width: 1320px; margin:0 auto; position:relative; }
.eyebrow { text-transform:uppercase; letter-spacing:.14em; font-size:11px; font-weight:750; color:#bdd7c9; display:flex; align-items:center; gap:8px; }
.dot { width:7px; height:7px; border-radius:99px; background:var(--lime); box-shadow:0 0 0 4px rgba(199,243,107,.12); }
.hero h1 { font-family: ui-serif, Georgia, "Times New Roman", serif; font-size: clamp(38px, 6vw, 76px); line-height:1.02; letter-spacing:-.035em; margin: 18px 0 16px; max-width: 900px; font-weight:500; }
.lede { color:#cad8d0; font-size: clamp(16px, 1.6vw, 20px); max-width: 680px; margin: 0 0 22px; }
.identity-chips { display:flex; flex-wrap:wrap; gap:7px; margin: 0 0 26px; max-width: 760px; }
.chip { border:1px solid rgba(255,255,255,.18); background:rgba(255,255,255,.06); border-radius:999px; padding:5px 10px; font-size:12px; color:#eef4ed; display:inline-flex; gap:7px; align-items:center; }
.chip span:first-child { color:#9cbcac; text-transform:uppercase; font-size:9px; letter-spacing:.1em; font-weight:750; }
.chip-muted { color:#9cbcac; }
.hero-actions { display:flex; flex-wrap:wrap; gap:9px; }
.button { border:1px solid rgba(255,255,255,.24); background:rgba(255,255,255,.06); color:#f4f1e8; padding:10px 16px; border-radius:9px; cursor:pointer; text-decoration:none; font-weight:650; font-size:13px; display:inline-flex; align-items:center; gap:7px; transition: .15s ease; }
.button:hover { background:rgba(255,255,255,.13); color:white; transform:translateY(-1px); }
.button-primary { background:var(--lime); border-color:var(--lime); color:#10241d; }
.button-primary:hover { background:#d7ff8c; color:#10241d; }
.button-small { padding:6px 10px; font-size:12px; }
.score-panel { justify-self:end; display:flex; flex-direction:column; align-items:center; gap:18px; }
.score-ring { --ring:#d98a2b; width:210px; aspect-ratio:1; border-radius:50%; background: conic-gradient(var(--ring) calc(var(--score) * 1%), rgba(255,255,255,.10) 0); display:grid; place-items:center; position:relative; box-shadow: 0 0 0 1px rgba(255,255,255,.1), inset 0 0 40px rgba(0,0,0,.15); }
.score-ring::after { content:""; position:absolute; inset:11px; background:var(--green); border-radius:50%; box-shadow: inset 0 0 0 1px rgba(255,255,255,.1); }
.score-inner { position:relative; z-index:1; text-align:center; display:flex; flex-direction:column; line-height:1; }
.score-value { font-family:ui-serif, Georgia, serif; font-size:66px; letter-spacing:-.06em; color:white; }
.score-denom { font-size:11px; color:#9cbcac; margin-top:4px; letter-spacing:.08em; }
.score-label { font-size:9px; color:#9cbcac; text-transform:uppercase; letter-spacing:.16em; margin-top:9px; }
.score-low { --ring:#7bd6a5; }
.score-moderate { --ring:#e7b84e; }
.score-high { --ring:#e07a3f; }
.score-severe { --ring:#e05b50; }
.score-meta { text-align:center; max-width:240px; }
.score-meta p { color:#a8beb2; font-size:11px; line-height:1.5; margin:7px 0 0; }
.score-band { font-size:12px; text-transform:uppercase; letter-spacing:.14em; font-weight:800; color:var(--lime); border:1px solid rgba(199,243,107,.3); padding:4px 9px; border-radius:99px; }
.score-band.score-high { color:#ffc49a; border-color:rgba(255,196,154,.35); }
.score-band.score-severe { color:#ffb1a9; border-color:rgba(255,177,169,.35); }
.score-band.score-moderate { color:#ffe0a0; border-color:rgba(255,224,160,.35); }
.ticker { max-width:1320px; margin: 46px auto 0; display:grid; grid-template-columns:repeat(5, 1fr); border-top:1px solid rgba(255,255,255,.14); position:relative; }
.ticker > div { padding:17px 8px 20px; border-right:1px solid rgba(255,255,255,.1); display:flex; flex-direction:column; gap:2px; }
.ticker > div:last-child { border-right:0; }
.ticker strong { font-family:ui-serif, Georgia, serif; font-size:26px; font-weight:500; color:white; }
.ticker span { color:#9cbcac; font-size:10px; text-transform:uppercase; letter-spacing:.1em; }
main { max-width:1320px; margin:0 auto; padding: 0 clamp(18px, 4vw, 56px) 80px; }
.banner { margin: 27px 0 0; background:#fff5d9; border:1px solid #e6d19a; border-radius:12px; padding:11px 15px; color:#5b4715; font-size:12px; }
.banner-info { background:#eaf4ef; border-color:#bad8c9; color:#24523f; }
.next-card { margin: 22px 0 0; background: var(--paper); border: 1px solid var(--line); border-radius: var(--radius); padding: 24px 28px; box-shadow: var(--shadow); }
.next-kicker { text-transform:uppercase; font-size:10px; font-weight:800; letter-spacing:.14em; color:var(--green-2); margin-bottom:7px; }
.next-grid { display:flex; gap:30px; justify-content:space-between; align-items:flex-start; }
.next-grid h2 { font-family:ui-serif, Georgia, serif; font-size:clamp(22px,3vw,31px); line-height:1.15; margin:0 0 7px; font-weight:500; letter-spacing:-.02em; }
.next-grid p { color:var(--muted); margin:0; max-width:760px; }
.next-meta { flex:0 0 190px; display:flex; flex-direction:column; align-items:flex-end; gap:6px; font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }
.text-link { font-weight:700; text-decoration:none; border-bottom:1px solid currentColor; white-space:nowrap; }
.section { margin-top: 58px; scroll-margin-top: 20px; }
.section-head { display:flex; justify-content:space-between; align-items:flex-end; gap:20px; margin-bottom:20px; }
.kicker { font-size:10px; text-transform:uppercase; letter-spacing:.16em; font-weight:800; color:var(--green-2); margin-bottom:4px; }
.section h2 { font-family:ui-serif, Georgia, serif; font-size:clamp(28px,3.4vw,43px); font-weight:500; letter-spacing:-.03em; line-height:1.1; margin:0; }
.section-note { color:var(--muted); font-size:11px; text-align:right; max-width:340px; }
.section-intro { max-width:780px; color:var(--muted); margin:-5px 0 18px; }
.overview-grid { display:grid; grid-template-columns: 1.2fr .9fr .9fr; gap:16px; }
.panel { background:var(--paper); border:1px solid var(--line); border-radius:var(--radius); padding:20px; min-width:0; }
.panel h3 { font-size:12px; text-transform:uppercase; letter-spacing:.1em; margin:0 0 16px; color:var(--muted); }
.panel-accent { background:#e9f1e9; border-color:#c7d8c8; }
.panel-note { color:var(--muted); font-size:11px; line-height:1.55; margin:16px 0 0; }
.bar-row { margin: 0 0 11px; }
.bar-label { display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px; }
.bar-label strong { font-variant-numeric: tabular-nums; }
.bar-track { height:8px; background:#e4e0d6; border-radius:99px; overflow:hidden; }
.bar-track span { display:block; height:100%; background:linear-gradient(90deg,var(--green-2),#70b884); border-radius:99px; }
.severity-grid { display:grid; grid-template-columns:1fr 1fr; gap:7px; }
.severity-card { border-radius:10px; padding:12px 11px; background:#f1eee6; display:flex; flex-direction:column; gap:1px; border:1px solid transparent; }
.severity-card strong { font-family:ui-serif, Georgia, serif; font-size:27px; font-weight:500; line-height:1; }
.severity-card span { font-size:9px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }
.sev-card-critical { background:#f6e4df; border-color:#e7c1b9; }
.sev-card-high { background:#fbecdd; border-color:#ecd0b5; }
.sev-card-medium { background:#faf3dc; border-color:#e9ddb8; }
.sev-card-low { background:#eaf1e8; border-color:#cdddc9; }
.identity-list { display:flex; flex-wrap:wrap; gap:6px; }
.identity-list .chip { border-color:#b9cabe; background:#f5f8f0; color:var(--ink); }
.identity-list .chip span:first-child { color:var(--green-2); }
.finding-tools { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:16px; background:var(--paper); border:1px solid var(--line); border-radius:12px; padding:10px; }
input[type="search"], select { border:1px solid var(--line); background:#fffdf7; border-radius:8px; padding:8px 10px; color:var(--ink); font-size:12px; outline:none; }
input[type="search"]:focus, select:focus { border-color:var(--green-2); box-shadow:0 0 0 3px rgba(31,111,82,.12); }
.search-box { flex:1 1 240px; }
.search-box input { width:100%; }
.filter-count { margin-left:auto; color:var(--muted); font-size:11px; white-space:nowrap; }
.findings-list { display:flex; flex-direction:column; gap:10px; }
.exposed-list { background:var(--paper); border:1px solid var(--line); border-radius:var(--radius); overflow:hidden; }
.exposed-row { display:grid; grid-template-columns:150px minmax(0,1.3fr) minmax(180px,.8fr); gap:16px; align-items:center; padding:10px 16px; border-bottom:1px solid #e7e2d7; }
.exposed-row:last-child { border-bottom:0; }
.exposed-row:nth-child(odd) { background:#f7f4ec; }
.exposed-kind { font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--green-2); font-weight:800; }
.exposed-row strong { font-size:13px; font-weight:600; overflow-wrap:anywhere; }
.exposed-meta { color:var(--muted); font-size:10px; text-align:right; overflow-wrap:anywhere; }
.inventory-strip { display:flex; flex-wrap:wrap; gap:6px; margin:0 0 16px; }
.inventory-chip { background:var(--paper); border:1px solid var(--line); border-radius:999px; padding:5px 9px; font-size:11px; color:var(--muted); }
.inventory-chip strong { color:var(--ink); margin-right:5px; }
.site-grid { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
.site-card { background:var(--paper); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
.site-head { display:flex; justify-content:space-between; gap:10px; align-items:flex-start; }
.site-head h3 { margin:0 0 5px; font-family:ui-serif, Georgia, serif; font-size:20px; font-weight:500; line-height:1.2; overflow-wrap:anywhere; }
.site-meta { display:flex; flex-wrap:wrap; gap:6px; align-items:center; color:var(--muted); font-size:10px; }
.site-meta .sev { margin-right:1px; }
.site-count { font-size:9px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); white-space:nowrap; }
.site-points { display:flex; flex-wrap:wrap; gap:5px; margin:12px 0; }
.site-foot { display:flex; justify-content:space-between; gap:10px; align-items:center; border-top:1px solid #e7e2d7; padding-top:8px; }
.site-links { display:flex; gap:8px; font-size:10px; }
.site-links a { color:var(--muted); text-decoration:none; }
.site-links a:hover { color:var(--green-2); text-decoration:underline; }
.finding-data { margin-top:11px; }
.finding-data-label { font-size:9px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); margin-bottom:4px; }
.data-points { display:flex; flex-wrap:wrap; gap:4px; }
.data-point { border:1px solid #d4d9cb; background:#f1f5e9; color:#3c5848; border-radius:5px; padding:3px 6px; font-size:10px; line-height:1.4; }
.data-point > span { color:#71806f; font-size:9px; text-transform:uppercase; letter-spacing:.04em; margin-right:3px; }
.data-point.possible { background:#faf4e4; border-color:#e5d4ae; color:#705c2e; }
.data-point.more { background:transparent; border-style:dashed; color:var(--muted); }
.enrich-note { background:#f2efe7; border:1px solid #e5e0d4; border-radius:7px; padding:9px 11px; margin-top:10px; }
.enrich-fields { display:grid; grid-template-columns:1fr 1fr; gap:4px 12px; margin:6px 0; }
.enrich-fields > div { display:flex; justify-content:space-between; gap:8px; font-size:10px; border-bottom:1px solid #e5e0d4; padding:2px 0; }
.enrich-fields span { color:var(--muted); text-transform:uppercase; font-size:8px; letter-spacing:.07em; }
.enrich-fields strong { font-weight:600; text-align:right; overflow-wrap:anywhere; }
.enrich-note blockquote { margin:6px 0 0; padding:6px 8px; border-left:2px solid #b8c8b8; background:#fbf9f4; color:#59685f; font-size:10px; }
.compact-table { margin-top:5px; }
.compact-table table { min-width:540px; font-size:10px; }
.compact-table th, .compact-table td { padding:6px 8px; }
.finding { background:var(--paper); border:1px solid var(--line); border-left:4px solid var(--line); border-radius:13px; padding:17px 20px; }
.sev-border-critical { border-left-color:var(--critical); }
.sev-border-high { border-left-color:var(--amber); }
.sev-border-medium { border-left-color:#b99b2e; }
.sev-border-low { border-left-color:#6c9475; }
.sev-border-info { border-left-color:#9caaa2; }
.finding-top { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:9px; }
.finding-badges { display:flex; gap:6px; flex-wrap:wrap; }
.sev, .status { font-size:9px; font-weight:800; letter-spacing:.09em; text-transform:uppercase; padding:3px 7px; border-radius:99px; border:1px solid transparent; white-space:nowrap; }
.sev-critical { background:#f5dedb; color:#7f1919; border-color:#e7bcb7; }
.sev-high { background:#fae8d7; color:#8a4a14; border-color:#eacbac; }
.sev-medium { background:#f7f0d5; color:#715b12; border-color:#e7daad; }
.sev-low { background:#e8f0e6; color:#315b3d; border-color:#c7d9c3; }
.sev-info { background:#e9eeeb; color:#485a50; }
.status-new { background:#e7effa; color:#2b4d78; border-color:#c4d6ea; }
.status-confirmed { background:#e8f0e6; color:#315b3d; border-color:#c7d9c3; }
.status-progress { background:#fbf0d8; color:#785414; border-color:#ead4a4; }
.status-done { background:#dff0e4; color:#1f5d39; border-color:#bcdcc8; }
.status-alert { background:#f6dedb; color:#7f1919; border-color:#e7bcb7; }
.status-monitor { background:#e8edf3; color:#3f5368; border-color:#cbd5df; }
.status-muted { background:#efede7; color:#6e6b62; border-color:#ddd9cf; }
.finding-source { color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:.08em; white-space:nowrap; }
.finding-main h3 { margin:0 0 5px; font-family:ui-serif, Georgia, serif; font-size:21px; font-weight:500; letter-spacing:-.015em; line-height:1.25; }
.finding-title-link { color:var(--ink); text-decoration:none; }
.finding-title-link:hover { color:var(--green-2); text-decoration:underline; }
.finding-snippet { color:var(--muted); margin:0; font-size:13px; max-width:1000px; }
.finding-meta { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; color:#7e877f; font-size:10px; text-transform:uppercase; letter-spacing:.06em; }
.finding-meta span + span::before { content:"·"; margin-right:8px; color:#b6b4aa; }
.meta-category { color:var(--green-2); font-weight:700; }
.finding-details { margin-top:12px; border-top:1px solid #e7e2d7; padding-top:10px; }
.finding-details summary { cursor:pointer; font-size:11px; color:var(--muted); font-weight:650; width:max-content; }
.finding-details[open] summary { margin-bottom:12px; }
.finding-detail-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-bottom:12px; }
.finding-detail-grid > div, .detail-block { display:flex; flex-direction:column; gap:2px; }
.finding-detail-grid span, .detail-block > span { font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); }
.finding-detail-grid strong { font-size:12px; font-weight:650; overflow-wrap:anywhere; }
.detail-block { margin:12px 0; }
.detail-block ul { margin:5px 0 0; padding-left:18px; color:var(--muted); font-size:12px; }
.code-list { display:flex; flex-wrap:wrap; gap:5px; margin-top:4px; }
.code-list code { font-size:10px; background:#ece9df; border:1px solid #ddd8ca; border-radius:5px; padding:3px 6px; overflow-wrap:anywhere; }
.tag-list { display:flex; gap:5px; flex-wrap:wrap; margin-top:4px; }
.tag-list span { background:#ece9df; border:1px solid #ddd8ca; border-radius:5px; padding:2px 6px; font-size:10px; }
.finding-notes { font-size:12px; background:#f3f0e7; padding:8px 10px; border-radius:7px; }
.command-row { display:flex; gap:6px; align-items:center; flex-wrap:wrap; margin-top:4px; }
.command-row code { background:#12211d; color:#dff4e6; border-radius:6px; padding:5px 8px; font-size:10px; overflow-wrap:anywhere; }
.copy-button { border:1px solid var(--line); background:#fffdf7; border-radius:6px; padding:4px 7px; font-size:10px; cursor:pointer; color:var(--muted); }
.copy-button:hover { border-color:var(--green-2); color:var(--green); }
.no-results { padding:30px; text-align:center; color:var(--muted); border:1px dashed var(--line); border-radius:12px; }
.empty-panel { background:var(--paper); border:1px dashed #c9c3b5; border-radius:var(--radius); padding:34px; text-align:center; }
.empty-panel h3 { font-family:ui-serif, Georgia, serif; font-size:29px; font-weight:500; margin:7px 0; }
.empty-panel p { color:var(--muted); max-width:660px; margin:0 auto; }
.empty-icon { font-size:38px; color:var(--green-2); }
.manual-searches { margin-top:16px; background:var(--paper); border:1px solid var(--line); border-radius:11px; }
.manual-searches summary { display:flex; justify-content:space-between; gap:12px; padding:13px 16px; cursor:pointer; list-style:none; align-items:center; }
.manual-searches summary::-webkit-details-marker { display:none; }
.manual-searches[open] .manual-toggle { font-size:0; }
.manual-searches[open] .manual-toggle::after { content:"Hide"; font-size:9px; }
.manual-searches summary strong { display:block; font-size:13px; }
.manual-searches summary small { display:block; font-size:10px; color:var(--muted); margin-top:2px; }
.manual-body { border-top:1px solid var(--line); padding:12px 16px 8px; }
.manual-table { width:100%; border-collapse:collapse; font-size:11px; }
.manual-table th { text-align:left; font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); padding:4px 6px; border-bottom:1px solid var(--line); }
.manual-table td { padding:5px 6px; border-bottom:1px solid #eee9dd; vertical-align:top; }
.manual-table code { font-size:10px; overflow-wrap:anywhere; }
.manual-index { color:var(--muted); width:2em; }
.manual-links { white-space:nowrap; }
.manual-links a { margin-right:9px; font-weight:650; }
.plan-summary { display:grid; grid-template-columns: 1.45fr .85fr; gap:16px; margin-bottom:16px; }
.progress-block, .plan-note { background:var(--paper); border:1px solid var(--line); border-radius:13px; padding:17px 19px; }
.progress-label { display:flex; justify-content:space-between; font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:9px; }
.progress-label strong { color:var(--ink); }
.priority-bar { height:12px; display:flex; overflow:hidden; border-radius:99px; background:#e4e0d6; }
.priority-bar span { display:block; height:100%; }
.priority-bar .p0 { background:#8f1d1d; }
.priority-bar .p1 { background:#c8752c; }
.priority-bar .p2 { background:#b89a33; }
.priority-bar .p3 { background:#6c9475; }
.priority-legend { display:flex; flex-wrap:wrap; gap:12px; margin-top:10px; font-size:10px; color:var(--muted); }
.priority-legend span { display:inline-flex; align-items:center; gap:5px; }
.priority-legend i { width:7px; height:7px; border-radius:2px; display:inline-block; }
.priority-legend .p0 { background:#8f1d1d; } .priority-legend .p1 { background:#c8752c; } .priority-legend .p2 { background:#b89a33; } .priority-legend .p3 { background:#6c9475; }
.plan-note { font-size:12px; color:var(--muted); }
.plan-note strong { color:var(--ink); }
.actions { display:flex; flex-direction:column; gap:11px; }
.action { background:var(--paper); border:1px solid var(--line); border-radius:14px; padding:19px 21px 16px; }
.action.priority-P0 { border-color:#d8b4ae; background:#fdf4f1; }
.action-head { display:flex; gap:12px; align-items:flex-start; }
.check-wrap { position:relative; display:inline-flex; align-items:center; cursor:pointer; flex:0 0 auto; }
.check-wrap input { position:absolute; opacity:0; width:20px; height:20px; cursor:pointer; }
.checkmark { width:19px; height:19px; border:1.5px solid #a8aea4; border-radius:5px; background:#fffdf7; display:inline-block; position:relative; margin-top:2px; }
.check-wrap input:checked + .checkmark { background:var(--green); border-color:var(--green); }
.check-wrap input:checked + .checkmark::after { content:""; position:absolute; left:6px; top:2px; width:4px; height:9px; border:solid white; border-width:0 2px 2px 0; transform:rotate(45deg); }
.action-title { flex:1; }
.action-kicker { font-size:9px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); margin-bottom:3px; }
.priority { color:var(--red); font-weight:800; }
.action-title h3 { font-family:ui-serif, Georgia, serif; font-size:21px; line-height:1.25; font-weight:500; margin:0; letter-spacing:-.01em; }
.action-status { font-size:9px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); border:1px solid var(--line); border-radius:99px; padding:3px 7px; white-space:nowrap; }
.action > p { color:var(--muted); font-size:13px; margin:11px 0 8px 31px; }
.action blockquote { margin:0 0 9px 31px; padding:7px 10px; border-left:2px solid #c3c9bd; background:#f2efe7; color:#6f756d; font-size:11px; }
.action ol { margin:8px 0 0 31px; padding-left:17px; color:#44514a; font-size:12px; }
.action ol li { margin:3px 0; }
.action-foot { display:flex; flex-wrap:wrap; gap:10px; justify-content:space-between; align-items:center; margin:13px 0 0 31px; }
.action-tags { display:flex; gap:5px; flex-wrap:wrap; }
.action-tags span { font-size:9px; text-transform:uppercase; letter-spacing:.06em; background:#ece9df; border:1px solid #ddd8ca; border-radius:4px; padding:2px 5px; color:#69746c; }
.action-links .button { color:var(--green); border-color:#b9cabe; background:#eff5ea; }
.action-links .button:hover { background:#e3eedc; }
.action .command-row { margin-left:31px; }
.action.checked { opacity:.68; }
.action.checked .action-title h3 { text-decoration:line-through; }
.channels { margin:0 0 21px; }
.channels-head { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:9px; }
.channels-head h3 { margin:0; font-size:12px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); }
.channels-head span { font-size:10px; color:var(--muted); }
.channel-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }
.channel-card { display:flex; flex-direction:column; gap:4px; background:var(--paper); border:1px solid var(--line); border-radius:10px; padding:12px 14px; text-decoration:none; color:var(--ink); }
.channel-card:hover { border-color:var(--green-2); background:#f6f9f1; }
.channel-kicker { font-size:8px; text-transform:uppercase; letter-spacing:.1em; color:var(--green-2); font-weight:800; }
.channel-card strong { font-size:13px; line-height:1.3; }
.channel-card span:last-child { font-size:10px; color:var(--muted); line-height:1.45; }
.broker-tools { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:9px; }
.table-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:12px; background:var(--paper); }
.broker-table { width:100%; border-collapse:collapse; min-width:760px; font-size:12px; }
.broker-table th { text-align:left; font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); padding:10px 12px; border-bottom:1px solid var(--line); background:#f2efe7; }
.broker-table td { padding:10px 12px; border-bottom:1px solid #e7e2d7; vertical-align:top; }
.broker-table tr:last-child td { border-bottom:0; }
.broker-table tbody tr:hover { background:#f7f4ec; }
.table-sub { display:block; color:var(--muted); font-size:10px; margin-top:2px; }
.table-links { white-space:nowrap; }
.table-links a { margin-right:10px; font-size:11px; }
.broker-help { margin-top:9px; font-size:11px; color:var(--muted); }
.hardening-grid { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
.check-item { display:flex; gap:10px; background:var(--paper); border:1px solid var(--line); border-radius:11px; padding:13px 15px; }
.check-item h3 { font-family:ui-serif, Georgia, serif; font-size:17px; font-weight:500; margin:0 0 3px; line-height:1.25; }
.check-item p { color:var(--muted); font-size:11px; margin:0; }
.check-foot { display:flex; justify-content:space-between; gap:8px; margin-top:7px; font-size:9px; text-transform:uppercase; letter-spacing:.07em; color:#8a928b; }
.check-item:has(input:checked), .check-item.checked { opacity:.55; }
.check-item:has(input:checked) h3, .check-item.checked h3 { text-decoration:line-through; }
.templates { display:flex; flex-direction:column; gap:7px; }
.template { background:var(--paper); border:1px solid var(--line); border-radius:11px; }
.template summary { display:flex; justify-content:space-between; gap:12px; padding:13px 16px; cursor:pointer; list-style:none; align-items:center; }
.template summary::-webkit-details-marker { display:none; }
.template summary strong { display:block; font-size:13px; }
.template summary small { display:block; font-size:10px; color:var(--muted); margin-top:2px; }
.template-arrow { font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--green-2); font-weight:800; }
.template[open] .template-arrow { color:var(--muted); }
.template-body { border-top:1px solid var(--line); padding:14px 16px; }
.template-subject { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:10px; font-size:10px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }
.template-subject code { text-transform:none; letter-spacing:0; background:#ece9df; padding:3px 7px; border-radius:4px; color:var(--ink); font-size:11px; }
.template pre { white-space:pre-wrap; overflow-wrap:anywhere; background:#f2efe7; border:1px solid #e5e0d4; border-radius:8px; padding:14px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:11.5px; line-height:1.65; color:#3f4b44; margin:0 0 10px; }
.method-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:15px; background:var(--paper); border:1px solid var(--line); border-radius:var(--radius); padding:22px; }
.method-grid h3 { font-size:11px; text-transform:uppercase; letter-spacing:.09em; margin:0 0 9px; color:var(--ink); }
.method-grid ul { padding-left:16px; margin:0; color:var(--muted); font-size:11px; line-height:1.6; }
.method-grid li { margin-bottom:5px; }
.metadata { display:flex; flex-direction:column; gap:6px; }
.metadata > div { display:flex; justify-content:space-between; gap:8px; border-bottom:1px solid #e7e2d7; padding-bottom:5px; font-size:10px; }
.metadata span { color:var(--muted); }
.metadata strong { font-weight:650; text-align:right; overflow-wrap:anywhere; }
.runs { margin-top:14px; }
.runs h4 { font-size:9px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin:0 0 5px; }
.runs table { width:100%; border-collapse:collapse; font-size:9px; }
.runs th { text-align:left; color:var(--muted); font-weight:600; border-bottom:1px solid #e7e2d7; padding:2px; }
.runs td { padding:2px; border-bottom:1px solid #efebe1; }
.legal { margin-top:14px; color:var(--muted); font-size:10px; line-height:1.6; max-width:1000px; }
.footer { max-width:1320px; margin:0 auto; padding:20px clamp(18px,4vw,56px) 36px; border-top:1px solid var(--line); display:flex; justify-content:space-between; gap:20px; color:var(--muted); font-size:10px; }
.footer strong { color:var(--ink); margin-right:7px; }
.toast { position:fixed; bottom:20px; left:50%; transform:translate(-50%,20px); background:var(--ink); color:white; border-radius:8px; padding:9px 13px; font-size:11px; opacity:0; pointer-events:none; transition:.2s ease; z-index:100; }
.toast.show { opacity:1; transform:translate(-50%,0); }
.muted { color:var(--muted); }
@media (max-width:1050px) {
  .hero-grid { grid-template-columns:1fr; gap:30px; }
  .score-panel { justify-self:start; flex-direction:row; text-align:left; }
  .score-meta { text-align:left; }
  .overview-grid { grid-template-columns:1fr 1fr; }
  .overview-grid .panel-accent { grid-column:1/-1; }
  .method-grid { grid-template-columns:1fr 1fr; }
  .channel-grid { grid-template-columns:1fr 1fr; }
  .plan-summary { grid-template-columns:1fr; }
  .ticker { grid-template-columns:repeat(3,1fr); }
  .ticker > div:nth-child(3) { border-right:0; }
  .ticker > div:nth-child(4), .ticker > div:nth-child(5) { border-top:1px solid rgba(255,255,255,.1); }
}
@media (max-width:760px) {
  .hero { padding-top:30px; }
  .score-ring { width:150px; }
  .score-value { font-size:48px; }
  .ticker { grid-template-columns:1fr 1fr; }
  .ticker > div { border-right:0; border-top:1px solid rgba(255,255,255,.1); }
  .section-head { display:block; }
  .section-note { text-align:left; margin-top:4px; }
  .overview-grid, .hardening-grid, .method-grid, .channel-grid, .site-grid { grid-template-columns:1fr; }
  .exposed-row { grid-template-columns:1fr; gap:2px; }
  .exposed-meta { text-align:left; }
  .enrich-fields { grid-template-columns:1fr; }
  .finding-detail-grid { grid-template-columns:1fr 1fr; }
  .next-grid { display:block; }
  .next-meta { align-items:flex-start; margin-top:10px; }
  .finding-top { align-items:flex-start; }
  .action-head { gap:8px; }
  .action-status { display:none; }
  .action > p, .action ol, .action-foot, .action .command-row { margin-left:27px; }
  .footer { display:block; }
  .footer > div + div { margin-top:6px; }
}
@media print {
  :root { --bg:white; --paper:white; --shadow:none; }
  body { background:white; font-size:10pt; }
  .hero { background:#0d3b2e !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .hero-actions, .finding-tools, .broker-tools, .copy-button, .toast, .footer, .button { display:none !important; }
  main { max-width:none; padding:0 16pt; }
  .section { break-inside:avoid-page; margin-top:28pt; }
  .finding, .action, .check-item, .template, .panel, .channel-card { break-inside:avoid; box-shadow:none; }
  .finding-details, .template { display:block; }
  details:not([open]) > *:not(summary) { display:block; }
  a { color:inherit; text-decoration:none; }
}
"""
JS = r"""
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const toast = (msg) => {
    const el = $('#toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => el.classList.remove('show'), 1800);
  };

  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    if (button) {
      const old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = old; }, 1200);
    }
    toast('Copied to clipboard');
  }

  $$('[data-copy-text]').forEach((button) => {
    button.addEventListener('click', () => copyText(button.getAttribute('data-copy-text') || '', button));
  });

  const checkKey = 'findmyfootprint.checks.v1';
  let checks = {};
  try { checks = JSON.parse(localStorage.getItem(checkKey) || '{}') || {}; } catch (err) { checks = {}; }
  $$('input[data-check]').forEach((input) => {
    const key = input.getAttribute('data-check');
    if (checks[key]) input.checked = true;
    const parent = input.closest('.action, .check-item');
    if (parent) parent.classList.toggle('checked', input.checked);
    input.addEventListener('change', () => {
      checks[key] = input.checked;
      if (!input.checked) delete checks[key];
      try { localStorage.setItem(checkKey, JSON.stringify(checks)); } catch (err) {}
      if (parent) parent.classList.toggle('checked', input.checked);
      updateHardeningCount();
    });
  });

  function updateHardeningCount() {
    const items = $$('.check-item');
    if (!items.length) return;
    const done = items.filter((item) => item.querySelector('input[data-check]')?.checked).length;
    const el = $('#hardening-count');
    if (el) el.textContent = `${done} of ${items.length} complete`;
  }
  updateHardeningCount();

  const search = $('#finding-search');
  const severity = $('#filter-severity');
  const category = $('#filter-category');
  const status = $('#filter-status');
  const findings = $$('.finding');
  const count = $('#filter-count');
  const noResults = $('#no-results');

  function applyFilters() {
    const q = (search?.value || '').trim().toLowerCase();
    const sev = severity?.value || 'all';
    const cat = category?.value || 'all';
    const stat = status?.value || 'all';
    let shown = 0;
    findings.forEach((el) => {
      const matchesText = !q || (el.dataset.search || '').includes(q);
      const matchesSev = sev === 'all' || el.dataset.severity === sev;
      const matchesCat = cat === 'all' || el.dataset.category === cat;
      const state = el.dataset.status;
      const matchesStat = stat === 'all' || (stat === 'active' ? !['removed', 'false_positive'].includes(state) : state === stat);
      const visible = matchesText && matchesSev && matchesCat && matchesStat;
      el.hidden = !visible;
      if (visible) shown += 1;
    });
    if (count) count.textContent = `${shown} shown`;
    if (noResults) noResults.hidden = shown !== 0;
  }
  [search, severity, category, status].forEach((el) => {
    if (!el) return;
    el.addEventListener('input', applyFilters);
    el.addEventListener('change', applyFilters);
  });
  const clear = $('#clear-filters');
  if (clear) clear.addEventListener('click', () => {
    if (search) search.value = '';
    [severity, category, status].forEach((el) => { if (el) el.value = 'all'; });
    applyFilters();
  });

  const region = $('#filter-region');
  const brokerStatus = $('#filter-broker-status');
  const brokerRows = $$('#broker-table tbody tr');
  function applyBrokerFilters() {
    const r = region?.value || 'all';
    const s = brokerStatus?.value || 'all';
    brokerRows.forEach((row) => {
      const visible = (r === 'all' || (row.dataset.region || '').split(' ').includes(r)) && (s === 'all' || row.dataset.brokerStatus === s);
      row.hidden = !visible;
    });
  }
  [region, brokerStatus].forEach((el) => el && el.addEventListener('change', applyBrokerFilters));

  const download = $('[data-download]');
  if (download) download.addEventListener('click', () => {
    const raw = $('#report-data')?.textContent || '{}';
    const blob = new Blob([raw], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `footprint-report-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
    toast('Data downloaded');
  });
})();
"""
