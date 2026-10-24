"""Turn a profile into a small, deliberate set of public-web searches."""

from __future__ import annotations

import re
from urllib.parse import unquote

from .config import Profile, SearchConfig
from .models import MatchInfo, QueryAnchor, SearchQuery
from .util import (
    domain_of,
    location_city,
    normalize_email,
    normalize_space,
    normalize_text,
    normalize_username,
    phone_digits,
    phone_variants,
)


def _quote(value: str) -> str:
    value = normalize_space(value).replace('"', " ").strip()
    return f'"{value}"'


def _anchor(kind: str, value: str) -> QueryAnchor:
    return QueryAnchor(kind=kind, value=value)


def build_queries(
    profile: Profile,
    search: SearchConfig,
    broker_catalog: list | None = None,
) -> list[SearchQuery]:
    """Build exact-match queries in descending value order.

    A name alone is ambiguous, so it is only one low-confidence query. When
    there is an email, the local part becomes a likely username and the name
    is also searched with it. Phone numbers use several equivalent formats.
    """
    candidates: list[SearchQuery] = []
    names = profile.names
    city = profile.city
    country = profile.country

    for email in profile.emails:
        candidates.append(
            SearchQuery(
                text=_quote(email),
                anchors=[_anchor("email", email)],
                label=f"Email · {email}",
                identifier_type="email",
                priority=10,
                purpose="email",
            )
        )
        for local in profile.email_locals:
            if local == email.split("@", 1)[0].casefold():
                candidates.append(
                    SearchQuery(
                        text=_quote(local),
                        anchors=[_anchor("username", local)],
                        label=f"Email handle · {local}",
                        identifier_type="username",
                        priority=19,
                        purpose="email_handle",
                    )
                )

    for phone in profile.phones:
        variants = [value for value in phone_variants(phone) if value]
        seen_variants: set[str] = set()
        for index, variant in enumerate(variants[:2]):
            key = variant.casefold()
            if key in seen_variants:
                continue
            seen_variants.add(key)
            candidates.append(
                SearchQuery(
                    text=_quote(variant),
                    anchors=[_anchor("phone", phone)],
                    label=f"Phone · {variant}",
                    identifier_type="phone",
                    priority=11 + index,
                    purpose="phone",
                )
            )
        for name in names[:1]:
            if variants:
                candidates.append(
                    SearchQuery(
                        text=f"{_quote(name)} {_quote(variants[0])}",
                        anchors=[_anchor("name", name), _anchor("phone", phone)],
                        label=f"Name + phone · {name}",
                        identifier_type="phone",
                        priority=14,
                        purpose="name_phone",
                    )
                )

    for name in names:
        for email in profile.emails[:2]:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(name)} {_quote(email)}",
                    anchors=[_anchor("name", name), _anchor("email", email)],
                    label=f"Name + email · {name}",
                    identifier_type="name",
                    priority=12,
                    purpose="name_email",
                )
            )
        for local in profile.email_locals[:2]:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(name)} {_quote(local)}",
                    anchors=[_anchor("name", name), _anchor("username", local)],
                    label=f"Name + email handle · {name} / {local}",
                    identifier_type="name",
                    priority=16,
                    purpose="name_handle",
                )
            )
        if city:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(name)} {_quote(city)}",
                    anchors=[_anchor("name", name), _anchor("location", city)],
                    label=f"Name + location · {name} / {city}",
                    identifier_type="name",
                    priority=30,
                    purpose="name_location",
                )
            )
        elif country:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(name)} {_quote(country)}",
                    anchors=[_anchor("name", name), _anchor("location", country)],
                    label=f"Name + country · {name} / {country}",
                    identifier_type="name",
                    priority=35,
                    purpose="name_country",
                )
            )

    for username in profile.all_usernames:
        derived = username not in profile.usernames
        suffix = " (from email)" if derived else ""
        candidates.append(
            SearchQuery(
                text=_quote(username),
                anchors=[_anchor("username", username)],
                label=f"Username · @{normalize_username(username)}{suffix}",
                identifier_type="username",
                priority=21 if derived else 20,
                purpose="username",
            )
        )
        if names:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(username)} {_quote(names[0])}",
                    anchors=[_anchor("username", username), _anchor("name", names[0])],
                    label=f"Username + name · @{normalize_username(username)}",
                    identifier_type="username",
                    priority=24 if derived else 22,
                    purpose="username_name",
                )
            )

    for address in profile.addresses:
        candidates.append(
            SearchQuery(
                text=_quote(address),
                anchors=[_anchor("address", address)],
                label=f"Address · {address}",
                identifier_type="address",
                priority=17,
                purpose="address",
            )
        )
        if names:
            candidates.append(
                SearchQuery(
                    text=f"{_quote(names[0])} {_quote(address)}",
                    anchors=[_anchor("name", names[0]), _anchor("address", address)],
                    label=f"Name + address · {names[0]}",
                    identifier_type="address",
                    priority=18,
                    purpose="name_address",
                )
            )

    for domain in profile.domain_names:
        candidates.append(
            SearchQuery(
                text=_quote(domain),
                anchors=[_anchor("domain", domain)],
                label=f"Website · {domain}",
                identifier_type="domain",
                priority=45,
                purpose="domain",
            )
        )

    # Broad name search: low confidence, but essential when the email is not
    # visible on the page. Kept last so stronger identifiers fill the budget.
    if search.broad_name and names:
        candidates.append(
            SearchQuery(
                text=_quote(names[0]),
                anchors=[_anchor("name", names[0])],
                label=f"Name · {names[0]} (broad)",
                identifier_type="name",
                priority=65,
                purpose="name_only",
            )
        )

    # Platform-specific probes surface profiles that a generic result page
    # may rank below news, directories, and unrelated namesakes.
    if search.platform_probes and names and search.platform_probe_count:
        context = city or country
        platforms = [
            ("linkedin.com", "LinkedIn"),
            ("facebook.com", "Facebook"),
            ("instagram.com", "Instagram"),
            ("github.com", "GitHub"),
            ("reddit.com", "Reddit"),
            ("x.com", "X / Twitter"),
        ]
        for domain, label in platforms[: search.platform_probe_count]:
            text = f"site:{domain} {_quote(names[0])}"
            anchors = [_anchor("name", names[0])]
            if context:
                text += f" {_quote(context)}"
                anchors.append(_anchor("location", context))
            candidates.append(
                SearchQuery(
                    text=text,
                    anchors=anchors,
                    label=f"{label} probe · {names[0]}",
                    identifier_type="name",
                    priority=50,
                    purpose="platform_probe",
                )
            )

    if search.broker_probes and broker_catalog:
        context = city or (profile.addresses[0] if profile.addresses else "")
        probes = 0
        for broker in broker_catalog:
            if probes >= search.broker_probe_count:
                break
            domains = getattr(broker, "domains", None)
            if domains is None and isinstance(broker, dict):
                domains = broker.get("domains") or []
            if not domains:
                continue
            domain = str(domains[0])
            broker_name = getattr(broker, "name", None)
            if broker_name is None and isinstance(broker, dict):
                broker_name = broker.get("name", domain)
            if names and context:
                context_kind = "location" if city else "address"
                candidates.append(
                    SearchQuery(
                        text=f"site:{domain} {_quote(names[0])} {_quote(context)}",
                        anchors=[_anchor("name", names[0]), _anchor(context_kind, context)],
                        label=f"Broker probe · {broker_name or domain}",
                        identifier_type="name",
                        priority=55,
                        purpose="broker_probe",
                    )
                )
                probes += 1
            elif not names and profile.phones:
                phone = profile.phones[0]
                variants = phone_variants(phone)
                if variants:
                    candidates.append(
                        SearchQuery(
                            text=f"site:{domain} {_quote(variants[0])}",
                            anchors=[_anchor("phone", phone)],
                            label=f"Phone broker probe · {broker_name or domain}",
                            identifier_type="phone",
                            priority=56,
                            purpose="broker_probe",
                        )
                    )
                    probes += 1

    deduped: dict[str, SearchQuery] = {}
    for query in candidates:
        key = query.text.casefold()
        if key not in deduped:
            deduped[key] = query
    ordered = sorted(deduped.values(), key=lambda item: (item.priority, item.text))
    return ordered[: search.max_queries]

def _token_in_text(token: str, text: str) -> bool:
    token = normalize_text(token)
    if not token:
        return False
    return re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", text) is not None


def anchor_matches(anchor: QueryAnchor, title: str, snippet: str, url: str) -> list[str]:
    """Return the fields where an anchor is visible, or an empty list."""
    text = normalize_text(f"{title} {snippet}")
    raw_text = f"{title} {snippet}"
    decoded_url = unquote(url or "")
    url_norm = normalize_text(decoded_url)
    found: list[str] = []
    if anchor.kind == "email":
        email = normalize_email(anchor.value)
        if email and email in raw_text.casefold():
            found.append("text")
        elif email and email in decoded_url.casefold():
            found.append("url")
    elif anchor.kind == "phone":
        digits = phone_digits(anchor.value)
        if len(digits) >= 7:
            suffix = digits[-9:]
            for label, haystack in (("text", raw_text), ("url", decoded_url)):
                for sequence in re.findall(r"[\d][\d\s().+-]{6,}\d", haystack):
                    if phone_digits(sequence).endswith(suffix):
                        found.append(label)
                        break
    elif anchor.kind == "username":
        username = normalize_username(anchor.value)
        if username:
            pattern = r"(?<![a-z0-9_.-])@?" + re.escape(username) + r"(?![a-z0-9_.-])"
            if re.search(pattern, raw_text, re.I):
                found.append("text")
            if username in url_norm:
                found.append("url")
    elif anchor.kind in {"name", "location", "address"}:
        tokens = [token for token in normalize_text(anchor.value).split(" ") if token]
        if tokens and all(_token_in_text(token, text) for token in tokens):
            found.append("text")
        if anchor.kind == "name" and len(tokens) > 1:
            phrase = " ".join(tokens)
            if phrase in url_norm:
                found.append("url")
    elif anchor.kind == "domain":
        domain = anchor.value.casefold()
        if domain and domain_of(url) and (
            domain_of(url) == domain or domain_of(url).endswith("." + domain)
        ):
            found.append("url")
    return sorted(set(found))


def match_query(query: SearchQuery, title: str, snippet: str, url: str) -> MatchInfo | None:
    """Require every anchor to be present. Query echoes alone are not a match."""
    matched: list[str] = []
    where: set[str] = set()
    for anchor in query.anchors:
        locations = anchor_matches(anchor, title, snippet, url)
        if not locations:
            return None
        matched.append(f"{anchor.kind}:{anchor.value}")
        where.update(locations)
    if not matched:
        return None

    confidence = 0.56
    if "text" in where:
        confidence += 0.24
    if "url" in where:
        confidence += 0.08
    if query.purpose in {"email", "phone", "name_email", "name_address"} and "text" in where:
        confidence = max(confidence, 0.9)
    if query.purpose == "broker_probe":
        confidence = max(confidence, 0.82)
    if query.purpose in {"name_location", "username_name"}:
        confidence = min(confidence, 0.82)
    if query.purpose == "name_country":
        confidence = min(confidence, 0.62)
    if query.purpose == "platform_probe":
        confidence = min(confidence, 0.58)
    if query.purpose == "name_only":
        confidence = min(confidence, 0.46)
    if query.purpose == "broker_probe" and len(query.anchors) == 1:
        confidence = min(confidence, 0.5)
    return MatchInfo(matched=matched, confidence=round(min(confidence, 0.98), 2), where=sorted(where))


def plan_summary(queries: list[SearchQuery]) -> list[dict[str, str]]:
    return [
        {
            "label": query.label,
            "query": query.text,
            "purpose": query.purpose,
            "identifier_type": query.identifier_type,
        }
        for query in queries
    ]


def location_for_query(profile: Profile) -> str:
    return location_city(profile.locations[0]) if profile.locations else ""
