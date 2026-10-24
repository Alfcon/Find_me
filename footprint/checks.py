"""Public profile, breach, and domain-registration checks."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote

from bs4 import BeautifulSoup

from .config import AppConfig
from .http import HttpClient, HttpError, friendly_http_error
from .models import Finding
from .util import (
    compact,
    fingerprint as make_fingerprint,
    normalize_email,
    normalize_space,
    normalize_text,
    normalize_username,
)


@dataclass
class CheckOutcome:
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    checks_skipped: int = 0
    errors: int = 0
    notes: list[tuple[str, str, str]] = field(default_factory=list)

    def note(self, kind: str, message: str, level: str = "info") -> None:
        self.notes.append((kind, message, level))

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


class CheckRunner:
    def __init__(
        self,
        config: AppConfig,
        http: HttpClient,
        *,
        on_check: Callable[[str], None] | None = None,
    ):
        self.config = config
        self.profile = config.profile
        self.http = http
        self.keys = config.api_keys
        self.checks = config.checks
        self.outcome = CheckOutcome()
        self.on_check = on_check

    def run(self) -> CheckOutcome:
        self._safe("gravatar", self._gravatar, self.checks.gravatar and bool(self.profile.emails))
        self._safe("github", self._github, self.checks.github and bool(self.profile.all_usernames))
        self._safe(
            "github_search",
            self._github_search,
            self.checks.github_search and bool(self.profile.names or self.profile.emails),
        )
        self._safe("gitlab", self._gitlab, self.checks.gitlab and bool(self.profile.all_usernames))
        self._safe("reddit", self._reddit, self.checks.reddit and bool(self.profile.all_usernames))
        self._safe("keybase", self._keybase, self.checks.keybase and bool(self.profile.all_usernames))
        self._safe("bluesky", self._bluesky, self.checks.bluesky and bool(self.profile.all_usernames))
        self._safe("mastodon", self._mastodon, self.checks.mastodon and bool(self.profile.names))
        self._safe("npm", self._npm, self.checks.npm and bool(self.profile.all_usernames))
        self._safe("rdap", self._rdap, self.checks.rdap and bool(self.profile.domain_names))
        self._safe("abn", self._abn, self.checks.abn and bool(self.profile.names and "australia" in self.profile.country.casefold()))
        if self.checks.github_commits:
            self._safe(
                "github_commits",
                self._github_commits,
                bool(self.profile.emails),
            )
        if self.checks.openpgp:
            self._safe("openpgp", self._openpgp, bool(self.profile.emails))
        if self.checks.hudsonrock:
            self._safe("hudsonrock", self._hudsonrock, bool(self.profile.emails))
        if self.checks.breaches:
            if self.keys.get("hibp"):
                self._safe("breaches", self._breaches, bool(self.profile.emails))
            elif self.checks.xposedornot:
                self._safe("xposedornot", self._xposedornot, bool(self.profile.emails))
                self.outcome.note(
                    "xposedornot",
                    "Breach data came from the free XposedOrNot index because HIBP_API_KEY is not set. "
                    "Set an HIBP key for the more established Have I Been Pwned dataset.",
                    "info",
                )
            else:
                self.outcome.checks_skipped += 1
                self.outcome.note(
                    "breaches",
                    "Breach check skipped: set HIBP_API_KEY or enable checks.xposedornot.",
                    "info",
                )
        return self.outcome

    # ------------------------------------------------------------------
    # Orchestration helpers
    # ------------------------------------------------------------------
    def _safe(self, name: str, function: Callable[[], None], enabled: bool) -> None:
        if not enabled:
            self.outcome.checks_skipped += 1
            return
        if self.on_check:
            self.on_check(name)
        try:
            function()
        except HttpError as exc:
            self.outcome.errors += 1
            self.outcome.note(name, friendly_http_error(exc), "error")
        except Exception as exc:  # keep one failing provider from stopping a scan
            self.outcome.errors += 1
            self.outcome.note(name, f"{type(exc).__name__}: {compact(str(exc), 200)}", "error")

    def _json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        ttl: int = 12 * 3600,
    ) -> tuple[int, Any]:
        self.outcome.checks_run += 1
        return self.http.get_json(url, headers=headers, ttl=ttl)

    def _identity_confidence(self, public_name: str = "", public_email: str = "") -> tuple[float, str]:
        if public_email and normalize_email(public_email) in {normalize_email(e) for e in self.profile.emails}:
            return 0.97, "public email matches your profile exactly"
        if public_name and self.profile.display_name:
            wanted = set(normalize_text(self.profile.display_name).split())
            actual = set(normalize_text(public_name).split())
            if wanted and wanted.issubset(actual):
                return 0.9, "public name matches your profile"
            if actual and wanted and len(wanted & actual) >= max(1, len(wanted) // 2):
                return 0.68, "part of the public name matches"
            return 0.45, "public name does not match your profile — verify ownership before acting"
        return 0.6, "username match only — verify ownership before acting"

    # ------------------------------------------------------------------
    # Gravatar
    # ------------------------------------------------------------------
    def _gravatar(self) -> None:
        for email in self.profile.emails:
            digest = hashlib.md5(normalize_email(email).encode("utf-8")).hexdigest()
            status, payload = self._json(
                f"https://gravatar.com/{digest}.json",
                headers={"Accept": "application/json"},
                ttl=24 * 3600,
            )
            if status == 404:
                continue
            if status != 200 or not payload:
                continue
            entries = payload.get("entry") if isinstance(payload, dict) else None
            entry = entries[0] if isinstance(entries, list) and entries else {}
            if not isinstance(entry, dict):
                continue
            display_name = str(entry.get("displayName") or entry.get("preferredUsername") or "")
            about = str(entry.get("aboutMe") or "")
            location = str(entry.get("currentLocation") or "")
            urls = entry.get("urls") or []
            url_values = []
            for item in urls if isinstance(urls, list) else []:
                if isinstance(item, dict) and item.get("value"):
                    url_values.append(str(item["value"]))
            profile_url = f"https://gravatar.com/{digest}"
            if entry.get("preferredUsername"):
                profile_url = f"https://gravatar.com/{entry['preferredUsername']}"
            snippet_bits = [bit for bit in [display_name, location, about] if bit]
            if url_values:
                snippet_bits.append("Links: " + ", ".join(url_values[:4]))
            confidence, reason = self._identity_confidence(display_name, email)
            severity = "medium" if (about or url_values or location) else "low"
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="social",
                    source="Gravatar",
                    title=f"Gravatar profile for {email}",
                    url=profile_url,
                    snippet=compact(" · ".join(snippet_bits), 400) or "A public Gravatar profile exists.",
                    identifier=email,
                    identifier_type="email",
                    severity=severity,
                    confidence=confidence,
                    matched=f"email:{email}",
                    details={
                        "provider": "gravatar",
                        "display_name": display_name,
                        "location": location,
                        "about": compact(about, 800),
                        "links": url_values,
                        "reason": reason,
                        "hashes_email": True,
                    },
                )
            )
            self.outcome.note("gravatar", f"Found a public Gravatar profile for {email}", "finding")

    # ------------------------------------------------------------------
    # Developer and social APIs
    # ------------------------------------------------------------------
    def _github(self) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.keys.get("github"):
            headers["Authorization"] = f"Bearer {self.keys['github']}"
        for username in self.profile.all_usernames:
            status, payload = self._json(
                f"https://api.github.com/users/{quote(username)}", headers=headers, ttl=6 * 3600
            )
            if status == 404:
                continue
            if status == 403:
                self.outcome.note(
                    "github",
                    "GitHub API rate limit reached. Set GITHUB_TOKEN to raise the limit.",
                    "warning",
                )
                return
            if status != 200 or not isinstance(payload, dict):
                continue
            public_email = str(payload.get("email") or "")
            public_name = str(payload.get("name") or "")
            confidence, reason = self._identity_confidence(public_name, public_email)
            bits = [
                value
                for value in [
                    public_name,
                    payload.get("bio"),
                    payload.get("company"),
                    payload.get("location"),
                    public_email,
                ]
                if value
            ]
            severity = "medium" if public_email else "low"
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="code",
                    source="GitHub",
                    title=f"GitHub profile: @{payload.get('login') or username}",
                    url=str(payload.get("html_url") or f"https://github.com/{username}"),
                    snippet=compact(" · ".join(str(value) for value in bits), 400)
                    or "Public GitHub profile.",
                    identifier=username,
                    identifier_type="username",
                    severity=severity,
                    confidence=confidence,
                    matched=f"username:{username}",
                    details={
                        "provider": "github",
                        "login": payload.get("login"),
                        "public_name": public_name,
                        "public_email": public_email,
                        "company": payload.get("company"),
                        "location": payload.get("location"),
                        "blog": payload.get("blog"),
                        "twitter_username": payload.get("twitter_username"),
                        "public_repos": payload.get("public_repos"),
                        "created_at": payload.get("created_at"),
                        "reason": reason,
                    },
                )
            )

    def _github_search(self) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.keys.get("github"):
            headers["Authorization"] = f"Bearer {self.keys['github']}"
        queries: list[tuple[str, str]] = []
        if self.profile.names:
            queries.append((f"{self.profile.names[0]} in:name", "name"))
        if self.profile.emails:
            queries.append((f"{self.profile.emails[0]} in:email", "email"))
        seen: set[str] = set()
        for query, method in queries:
            status, payload = self._json(
                f"https://api.github.com/search/users?q={quote(query, safe='')}&per_page=5",
                headers=headers,
                ttl=6 * 3600,
            )
            if status == 403:
                self.outcome.note(
                    "github_search",
                    "GitHub user search hit a rate limit; set GITHUB_TOKEN to raise it.",
                    "warning",
                )
                return
            if status != 200 or not isinstance(payload, dict):
                continue
            for item in (payload.get("items") or [])[:5]:
                if not isinstance(item, dict):
                    continue
                login = str(item.get("login") or "")
                if not login or login.casefold() in seen:
                    continue
                seen.add(login.casefold())
                user_status, user = self._json(
                    f"https://api.github.com/users/{quote(login, safe='')}",
                    headers=headers,
                    ttl=6 * 3600,
                )
                if user_status != 200 or not isinstance(user, dict):
                    continue
                public_name = str(user.get("name") or "")
                public_email = str(user.get("email") or "")
                name_match = bool(
                    self.profile.display_name
                    and normalize_text(public_name) == normalize_text(self.profile.display_name)
                )
                email_match = bool(
                    public_email
                    and normalize_email(public_email) in {normalize_email(item) for item in self.profile.emails}
                )
                if not (name_match or email_match):
                    continue
                confidence, reason = self._identity_confidence(public_name, public_email)
                bits = [
                    value
                    for value in [
                        public_name,
                        user.get("bio"),
                        user.get("company"),
                        user.get("location"),
                        public_email,
                    ]
                    if value
                ]
                self.outcome.add(
                    Finding(
                        kind="profile",
                        category="code",
                        source="GitHub user search",
                        title=f"GitHub profile found by {method}: @{login}",
                        url=str(user.get("html_url") or f"https://github.com/{login}"),
                        snippet=compact(" · ".join(str(value) for value in bits), 400)
                        or "Public GitHub profile.",
                        identifier=login,
                        identifier_type="username",
                        severity="medium" if public_email else "low",
                        confidence=max(confidence, 0.9),
                        matched=f"github_{method}:{login}",
                        details={
                            "provider": "github_search",
                            "login": login,
                            "public_name": public_name,
                            "public_email": public_email,
                            "company": user.get("company"),
                            "location": user.get("location"),
                            "blog": user.get("blog"),
                            "public_repos": user.get("public_repos"),
                            "created_at": user.get("created_at"),
                            "search_query": query,
                            "reason": reason,
                        },
                    )
                )
                self.outcome.note(
                    "github_search",
                    f"Found a likely GitHub profile by {method}: @{login}",
                    "finding",
                )

    def _gitlab(self) -> None:
        for username in self.profile.all_usernames:
            status, payload = self._json(
                f"https://gitlab.com/api/v4/users?username={quote(username)}",
                headers={"Accept": "application/json"},
                ttl=6 * 3600,
            )
            if status != 200 or not isinstance(payload, list) or not payload:
                continue
            for user in payload[:3]:
                if not isinstance(user, dict):
                    continue
                if normalize_username(str(user.get("username") or "")) != username:
                    continue
                public_email = str(user.get("public_email") or "")
                public_name = str(user.get("name") or "")
                confidence, reason = self._identity_confidence(public_name, public_email)
                bits = [
                    value
                    for value in [public_name, user.get("bio"), user.get("organization"), user.get("location"), public_email]
                    if value
                ]
                self.outcome.add(
                    Finding(
                        kind="profile",
                        category="code",
                        source="GitLab",
                        title=f"GitLab profile: @{user.get('username')}",
                        url=str(user.get("web_url") or f"https://gitlab.com/{username}"),
                        snippet=compact(" · ".join(str(value) for value in bits), 400)
                        or "Public GitLab profile.",
                        identifier=username,
                        identifier_type="username",
                        severity="medium" if public_email else "low",
                        confidence=confidence,
                        matched=f"username:{username}",
                        details={
                            "provider": "gitlab",
                            "public_name": public_name,
                            "public_email": public_email,
                            "reason": reason,
                        },
                    )
                )

    def _reddit(self) -> None:
        headers = {"User-Agent": "FindMyFootprint/1.0 (personal privacy self-audit)"}
        for username in self.profile.all_usernames:
            try:
                status, payload = self._json(
                    f"https://www.reddit.com/user/{quote(username)}/about.json",
                    headers=headers,
                    ttl=6 * 3600,
                )
            except HttpError as exc:
                if "invalid JSON" in str(exc):
                    self.outcome.note(
                        "reddit",
                        "Reddit returned a bot-protection page instead of JSON; skipped.",
                        "warning",
                    )
                    return
                raise
            if status == 403:
                self.outcome.note("reddit", "Reddit blocked the public profile lookup (HTTP 403).", "warning")
                return
            if status != 200 or not isinstance(payload, dict):
                continue
            data = payload.get("data")
            if not isinstance(data, dict) or not data.get("name"):
                continue
            if normalize_username(str(data.get("name"))) != username:
                continue
            description = str(data.get("public_description") or "")
            bits = [
                value
                for value in [
                    data.get("subreddit", {}).get("title") if isinstance(data.get("subreddit"), dict) else "",
                    description,
                    f"{data.get('link_karma', 0)} post karma",
                    f"{data.get('comment_karma', 0)} comment karma",
                ]
                if value
            ]
            confidence, reason = self._identity_confidence("", "")
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="social",
                    source="Reddit",
                    title=f"Reddit profile: u/{data.get('name')}",
                    url=f"https://www.reddit.com/user/{data.get('name')}/",
                    snippet=compact(" · ".join(str(value) for value in bits), 400)
                    or "Public Reddit profile.",
                    identifier=username,
                    identifier_type="username",
                    severity="low",
                    confidence=confidence,
                    matched=f"username:{username}",
                    details={
                        "provider": "reddit",
                        "created_utc": data.get("created_utc"),
                        "link_karma": data.get("link_karma"),
                        "comment_karma": data.get("comment_karma"),
                        "reason": reason,
                    },
                )
            )

    def _keybase(self) -> None:
        for username in self.profile.all_usernames:
            status, payload = self._json(
                f"https://keybase.io/_/api/1.0/user/lookup.json?username={quote(username)}&fields=basics,profile,proofs_summary",
                headers={"Accept": "application/json"},
                ttl=12 * 3600,
            )
            if status != 200 or not isinstance(payload, dict) or payload.get("status", {}).get("code") != 0:
                continue
            them = payload.get("them") or []
            if isinstance(them, dict):
                them = [them]
            if not isinstance(them, list) or not them or not isinstance(them[0], dict):
                continue
            profile = them[0].get("profile") or {}
            basics = them[0].get("basics") or {}
            public_name = str(profile.get("full_name") or "")
            bits = [
                value
                for value in [
                    public_name,
                    profile.get("location"),
                    profile.get("bio"),
                    profile.get("website"),
                ]
                if value
            ]
            confidence, reason = self._identity_confidence(public_name, "")
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="social",
                    source="Keybase",
                    title=f"Keybase profile: @{basics.get('username') or username}",
                    url=f"https://keybase.io/{basics.get('username') or username}",
                    snippet=compact(" · ".join(str(value) for value in bits), 400)
                    or "Public Keybase profile.",
                    identifier=username,
                    identifier_type="username",
                    severity="low",
                    confidence=confidence,
                    matched=f"username:{username}",
                    details={"provider": "keybase", "reason": reason},
                )
            )

    def _bluesky(self) -> None:
        for username in self.profile.all_usernames:
            status, payload = self._json(
                f"https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q={quote(username)}&limit=10",
                headers={"Accept": "application/json"},
                ttl=6 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            actors = payload.get("actors") or []
            if not isinstance(actors, list):
                continue
            added = 0
            for actor in actors:
                if not isinstance(actor, dict):
                    continue
                handle = str(actor.get("handle") or "")
                if username not in handle.casefold() and normalize_username(handle.split(".")[0]) != username:
                    continue
                public_name = str(actor.get("displayName") or "")
                confidence, reason = self._identity_confidence(public_name, "")
                self.outcome.add(
                    Finding(
                        kind="profile",
                        category="social",
                        source="Bluesky",
                        title=f"Bluesky profile: @{handle}",
                        url=f"https://bsky.app/profile/{handle}",
                        snippet=compact(
                            " · ".join(
                                value for value in [public_name, actor.get("description")] if value
                            ),
                            400,
                        )
                        or "Public Bluesky profile.",
                        identifier=username,
                        identifier_type="username",
                        severity="low",
                        confidence=confidence,
                        matched=f"username:{username}",
                        details={"provider": "bluesky", "handle": handle, "reason": reason},
                    )
                )
                added += 1
                if added >= 3:
                    break

    def _mastodon(self) -> None:
        for name in self.profile.names[:1]:
            status, payload = self._json(
                f"https://mastodon.social/api/v2/search?q={quote(name, safe='')}&type=accounts&limit=10",
                headers={"Accept": "application/json"},
                ttl=6 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            added = 0
            for account in payload.get("accounts") or []:
                if not isinstance(account, dict):
                    continue
                display_name = str(account.get("display_name") or "")
                if normalize_text(display_name) != normalize_text(name):
                    continue
                acct = str(account.get("acct") or account.get("username") or "")
                if not acct:
                    continue
                note = BeautifulSoup(str(account.get("note") or ""), "html.parser").get_text(" ", strip=True)
                self.outcome.add(
                    Finding(
                        kind="profile",
                        category="social",
                        source="Mastodon",
                        title=f"Mastodon profile: @{acct}",
                        url=str(account.get("url") or f"https://mastodon.social/@{acct}"),
                        snippet=compact(
                            " · ".join(
                                str(value)
                                for value in [display_name, note, account.get("created_at")]
                                if value
                            ),
                            400,
                        )
                        or "Public Mastodon profile.",
                        identifier=acct,
                        identifier_type="username",
                        severity="low",
                        confidence=0.7,
                        matched=f"mastodon:{acct}",
                        details={
                            "provider": "mastodon",
                            "display_name": display_name,
                            "reason": "Exact display-name match on a federated Mastodon instance",
                        },
                    )
                )
                added += 1
                if added >= 3:
                    break

    def _npm(self) -> None:
        for username in self.profile.all_usernames:
            status, payload = self._json(
                f"https://registry.npmjs.org/-/v1/search?text=maintainer:{quote(username)}&size=10",
                headers={"Accept": "application/json"},
                ttl=12 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            total = int(payload.get("total") or 0)
            if total <= 0:
                continue
            objects = payload.get("objects") or []
            names = []
            for item in objects[:6]:
                package = item.get("package") if isinstance(item, dict) else None
                if isinstance(package, dict) and package.get("name"):
                    names.append(str(package["name"]))
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="code",
                    source="npm",
                    title=f"npm maintainer: {username}",
                    url=f"https://www.npmjs.com/~{username}",
                    snippet=compact(
                        f"{total} package(s) publicly linked to this maintainer"
                        + (": " + ", ".join(names) if names else ""),
                        400,
                    ),
                    identifier=username,
                    identifier_type="username",
                    severity="low",
                    confidence=0.55,
                    matched=f"username:{username}",
                    details={
                        "provider": "npm",
                        "package_count": total,
                        "sample_packages": names,
                        "reason": "maintainer match only — verify ownership",
                    },
                )
            )

    def _github_commits(self) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.keys.get("github"):
            headers["Authorization"] = f"Bearer {self.keys['github']}"
        for email in self.profile.emails:
            query = f"author-email:{email}"
            status, payload = self._json(
                f"https://api.github.com/search/commits?q={quote(query, safe='')}"
                "&per_page=5&sort=author-date&order=desc",
                headers=headers,
                ttl=6 * 3600,
            )
            if status == 422:
                self.outcome.note("github_commits", "GitHub rejected the commit-search query.", "warning")
                continue
            if status == 403:
                self.outcome.note(
                    "github_commits",
                    "GitHub commit search hit a rate limit; set GITHUB_TOKEN to raise it.",
                    "warning",
                )
                return
            if status != 200 or not isinstance(payload, dict):
                continue
            total = int(payload.get("total_count") or 0)
            items = payload.get("items") or []
            exact = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                author = ((item.get("commit") or {}).get("author") or {})
                if normalize_email(str(author.get("email") or "")) == normalize_email(email):
                    exact.append(item)
            if total <= 0 and not exact:
                continue
            repositories = []
            samples = []
            for item in exact:
                repo = (item.get("repository") or {}).get("full_name") or ""
                commit = item.get("commit") or {}
                if repo:
                    repositories.append(repo)
                samples.append(
                    {
                        "repository": repo,
                        "url": item.get("html_url", ""),
                        "message": compact(str(commit.get("message") or ""), 180),
                        "date": (commit.get("author") or {}).get("date", ""),
                    }
                )
            repositories = list(dict.fromkeys(repositories))
            self.outcome.add(
                Finding(
                    kind="profile",
                    category="code",
                    source="GitHub commit search",
                    title=f"Email appears in {total:,} public GitHub commit(s)",
                    url=f"https://github.com/search?q=author-email%3A{quote(email, safe='')}&type=commits",
                    snippet=compact(
                        "Public commits by this email"
                        + (f" in {', '.join(repositories[:5])}" if repositories else "")
                        + (f" (showing {len(samples)} of {total:,})" if total else ""),
                        400,
                    ),
                    identifier=email,
                    identifier_type="email",
                    severity="medium",
                    confidence=0.96,
                    matched=f"email:{email}",
                    fingerprint=make_fingerprint("github-commits", normalize_email(email)),
                    details={
                        "provider": "github_commits",
                        "total_count": total,
                        "repositories": repositories[:20],
                        "samples": samples[:5],
                        "reason": "Git commit author email is public",
                    },
                )
            )
            self.outcome.note(
                "github_commits",
                f"Found {total:,} public GitHub commit(s) associated with the email.",
                "finding",
            )

    def _openpgp(self) -> None:
        for email in self.profile.emails:
            self.outcome.checks_run += 1
            response = self.http.get(
                f"https://keys.openpgp.org/vks/v1/by-email/{quote(email, safe='')}",
                headers={"Accept": "application/pgp-keys, text/plain"},
                ttl=24 * 3600,
            )
            if response.status == 404:
                continue
            if response.status == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in response.text:
                self.outcome.add(
                    Finding(
                        kind="profile",
                        category="other",
                        source="keys.openpgp.org",
                        title=f"Public OpenPGP key for {email}",
                        url=f"https://keys.openpgp.org/search?q={quote(email, safe='')}",
                        snippet="A public OpenPGP key is published for this email address; key UIDs can include a name and comments.",
                        identifier=email,
                        identifier_type="email",
                        severity="low",
                        confidence=0.95,
                        matched=f"email:{email}",
                        fingerprint=make_fingerprint("openpgp", normalize_email(email)),
                        details={"provider": "openpgp", "reason": "Public key lookup by email"},
                    )
                )

    def _xposedornot(self) -> None:
        for email in self.profile.emails:
            status, payload = self._json(
                f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email, safe='')}",
                headers={"Accept": "application/json"},
                ttl=12 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            summary = payload.get("BreachesSummary") or {}
            names = []
            site_value = str(summary.get("site") or "")
            if site_value:
                names.extend(part.strip() for part in site_value.split(";") if part.strip())
            exposed = payload.get("ExposedBreaches") or {}
            breaches = exposed.get("breaches_details") if isinstance(exposed, dict) else None
            breach_details = []
            exposed_data: list[str] = []
            password_risk = False
            for breach in breaches or []:
                if not isinstance(breach, dict):
                    continue
                name = str(breach.get("breach") or "").strip()
                if name and name not in names:
                    names.append(name)
                data = [part.strip() for part in str(breach.get("xposed_data") or "").split(";") if part.strip()]
                exposed_data.extend(data)
                risk = str(breach.get("password_risk") or "").casefold()
                if "password" in {part.casefold() for part in data} or risk not in {"", "unknown"}:
                    password_risk = True
                breach_details.append(
                    {
                        "breach": name,
                        "date": breach.get("xposed_date"),
                        "records": breach.get("xposed_records"),
                        "data": data,
                        "password_risk": risk,
                        "domain": breach.get("domain"),
                    }
                )
            names = list(dict.fromkeys(name for name in names if name))
            if not names and not breach_details:
                continue
            exposed_data = list(dict.fromkeys(exposed_data))
            severity = "critical" if password_risk or any(
                "password" in value.casefold() for value in exposed_data
            ) else "high"
            count = len(names) or len(breach_details)
            self.outcome.add(
                Finding(
                    kind="breach",
                    category="breach",
                    source="XposedOrNot",
                    title=f"Email exposed in {count} known breach{'es' if count != 1 else ''}",
                    url="https://xposedornot.com/",
                    snippet=compact(
                        "Breaches: "
                        + ", ".join(names[:10])
                        + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
                        + (". Exposed data: " + ", ".join(exposed_data[:10]) if exposed_data else ""),
                        400,
                    ),
                    identifier=email,
                    identifier_type="email",
                    severity=severity,
                    confidence=0.95,
                    matched=f"email:{email}",
                    fingerprint=make_fingerprint("xposedornot", normalize_email(email)),
                    details={
                        "provider": "xposedornot",
                        "breach_count": count,
                        "breaches": breach_details[:30],
                        "exposed_data": exposed_data[:30],
                        "password_risk": password_risk,
                        "reason": "Free third-party breach index; HIBP is preferred when configured",
                        "reasons": [
                            "Email appears in the free XposedOrNot breach index",
                            "Exposed data includes passwords"
                            if severity == "critical"
                            else "Email was exposed in a breach",
                        ],
                    },
                )
            )
            self.outcome.note(
                "xposedornot",
                f"Found {count} breach record(s) in the free XposedOrNot index.",
                "finding",
            )

    # ------------------------------------------------------------------
    # Domain registration
    # ------------------------------------------------------------------
    def _abn(self) -> None:
        name = self.profile.display_name
        if not name:
            return
        self.outcome.checks_run += 1
        response = self.http.get(
            "https://abr.business.gov.au/Search/ResultsActive",
            params={"SearchText": name},
            headers={"Accept": "text/html,application/xhtml+xml"},
            ttl=24 * 3600,
        )
        if response.status != 200:
            return
        soup = BeautifulSoup(response.text, "html.parser")
        for row in soup.select("table tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.select("td")]
            if len(cells) < 4:
                continue
            abn_text, entity_name, entity_type, location = cells[:4]
            if normalize_text(entity_name) != normalize_text(name):
                continue
            digits = re.sub(r"\D", "", abn_text)
            if len(digits) < 11:
                continue
            abn = digits[:11]
            self.outcome.add(
                Finding(
                    kind="public_record",
                    category="public_record",
                    source="ABN Lookup",
                    title=f"ABN record: {entity_name}",
                    url=f"https://abr.business.gov.au/ABN/View?abn={abn}",
                    snippet=compact(f"{entity_type} · {location} · ABN {abn[:2]} {abn[2:5]} {abn[5:8]} {abn[8:]}", 300),
                    identifier=abn,
                    identifier_type="abn",
                    severity="medium",
                    confidence=0.96,
                    matched=f"name:{name}",
                    fingerprint=make_fingerprint("abn", abn),
                    details={
                        "provider": "abn_lookup",
                        "abn": abn,
                        "entity_name": entity_name,
                        "entity_type": entity_type,
                        "location": normalize_space(location),
                        "reason": "Exact name match in the public Australian Business Register",
                        "data_points": [
                            {
                                "kind": "name",
                                "label": "Name",
                                "value": entity_name,
                                "evidence": "Exact name match in ABN Lookup",
                                "confidence": 0.95,
                                "source": "ABN Lookup",
                                "observed": True,
                            },
                            {
                                "kind": "business",
                                "label": "Registered business / entity",
                                "value": entity_name,
                                "evidence": f"ABN {abn}",
                                "confidence": 0.8,
                                "source": "ABN Lookup",
                                "observed": True,
                            },
                            {
                                "kind": "location",
                                "label": "Location",
                                "value": normalize_space(location),
                                "evidence": "ABN registration locality",
                                "confidence": 0.8,
                                "source": "ABN Lookup",
                                "observed": True,
                            },
                            {
                                "kind": "government_id",
                                "label": "ABN",
                                "value": f"{abn[:2]} {abn[2:5]} {abn[5:8]} {abn[8:]}",
                                "evidence": "Public Australian Business Register record",
                                "confidence": 0.98,
                                "source": "ABN Lookup",
                                "observed": True,
                            },
                        ],
                    },
                )
            )

    def _hudsonrock(self) -> None:
        for email in self.profile.emails:
            status, payload = self._json(
                f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={quote(email, safe='')}",
                headers={"Accept": "application/json"},
                ttl=6 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            stealers = payload.get("stealers") or []
            if not isinstance(stealers, list) or not stealers:
                continue
            computers = []
            for stealer in stealers[:10]:
                if not isinstance(stealer, dict):
                    continue
                computers.append(
                    {
                        "date": stealer.get("date_compromised"),
                        "computer_name": stealer.get("computer_name"),
                        "operating_system": stealer.get("operating_system"),
                        "user_services": stealer.get("total_user_services"),
                        "corporate_services": stealer.get("total_corporate_services"),
                        "antiviruses": stealer.get("antiviruses") or [],
                    }
                )
            latest = max(
                (str(item.get("date") or "") for item in computers if item.get("date")),
                default="",
            )
            count = len(stealers)
            self.outcome.add(
                Finding(
                    kind="breach",
                    category="breach",
                    source="Hudson Rock",
                    title=f"Email linked to {count} infostealer-infected computer{'s' if count != 1 else ''}",
                    url="https://www.hudsonrock.com/free-tools",
                    snippet=compact(
                        f"{count} infected computer record(s)"
                        + (f" · latest {latest}" if latest else "")
                        + " · saved credentials may be exposed. Review all passwords and sessions.",
                        400,
                    ),
                    identifier=email,
                    identifier_type="email",
                    severity="critical",
                    confidence=0.85,
                    matched=f"email:{email}",
                    fingerprint=make_fingerprint("hudsonrock", normalize_email(email)),
                    details={
                        "provider": "hudsonrock",
                        "infection_count": count,
                        "latest_date": latest,
                        "computers": computers,
                        "reason": "Email appears in the Hudson Rock infostealer index; this can indicate malware-exposed credentials",
                        "data_points": [
                            {
                                "kind": "email",
                                "label": "Email address",
                                "value": email,
                                "evidence": "Matched infostealer records",
                                "confidence": 0.9,
                                "source": "Hudson Rock",
                                "observed": True,
                            },
                            {
                                "kind": "device",
                                "label": "Device / malware record",
                                "value": computers[0].get("operating_system") or "Infected computer record",
                                "evidence": f"{count} infected computer record(s)",
                                "confidence": 0.8,
                                "source": "Hudson Rock",
                                "observed": True,
                            },
                            {
                                "kind": "password",
                                "label": "Saved credentials at risk",
                                "value": "Credentials stored on infected computer(s)",
                                "evidence": "Infostealer malware can capture saved browser credentials",
                                "confidence": 0.8,
                                "source": "Hudson Rock",
                                "observed": True,
                            },
                        ],
                    },
                )
            )
            self.outcome.note(
                "hudsonrock",
                f"Email appears in {count} Hudson Rock infostealer record(s).",
                "finding",
            )

    def _rdap(self) -> None:
        for domain in self.profile.domain_names:
            status, payload = self._json(
                f"https://rdap.org/domain/{quote(domain)}",
                headers={"Accept": "application/rdap+json, application/json"},
                ttl=24 * 3600,
            )
            if status != 200 or not isinstance(payload, dict):
                continue
            registrar = ""
            for entity in payload.get("entities") or []:
                if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
                    registrar = self._vcard_name(entity.get("vcardArray")) or registrar
            exposed: dict[str, str] = {}
            for entity in payload.get("entities") or []:
                if not isinstance(entity, dict):
                    continue
                roles = [str(role) for role in entity.get("roles") or []]
                if "registrant" not in roles:
                    continue
                vcard = self._vcard_values(entity.get("vcardArray"))
                for key, value in vcard.items():
                    if value and not self._looks_redacted(value):
                        exposed[key] = value
            if exposed:
                snippet = " · ".join(f"{key}: {value}" for key, value in exposed.items())
                self.outcome.add(
                    Finding(
                        kind="whois",
                        category="domain",
                        source="RDAP / WHOIS",
                        title=f"Public registrant data for {domain}",
                        url=f"https://rdap.org/domain/{quote(domain)}",
                        snippet=compact(snippet, 400),
                        identifier=domain,
                        identifier_type="domain",
                        severity="high",
                        confidence=0.9,
                        matched=f"domain:{domain}",
                        details={
                            "provider": "rdap",
                            "registrar": registrar,
                            "redacted": False,
                            "exposed_fields": exposed,
                        },
                    )
                )
            else:
                self.outcome.note(
                    "rdap",
                    f"{domain}: registrant data appears redacted (good).",
                    "info",
                )

    @staticmethod
    def _looks_redacted(value: str) -> bool:
        lowered = normalize_text(value)
        return any(
            marker in lowered
            for marker in (
                "redacted",
                "privacy",
                "not disclosed",
                "data protected",
                "withheld",
                "statutory masking",
                "gdpr",
            )
        )

    @staticmethod
    def _vcard_values(vcard: Any) -> dict[str, str]:
        result: dict[str, str] = {}
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            return result
        labels = {
            "fn": "name",
            "email": "email",
            "tel": "phone",
            "adr": "address",
            "org": "organisation",
        }
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            key = str(item[0]).casefold()
            if key not in labels:
                continue
            value = item[3]
            if isinstance(value, list):
                value = ", ".join(str(part) for part in value if part)
            value = str(value or "").strip()
            if value:
                result[labels[key]] = value
        return result

    @classmethod
    def _vcard_name(cls, vcard: Any) -> str:
        return cls._vcard_values(vcard).get("name", "")

    # ------------------------------------------------------------------
    # Breaches
    # ------------------------------------------------------------------
    def _breaches(self) -> None:
        key = self.keys["hibp"]
        headers = {
            "hibp-api-key": key,
            "User-Agent": "FindMyFootprint/1.0 (personal privacy self-audit)",
            "Accept": "application/json",
        }
        for email in self.profile.emails:
            status, payload = self._json(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false",
                headers=headers,
                ttl=6 * 3600,
            )
            if status == 404:
                self.outcome.note("breaches", f"No breaches returned for {email}.", "info")
                continue
            if status in {401, 403}:
                self.outcome.note(
                    "breaches",
                    "Have I Been Pwned rejected the API key. Check HIBP_API_KEY and its subscription.",
                    "error",
                )
                return
            if status == 429:
                self.outcome.note("breaches", "Have I Been Pwned rate limit reached; try again later.", "warning")
                return
            if status != 200 or not isinstance(payload, list):
                continue
            for breach in payload:
                if not isinstance(breach, dict):
                    continue
                name = str(breach.get("Name") or "Unknown breach")
                data_classes = [str(value) for value in breach.get("DataClasses") or []]
                lowered = {value.casefold() for value in data_classes}
                if "passwords" in lowered or "password" in lowered:
                    severity = "critical"
                elif breach.get("IsSensitive") or any(
                    item in lowered for item in {"credit cards", "bank account numbers", "government issued ids"}
                ):
                    severity = "high"
                else:
                    severity = "high"
                date = str(breach.get("BreachDate") or "")
                pwn_count = int(breach.get("PwnCount") or 0)
                snippet = " · ".join(
                    part
                    for part in [
                        f"Breach date: {date}" if date else "",
                        f"{pwn_count:,} accounts" if pwn_count else "",
                        "Data: " + ", ".join(data_classes[:8]) if data_classes else "",
                        "Sensitive breach" if breach.get("IsSensitive") else "",
                    ]
                    if part
                )
                self.outcome.add(
                    Finding(
                        kind="breach",
                        category="breach",
                        source="Have I Been Pwned",
                        title=f"Email exposed in the {name} breach",
                        url=f"https://haveibeenpwned.com/PwnedWebsites#{quote(name)}",
                        snippet=compact(snippet, 400),
                        identifier=email,
                        identifier_type="email",
                        severity=severity,
                        confidence=0.99,
                        matched=f"email:{email}",
                        fingerprint=make_fingerprint("breach", normalize_email(email), name),
                        details={
                            "provider": "hibp",
                            "breach": name,
                            "title": breach.get("Title"),
                            "domain": breach.get("Domain"),
                            "breach_date": date,
                            "pwn_count": pwn_count,
                            "data_classes": data_classes,
                            "is_sensitive": bool(breach.get("IsSensitive")),
                            "is_verified": bool(breach.get("IsVerified")),
                            "is_spam_list": bool(breach.get("IsSpamList")),
                        },
                    )
                )


def mask_breach_details(details: dict[str, Any]) -> dict[str, Any]:
    """Defensive helper: breach reports should never contain credentials."""
    allowed = {
        "provider",
        "breach",
        "title",
        "domain",
        "breach_date",
        "pwn_count",
        "data_classes",
        "is_sensitive",
        "is_verified",
        "is_spam_list",
    }
    return {key: value for key, value in details.items() if key in allowed}
