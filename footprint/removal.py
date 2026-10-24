"""Prepare, track, and verify removal requests.

This module is intentionally a *workbench*, not an autonomous removal bot. It
prepares the exact request, stores the evidence and deadline, and verifies the
public listing later. It does not submit forms, log in, or solve CAPTCHAs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from bs4 import BeautifulSoup

from .brokers import Broker, BrokerCatalog, load_catalog
from .config import AppConfig, Profile
from .db import REQUEST_STATUSES, Store
from .http import HttpClient, HttpError, friendly_http_error
from .util import (
    compact,
    days_from_now,
    domain_of,
    is_safe_public_url,
    iso_now,
    normalize_text,
    phone_digits,
    severity_rank,
)

PRIORITY_DAYS = {"P0": 7, "P1": 14, "P2": 30, "P3": 45}


def _priority_for(severity: str) -> str:
    return {
        "critical": "P0",
        "high": "P1",
        "medium": "P2",
        "low": "P3",
        "info": "P3",
    }.get(severity, "P2")


def _email_body(profile: Profile, request: dict[str, Any]) -> str:
    name = profile.display_name or "[your full name]"
    email = profile.emails[0] if profile.emails else "[your email]"
    phone = profile.phones[0] if profile.phones else "[your phone]"
    address = profile.addresses[0] if profile.addresses else "[your address]"
    url = request.get("verify_url") or request.get("details", {}).get("source_url") or "[URL]"
    return (
        "To the Privacy / Data Protection Team,\n\n"
        "I am writing to request deletion or correction of my personal information.\n\n"
        f"Name: {name}\nEmail: {email}\nPhone: {phone}\nAddress: {address}\n"
        f"Affected page: {url}\n\n"
        "Please remove the personal information relating to me from your site and "
        "suppress it from future publications. If you cannot delete it, tell me what "
        "you retain, why, and what suppression or de-indexing options are available. "
        "Please confirm the action and date in writing.\n\n"
        "I understand you may need to verify my identity; tell me the minimum evidence "
        "required rather than asking for unnecessary documents.\n\n"
        "Yours sincerely,\n"
        f"{name}\n"
    )


@dataclass
class RequestResult:
    request: dict[str, Any]
    created: bool
    message: str = ""


class RemovalManager:
    def __init__(
        self,
        config: AppConfig,
        store: Store,
        *,
        catalog: BrokerCatalog | None = None,
        http: HttpClient | None = None,
    ):
        self.config = config
        self.profile = config.profile
        self.store = store
        self.catalog = catalog or load_catalog()
        self.http = http or HttpClient(config.cache_dir, min_interval=1.5)
        self._owns_http = http is None

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def create_for_finding(self, finding_id: int, notes: str = "") -> RequestResult:
        finding = self.store.get_finding(finding_id)
        if not finding:
            return RequestResult({}, False, f"No finding with id {finding_id}")
        broker = self.catalog.get(str((finding.get("details") or {}).get("broker_id") or ""))
        request = self._build_request(finding, broker, notes)
        created, is_new = self.store.create_request(request)
        return RequestResult(created, is_new, "Request prepared" if is_new else "Request already exists")

    def create_for_broker(self, broker_id: str, notes: str = "") -> RequestResult:
        broker = self.catalog.get(broker_id)
        if not broker:
            return RequestResult({}, False, f"Unknown broker id: {broker_id}")
        request = self._build_request(None, broker, notes)
        created, is_new = self.store.create_request(request)
        return RequestResult(created, is_new, "Request prepared" if is_new else "Request already exists")

    def _build_request(
        self, finding: dict[str, Any] | None, broker: Broker | None, notes: str
    ) -> dict[str, Any]:
        finding = finding or {}
        severity = str(finding.get("severity") or "medium")
        priority = _priority_for(severity)
        details = finding.get("details") or {}
        broker_id = broker.id if broker else str(details.get("broker_id") or "")
        finding_id = int(finding["id"]) if finding.get("id") else None
        request_key = f"finding:{finding_id}" if finding_id else f"broker:{broker_id}"
        source_url = str(finding.get("url") or "")
        optout_url = broker.optout_url if broker else ""
        url = optout_url or source_url
        verify_url = source_url if source_url and source_url != optout_url else ""
        title = (
            f"Remove your listing from {broker.name}"
            if broker
            else f"Request removal: {finding.get('title') or 'reviewed result'}"
        )
        method = broker.method if broker else "source request"
        details_payload = {
            "fields": {
                "name": self.profile.display_name,
                "email": self.profile.emails[0] if self.profile.emails else "",
                "phone": self.profile.phones[0] if self.profile.phones else "",
                "address": self.profile.addresses[0] if self.profile.addresses else "",
                "listing_url": source_url,
                "date": iso_now(),
            },
            "requirements": broker.requirements if broker else "",
            "broker_notes": broker.notes if broker else "",
            "source_url": source_url,
            "optout_url": optout_url,
            "email_subject": "Request to delete or correct my personal information",
            "email_body": _email_body(self.profile, {"verify_url": verify_url, "details": {"source_url": source_url}}),
            "steps": [
                "Open the official opt-out/privacy URL and locate the exact listing.",
                "Submit only the minimum identity data required.",
                "Save the confirmation/reference and record it in this request.",
                "Run `footprint verify <id>` after the broker's stated processing period.",
            ],
            "authorization": "The profile owner must review and submit this request.",
            "broker_id": broker_id,
            "domain": domain_of(source_url) if source_url else "",
        }
        return {
            "request_key": request_key,
            "finding_id": finding_id,
            "broker_id": broker_id,
            "title": title,
            "method": method,
            "url": url,
            "verify_url": verify_url,
            "status": "prepared",
            "priority": priority,
            "created_at": iso_now(),
            "due_at": days_from_now(PRIORITY_DAYS.get(priority, 30)),
            "notes": notes,
            "evidence": compact(str(finding.get("snippet") or ""), 500),
            "details": details_payload,
        }

    def verify_request(self, request_id: int) -> dict[str, Any] | None:
        request = self.store.get_request(request_id)
        if not request:
            return None
        verify_url = str(request.get("verify_url") or "")
        if not verify_url or not is_safe_public_url(verify_url):
            updated = self.store.update_request(
                request_id,
                status="blocked",
                last_checked_at=iso_now(),
                details={
                    **(request.get("details") or {}),
                    "verification": {
                        "status": "blocked",
                        "reason": "No safe direct listing URL is available to verify",
                    },
                },
            )
            return updated
        try:
            response = self.http.get(
                verify_url,
                ttl=0,
                timeout=20,
                headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"},
            )
        except HttpError as exc:
            return self.store.update_request(
                request_id,
                status="blocked",
                last_checked_at=iso_now(),
                details={
                    **(request.get("details") or {}),
                    "verification": {
                        "status": "blocked",
                        "reason": friendly_http_error(exc),
                        "checked_at": iso_now(),
                    },
                },
            )
        old_status = str(request.get("status") or "")
        if response.status == 404:
            return self._apply_verification(
                request, status="removed", reason="HTTP 404 — listing is gone", matches=[]
            )
        if response.status in {401, 403, 429}:
            return self.store.update_request(
                request_id,
                status="blocked",
                last_checked_at=iso_now(),
                details={
                    **(request.get("details") or {}),
                    "verification": {
                        "status": "blocked",
                        "reason": f"HTTP {response.status}; site blocks automated verification",
                        "checked_at": iso_now(),
                    },
                },
            )
        if response.status != 200:
            return self.store.update_request(
                request_id,
                status="blocked",
                last_checked_at=iso_now(),
                details={
                    **(request.get("details") or {}),
                    "verification": {
                        "status": "blocked",
                        "reason": f"HTTP {response.status}",
                        "checked_at": iso_now(),
                    },
                },
            )
        text = BeautifulSoup(response.text or "", "html.parser").get_text(" ", strip=True)
        if len(text) < 180 or "captcha" in text.casefold() or "verify you are human" in text.casefold():
            return self.store.update_request(
                request_id,
                status="blocked",
                last_checked_at=iso_now(),
                details={
                    **(request.get("details") or {}),
                    "verification": {
                        "status": "blocked",
                        "reason": "Page is too short or is a challenge page; manual verification required",
                        "checked_at": iso_now(),
                    },
                },
            )
        matches = self._identity_matches(text)
        if matches:
            new_status = "reappeared" if old_status == "removed" else "still_listed"
            return self._apply_verification(
                request,
                status=new_status,
                reason="Identifiers still visible on the page",
                matches=matches,
                excerpt=self._excerpt(text, matches),
            )
        return self._apply_verification(
            request,
            status="removed",
            reason="No configured identifiers found in the readable page",
            matches=[],
            excerpt=compact(text, 300),
        )

    def verify_many(
        self,
        request_ids: list[int] | None = None,
        *,
        due_only: bool = False,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        if request_ids:
            requests = [self.store.get_request(item) for item in request_ids]
            requests = [item for item in requests if item]
        else:
            requests = self.store.list_requests(status="open", due_only=due_only, limit=limit)
        return [self.verify_request(int(item["id"])) for item in requests]  # type: ignore[list-item]

    def _apply_verification(
        self,
        request: dict[str, Any],
        *,
        status: str,
        reason: str,
        matches: list[str],
        excerpt: str = "",
    ) -> dict[str, Any]:
        details = dict(request.get("details") or {})
        details["verification"] = {
            "status": status,
            "reason": reason,
            "matches": matches,
            "checked_at": iso_now(),
            "excerpt": compact(excerpt, 500),
        }
        updated = self.store.update_request(
            int(request["id"]),
            status=status,
            last_checked_at=iso_now(),
            details=details,
        )
        finding_id = request.get("finding_id")
        if finding_id:
            finding_status = "removed" if status == "removed" else "reappeared" if status == "reappeared" else "confirmed"
            self.store.update_finding(
                int(finding_id),
                status=finding_status,
                notes=f"Verification: {reason}",
            )
        broker_id = str(request.get("broker_id") or "")
        if broker_id:
            broker_status = "removed" if status == "removed" else "listed"
            try:
                self.store.update_broker(broker_id, broker_status, notes=f"Request #{request['id']}: {reason}")
            except ValueError:
                pass
        return updated or {}

    def _identity_matches(self, text: str) -> list[str]:
        normalized = normalize_text(text)
        matches: list[str] = []
        if self.profile.display_name and normalize_text(self.profile.display_name) in normalized:
            matches.append("name")
        for email in self.profile.emails:
            if email.casefold() in text.casefold():
                matches.append("email")
        for phone in self.profile.phones:
            digits = phone_digits(phone)
            if len(digits) >= 7 and digits[-9:] in phone_digits(text):
                matches.append("phone")
        for address in self.profile.addresses:
            if normalize_text(address) and normalize_text(address) in normalized:
                matches.append("address")
        for username in self.profile.all_usernames:
            if re.search(r"(?<![a-z0-9_.-])" + re.escape(username) + r"(?![a-z0-9_.-])", text, re.I):
                matches.append("username")
        return sorted(set(matches))

    @staticmethod
    def _excerpt(text: str, matches: Iterable[str]) -> str:
        lowered = text.casefold()
        for match in matches:
            index = lowered.find(match.casefold())
            if index >= 0:
                return compact(text[max(0, index - 100) : index + 220], 320)
        return compact(text, 300)
