"""Polite HTTP client with on-disk caching for repeatable, low-impact scans."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from . import __version__
from .util import ensure_private_dir, ensure_private_file

DEFAULT_USER_AGENT = (
    f"FindMyFootprint/{__version__} (personal privacy self-audit; public data only)"
)
SENSITIVE_PARAMS = {"api_key", "apikey", "key", "token", "access_token", "subscription-key"}


class HttpError(RuntimeError):
    def __init__(self, message: str, url: str = "", status: int | None = None):
        super().__init__(message)
        self.url = url
        self.status = status


@dataclass(slots=True)
class HttpResponse:
    status: int
    text: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False
    stale: bool = False

    def json(self) -> Any:
        if not self.text:
            return None
        return json.loads(self.text)


def redact_url(url: str) -> str:
    try:
        split = urlsplit(url)
    except ValueError:
        return url
    pairs = []
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        if key.casefold() in SENSITIVE_PARAMS:
            pairs.append((key, "REDACTED"))
        else:
            pairs.append((key, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))


class HttpClient:
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        *,
        timeout: float = 20.0,
        min_interval: float = 1.0,
        offline: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        logger: Callable[[str], None] | None = None,
    ):
        self.cache_dir = Path(cache_dir).expanduser().resolve() if cache_dir else None
        self.timeout = timeout
        self.min_interval = max(0.0, min_interval)
        self.offline = offline
        self.logger = logger
        self.requests_made = 0
        self.cache_hits = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-AU,en;q=0.8",
            }
        )
        self._last_request: dict[str, float] = {}

    def close(self) -> None:
        self.session.close()

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl: int = 12 * 3600,
        allow_redirects: bool = True,
        timeout: float | None = None,
        min_interval: float | None = None,
        _retry: int = 0,
    ) -> HttpResponse:
        request_url = self._build_url(url, params)
        headers = dict(headers or {})
        cache_key = hashlib.sha256(
            (request_url + "\x1f" + json.dumps(headers, sort_keys=True)).encode("utf-8")
        ).hexdigest()
        cached = self._read_cache(cache_key)
        if cached and cached.get("fetched_at", 0) + ttl >= time.time():
            self.cache_hits += 1
            return HttpResponse(
                status=int(cached["status"]),
                text=cached.get("text", ""),
                url=cached.get("url", request_url),
                headers=cached.get("headers", {}),
                from_cache=True,
            )
        if self.offline:
            if cached:
                self.cache_hits += 1
                return HttpResponse(
                    status=int(cached["status"]),
                    text=cached.get("text", ""),
                    url=cached.get("url", request_url),
                    headers=cached.get("headers", {}),
                    from_cache=True,
                    stale=True,
                )
            raise HttpError(f"offline and no cache for {redact_url(request_url)}", request_url)

        split = urlsplit(request_url)
        host = (split.hostname or "").casefold()
        interval = self.min_interval if min_interval is None else max(0.0, min_interval)
        self._wait(host, interval)
        if self.logger:
            self.logger(f"GET {redact_url(request_url)}")
        started = time.time()
        try:
            response = self.session.get(
                request_url,
                headers=headers,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException as exc:
            self._last_request[host] = time.time()
            if _retry < 2:
                delay = 1.5 * (_retry + 1)
                if self.logger:
                    self.logger(f"network error ({type(exc).__name__}); retrying in {delay:.1f}s")
                time.sleep(delay)
                return self.get(
                    url,
                    params=params,
                    headers=headers,
                    ttl=ttl,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    min_interval=interval,
                    _retry=_retry + 1,
                )
            if cached:
                self.cache_hits += 1
                return HttpResponse(
                    status=int(cached["status"]),
                    text=cached.get("text", ""),
                    url=cached.get("url", request_url),
                    headers=cached.get("headers", {}),
                    from_cache=True,
                    stale=True,
                )
            raise HttpError(
                "could not connect to the remote service after 3 attempts "
                f"({type(exc).__name__}); check your internet connection, VPN, or firewall",
                request_url,
            ) from exc
        self._last_request[host] = time.time()
        self.requests_made += 1

        if response.status_code == 429:
            if _retry >= 2:
                raise HttpError(
                    f"rate limited by {host} after retries; try again later",
                    request_url,
                    429,
                )
            wait = self._retry_after(response.headers.get("Retry-After"))
            if self.logger:
                self.logger(f"rate limited by {host}; waiting {wait:.0f}s")
            time.sleep(min(wait, 15.0))
            return self.get(
                url,
                params=params,
                headers=headers,
                ttl=ttl,
                allow_redirects=allow_redirects,
                timeout=timeout,
                min_interval=max(interval, 3.0),
                _retry=_retry + 1,
            )

        if response.status_code >= 500:
            if _retry < 2:
                delay = 2.0 * (_retry + 1)
                if self.logger:
                    self.logger(f"server error {response.status_code}; retrying in {delay:.1f}s")
                time.sleep(delay)
                return self.get(
                    url,
                    params=params,
                    headers=headers,
                    ttl=ttl,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    min_interval=interval,
                    _retry=_retry + 1,
                )
            raise HttpError(
                f"server error {response.status_code} for {redact_url(request_url)}",
                request_url,
                response.status_code,
            )

        text = response.text
        result = HttpResponse(
            status=response.status_code,
            text=text,
            url=response.url,
            headers={key.casefold(): value for key, value in response.headers.items()},
        )
        if response.status_code < 500:
            self._write_cache(
                cache_key,
                {
                    "fetched_at": time.time(),
                    "status": response.status_code,
                    "text": text,
                    "url": response.url,
                    "headers": {
                        "content-type": response.headers.get("content-type", ""),
                    },
                },
            )
        if self.logger:
            self.logger(
                f"  -> {response.status_code} {len(response.content)} bytes in {time.time() - started:.2f}s"
            )
        return result


    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Small JSON POST helper for search providers that require it."""
        if self.offline:
            raise HttpError("offline mode does not support POST requests", url)
        headers = {"Accept": "application/json", "Content-Type": "application/json", **(headers or {})}
        split = urlsplit(url)
        host = (split.hostname or "").casefold()
        self._wait(host, self.min_interval)
        if self.logger:
            self.logger(f"POST {redact_url(url)}")
        try:
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=timeout or self.timeout,
            )
        except requests.RequestException as exc:
            self._last_request[host] = time.time()
            raise HttpError(
                f"could not connect to {host} ({type(exc).__name__}); check your connection",
                url,
            ) from exc
        self._last_request[host] = time.time()
        self.requests_made += 1
        if response.status_code == 429:
            raise HttpError(f"rate limited by {host}", url, 429)
        if response.status_code >= 500:
            raise HttpError(f"server error {response.status_code} from {host}", url, response.status_code)
        return HttpResponse(
            status=response.status_code,
            text=response.text,
            url=response.url,
            headers={key.casefold(): value for key, value in response.headers.items()},
        )

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl: int = 12 * 3600,
        timeout: float | None = None,
    ) -> tuple[int, Any]:
        response = self.get(
            url, params=params, headers=headers, ttl=ttl, timeout=timeout
        )
        if not response.text.strip():
            return response.status, None
        try:
            return response.status, response.json()
        except json.JSONDecodeError as exc:
            raise HttpError(
                f"invalid JSON from {redact_url(response.url)}", response.url, response.status
            ) from exc

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_url(self, url: str, params: dict[str, Any] | None) -> str:
        if not params:
            return url
        split = urlsplit(url)
        existing = dict(parse_qsl(split.query, keep_blank_values=True))
        for key, value in params.items():
            if value is not None:
                existing[key] = str(value)
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(existing), split.fragment))

    def _wait(self, host: str, interval: float) -> None:
        if interval <= 0:
            return
        last = self._last_request.get(host)
        if last is not None:
            remaining = interval - (time.time() - last)
            if remaining > 0:
                time.sleep(remaining)

    def _retry_after(self, value: str | None) -> float:
        try:
            return max(1.0, float(value or 5))
        except (TypeError, ValueError):
            return 5.0

    def _cache_path(self, key: str) -> Path | None:
        if not self.cache_dir:
            return None
        return self.cache_dir / key[:2] / f"{key}.json"

    def _read_cache(self, key: str) -> dict[str, Any] | None:
        path = self._cache_path(key)
        if not path or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _write_cache(self, key: str, data: dict[str, Any]) -> None:
        path = self._cache_path(key)
        if not path:
            return
        if self.cache_dir:
            ensure_private_dir(self.cache_dir)
        ensure_private_dir(path.parent)
        try:
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            ensure_private_file(path)
        except OSError:
            pass


def friendly_http_error(exc: Exception) -> str:
    if isinstance(exc, HttpError):
        return str(exc)
    if isinstance(exc, requests.Timeout):
        return "request timed out"
    if isinstance(exc, requests.RequestException):
        return f"network error: {type(exc).__name__}"
    return f"{type(exc).__name__}: {exc}"
