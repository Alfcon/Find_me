"""Small, dependency-light helpers shared by the footprint audit."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_PARAMS = {
    "fbclid",
    "gclid",
    "dclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "igshid",
    "ref",
    "ref_src",
    "ref_url",
    "source",
    "si",
    "spm",
}

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])", re.I)
USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,38})$", re.I)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 1}


def iso_now() -> str:
    """Current local time as an ISO-8601 string with an offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def days_from_now(days: int) -> str:
    return (datetime.now().astimezone() + timedelta(days=days)).isoformat(timespec="seconds")


def due_label(value: str | None) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "—"
    return parsed.astimezone().strftime("%d %b %Y")


def stable_id(*parts: Any) -> str:
    """A short, stable identifier derived from arbitrary values."""
    raw = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def fingerprint(*parts: Any) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compact(value: str, limit: int = 280) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def normalize_text(value: str) -> str:
    """Case-fold text and reduce punctuation to spaces for tolerant matching."""
    value = unicodedata.normalize("NFKD", value or "")
    value = value.casefold()
    value = re.sub(r"[^a-z0-9@.+_-]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def words(value: str) -> list[str]:
    return [part for part in normalize_text(value).split(" ") if part]


def normalize_email(value: str) -> str:
    return (value or "").strip().strip(".,;:<>()[]").casefold()


def is_valid_email(value: str) -> bool:
    value = normalize_email(value)
    return bool(EMAIL_RE.fullmatch(value)) and len(value) <= 254


def normalize_username(value: str) -> str:
    value = (value or "").strip()
    value = re.sub(r"^https?://(?:www\.)?", "", value, flags=re.I)
    value = value.split("/")[0].split("?")[0]
    return value.lstrip("@").strip().casefold()


def is_valid_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(value or ""))


def normalize_phone(value: str) -> str:
    """Return digits plus an optional leading +, with common formatting removed."""
    raw = (value or "").strip()
    plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""
    return ("+" if plus else "") + digits


def phone_digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def phone_variants(value: str) -> list[str]:
    """Useful searchable forms of a phone number, including AU +61 variants."""
    raw = normalize_space(value)
    digits = phone_digits(raw)
    if len(digits) < 7:
        return [raw] if raw else []
    variants = [raw, digits]
    if len(digits) == 10 and digits.startswith("0"):
        rest = digits[1:]
        variants.extend([f"+61 {rest}", f"+61{rest}", f"{digits[:4]} {digits[4:7]} {digits[7:]}"])
    if digits.startswith("61") and len(digits) == 11:
        local = "0" + digits[2:]
        variants.extend([local, f"{local[:4]} {local[4:7]} {local[7:]}"])
    seen: set[str] = set()
    result = []
    for item in variants:
        key = item.casefold()
        if item and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def normalize_location(value: str) -> str:
    return normalize_space(value).strip(" ,")


def location_city(value: str) -> str:
    """Use the first component of a location as the searchable city."""
    parts = [part.strip() for part in re.split(r"[,|]", value or "") if part.strip()]
    return parts[0] if parts else ""


def domain_of(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:
        return ""
    host = host.casefold().strip(".")
    return host[4:] if host.startswith("www.") else host


def domain_matches(host: str, candidate: str) -> bool:
    host = (host or "").casefold().strip(".")
    candidate = (candidate or "").casefold().strip(".")
    if not host or not candidate:
        return False
    return host == candidate or host.endswith("." + candidate)


def canonical_url(url: str) -> str:
    """Normalise a result URL and drop common tracking parameters."""
    if not url:
        return ""
    url = url.strip()
    if url.startswith("//"):
        url = "https:" + url
    if "://" not in url:
        return ""
    try:
        split = urlsplit(url)
    except ValueError:
        return ""
    if split.scheme.lower() not in {"http", "https"}:
        return ""
    host = (split.hostname or "").casefold().strip(".")
    if not host:
        return ""
    try:
        port = split.port
    except ValueError:
        port = None
    netloc = host
    if port and not ((split.scheme == "http" and port == 80) or (split.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    query = []
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        if key.casefold().startswith("utm_") or key.casefold() in TRACKING_PARAMS:
            continue
        query.append((key, value))
    path = re.sub(r"/+", "/", split.path or "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urlunsplit((split.scheme.lower(), netloc, path, urlencode(query, doseq=True), ""))


def unwrap_redirect(url: str) -> str:
    """Unwrap the redirect links used by DuckDuckGo and Bing HTML results."""
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    try:
        split = urlsplit(url)
    except ValueError:
        return url
    params = dict(parse_qsl(split.query, keep_blank_values=True))
    host = (split.hostname or "").casefold()
    if host.endswith("duckduckgo.com") and "uddg" in params:
        return params["uddg"]
    if host.endswith("google.com") and ("q" in params or "url" in params):
        candidate = params.get("q") or params.get("url") or ""
        if candidate.startswith("http"):
            return candidate
    if host.endswith("bing.com") and ("url" in params or "u" in params):
        candidate = params.get("url") or params.get("u") or ""
        if candidate.startswith("http"):
            return candidate
        if candidate.startswith("a1"):
            # Bing's click tracker uses a1 + unpadded URL-safe base64.
            encoded = candidate[2:]
            encoded += "=" * (-len(encoded) % 4)
            try:
                decoded = base64.urlsafe_b64decode(encoded).decode("utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                return url
            if decoded.startswith("http"):
                return decoded
    return url


def is_private_host(host: str) -> bool:
    host = (host or "").casefold().strip("[]")
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def is_safe_public_url(url: str) -> bool:
    """Used before fetching a user-supplied URL. Blocks obvious SSRF targets."""
    try:
        split = urlsplit(url)
    except ValueError:
        return False
    if split.scheme not in {"http", "https"} or not split.hostname:
        return False
    if split.username or split.password:
        return False
    return not is_private_host(split.hostname)


def safe_href(url: str) -> str:
    """Only allow safe, public http(s) links into generated HTML/CSV."""
    if not url:
        return ""
    url = url.strip()
    if not is_safe_public_url(url):
        return ""
    return canonical_url(url) or url


def truncate(value: str, limit: int = 120) -> str:
    value = normalize_space(value)
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get((value or "").casefold(), 99)


def severity_weight(value: str) -> int:
    return SEVERITY_WEIGHT.get((value or "").casefold(), 0)


def max_severity(values: Iterable[str]) -> str:
    values = list(values)
    if not values:
        return "info"
    return min(values, key=severity_rank)


def mask_email(value: str) -> str:
    value = normalize_email(value)
    if "@" not in value:
        return mask_text(value)
    local, domain = value.split("@", 1)
    if not local:
        return "***@" + domain
    return local[0] + "***@" + domain


def mask_phone(value: str) -> str:
    digits = phone_digits(value)
    if len(digits) <= 3:
        return "***"
    return "*** *** " + digits[-3:]


def mask_name(value: str) -> str:
    parts = [part for part in normalize_space(value).split(" ") if part]
    if not parts:
        return "***"
    return " ".join(part[0] + "***" for part in parts)


def mask_address(value: str) -> str:
    value = normalize_space(value)
    if not value:
        return "***"
    first = value.split(" ")[0]
    return first + " …"


def mask_username(value: str) -> str:
    value = normalize_username(value)
    if len(value) <= 2:
        return value[:1] + "***"
    return value[:2] + "***"


def mask_text(value: str) -> str:
    value = normalize_space(value)
    if len(value) <= 2:
        return "***"
    return value[:1] + "***" + value[-1:]


def display_identifier(value: str, kind: str, redact: bool = False) -> str:
    if not redact:
        return value
    if kind == "email":
        return mask_email(value)
    if kind == "phone":
        return mask_phone(value)
    if kind == "name":
        return mask_name(value)
    if kind == "address":
        return mask_address(value)
    if kind == "username":
        return mask_username(value)
    return mask_text(value)


class Redactor:
    """Best-effort redaction of configured identifiers in free text.

    This is for making a report safer to share, not a guarantee that every
    identifying detail has been removed. Review a redacted report before sharing.
    """

    def __init__(self, identifiers: Iterable[tuple[str, str]] = (), enabled: bool = False):
        self.enabled = enabled
        pairs: list[tuple[str, str]] = []
        if enabled:
            for kind, value in identifiers:
                if not value or len(value) < 3:
                    continue
                masked = display_identifier(value, kind, True)
                pairs.append((value, masked))
                if kind == "phone":
                    digits = phone_digits(value)
                    if len(digits) >= 7:
                        pairs.append((digits, masked))
                if kind == "email":
                    pairs.append((normalize_email(value), masked))
        self._pairs = sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)
        self._email_re = EMAIL_RE
        self._phone_patterns: list[tuple[re.Pattern[str], str]] = []
        if enabled:
            for kind, value in identifiers:
                if kind != "phone":
                    continue
                digits = phone_digits(value)
                if len(digits) < 7:
                    continue
                core = digits[-9:]
                masked = display_identifier(value, "phone", True)
                pattern = re.compile(
                    r"(?<!\d)(?:\+?\s*61[\s().-]*)?0?[\s().-]*"
                    + r"[\s().-]*".join(re.escape(digit) for digit in core)
                    + r"(?!\d)"
                )
                self._phone_patterns.append((pattern, masked))

    def text(self, value: str) -> str:
        value = value or ""
        if not self.enabled:
            return value
        for original, masked in self._pairs:
            if not original:
                continue
            value = re.sub(re.escape(original), lambda _m, replacement=masked: replacement, value, flags=re.I)
        for pattern, masked in self._phone_patterns:
            value = pattern.sub(masked, value)
        return self._email_re.sub(lambda match: mask_email(match.group(0)), value)

    def obj(self, value):
        """Recursively redact strings in JSON-like data."""
        if not self.enabled:
            return value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.obj(item) for item in value)
        if isinstance(value, dict):
            return {key: self.obj(item) for key, item in value.items()}
        return value


def ensure_private_file(path: Path) -> None:
    """Best-effort 0600 permissions for local files containing personal data."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


def ensure_private_dir(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError:
        pass


def write_private_text(path: Path, content: str) -> None:
    ensure_private_dir(path.parent)
    path.write_text(content, encoding="utf-8")
    ensure_private_file(path)


def slugify(value: str, fallback: str = "item") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").casefold()).strip("-")
    return slug or fallback


def host_is_engine(host: str) -> bool:
    engines = (
        "duckduckgo.com",
        "bing.com",
        "google.com",
        "search.brave.com",
        "brave.com",
        "yahoo.com",
        "yandex.com",
        "baidu.com",
    )
    return any(domain_matches(host, engine) for engine in engines)
