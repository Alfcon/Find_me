"""Shared test helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path

from footprint.config import AppConfig, BrokersConfig, Profile, ReportConfig, SearchConfig


def make_config(base: Path, *, redact: bool = False) -> AppConfig:
    return AppConfig(
        path=base / "profile.yaml",
        base_dir=base,
        profile=Profile.from_mapping(
            {
                "display_name": "Jordan Example",
                "emails": ["jordan@example.com"],
                "phones": ["+61 412 345 678"],
                "usernames": ["jordan-example"],
                "addresses": ["12 Example Street, Melbourne VIC 3000"],
                "locations": ["Melbourne, Australia"],
                "country": "Australia",
            }
        ),
        search=SearchConfig(engines=["duckduckgo"], max_queries=12),
        brokers=BrokersConfig(regions=["AU", "GLOBAL"]),
        report=ReportConfig(output=str(base / "reports" / "report.html"), redact=redact),
    )


class TempDir:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        return Path(self._tmp.name)

    def __exit__(self, *_exc) -> None:
        self._tmp.cleanup()
