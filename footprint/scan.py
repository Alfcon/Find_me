"""Scan orchestration: plan queries, collect results, run checks, store findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .analyze import analyze_hit, merge_findings
from .brokers import BrokerCatalog, load_catalog
from .checks import CheckRunner
from .config import AppConfig
from .db import Store
from .http import HttpClient, HttpError, friendly_http_error
from .models import Finding, ScanStats, SearchQuery
from .queries import build_queries
from .search import SearchClient, SearchEngineError, engine_label
from .util import iso_now


@dataclass
class ScanResult:
    stats: ScanStats
    findings: list[Finding] = field(default_factory=list)
    queries: list[SearchQuery] = field(default_factory=list)
    dry_run: bool = False
    engine_availability: list[tuple[str, bool, str]] = field(default_factory=list)
    ok: bool = True
    message: str = ""


class Scanner:
    def __init__(
        self,
        config: AppConfig,
        store: Store | None = None,
        *,
        offline: bool = False,
        logger: Callable[[str], None] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.store = store
        self.offline = offline
        self.logger = logger
        self.on_event = on_event
        self.catalog = load_catalog()
        self.http = HttpClient(
            config.cache_dir,
            offline=offline,
            min_interval=max(1.0, config.search.delay_seconds / 2),
            logger=logger,
        )
        self.search = SearchClient(
            self.http,
            config.search.engines,
            region=config.search.region,
            api_keys=config.api_keys,
            fallback_engine=config.search.fallback_engine,
            logger=logger,
        )
        self.stats = ScanStats()

    def close(self) -> None:
        self.http.close()

    def event(self, stage: str, message: str, **extra: Any) -> None:
        if self.on_event:
            payload = {"stage": stage, "message": message, **extra}
            self.on_event(payload)

    def plan(self, max_queries: int | None = None) -> list[SearchQuery]:
        brokers = self.catalog.filter_regions(self.config.brokers.regions)
        queries = build_queries(self.config.profile, self.config.search, brokers)
        if max_queries is not None:
            queries = queries[: max(0, max_queries)]
        self.stats.queries_planned = len(queries)
        return queries

    def run(
        self,
        *,
        only: str = "all",
        dry_run: bool = False,
        max_queries: int | None = None,
    ) -> ScanResult:
        if only not in {"all", "search", "checks"}:
            raise ValueError("only must be one of: all, search, checks")
        queries = self.plan(max_queries)
        availability = self.search.availability()
        if dry_run:
            self.stats.finished_at = self.stats.started_at
            return ScanResult(
                stats=self.stats,
                queries=queries,
                dry_run=True,
                engine_availability=availability,
                message="Dry run: no network requests, no database writes.",
            )

        if not queries and only in {"all", "search"}:
            self.stats.note(
                "planning",
                "No search queries were generated. Add an email, username, phone, or address to the profile.",
                "warning",
            )
            if only == "search":
                return ScanResult(
                    stats=self.stats,
                    queries=queries,
                    engine_availability=availability,
                    ok=False,
                    message="No search queries available.",
                )

        if not self.store:
            raise ValueError("a Store is required for a non-dry-run scan")
        run_id = self.store.start_run(mode=only)
        self.stats.run_id = run_id
        search_findings: list[Finding] = []
        check_outcome = None
        status = "complete"
        try:
            if only in {"all", "search"} and queries:
                search_findings = self._run_search(queries, availability)
            if only in {"all", "checks"}:
                check_outcome = self._run_checks()
                if check_outcome:
                    self.stats.checks_run = check_outcome.checks_run
                    self.stats.checks_skipped = check_outcome.checks_skipped
                    self.stats.errors += check_outcome.errors
                    for kind, message, level in check_outcome.notes:
                        self.stats.note(kind, message, level)
            all_findings = list(search_findings)
            if check_outcome:
                all_findings.extend(check_outcome.findings)
            all_findings = merge_findings(all_findings)
            self._store_findings(all_findings, run_id)
            self.stats.finished_at = iso_now()
            return ScanResult(
                stats=self.stats,
                findings=all_findings,
                queries=queries,
                engine_availability=availability,
                message="Scan complete.",
            )
        except KeyboardInterrupt:
            status = "interrupted"
            self.stats.note("scan", "Scan interrupted by user.", "warning")
            raise
        except Exception as exc:
            status = "error"
            self.stats.note("scan", f"{type(exc).__name__}: {friendly_http_error(exc)}", "error")
            self.stats.errors += 1
            raise
        finally:
            self.stats.requests = self.http.requests_made
            self.stats.finished_at = self.stats.finished_at or iso_now()
            if self.store:
                self.store.finish_run(run_id, status, self.stats.as_dict())

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------
    def _run_search(
        self, queries: list[SearchQuery], availability: list[tuple[str, bool, str]]
    ) -> list[Finding]:
        enabled = [(engine, ok, reason) for engine, ok, reason in availability]
        usable = [engine for engine, ok, _reason in enabled if ok]
        for engine, ok, reason in enabled:
            if not ok:
                self.stats.note("search", f"{engine_label(engine)} disabled: {reason}", "warning")
        fallback = self.search.fallback_engine
        if fallback:
            self.stats.note(
                "search",
                f"Fallback engine available: {engine_label(fallback)}.",
                "info",
            )
        if not usable and fallback:
            usable.append(fallback)
        if not usable:
            self.stats.note("search", "No usable search engine is configured.", "error")
            self.stats.errors += 1
            return []

        failures: dict[str, int] = {engine: 0 for engine in usable}
        disabled: set[str] = set()
        collected: list[Finding] = []

        def consume(engine: str, query: SearchQuery) -> int:
            hits = self.search.search(
                engine,
                query.text,
                self.config.search.results_per_query,
                force=engine == fallback and engine not in self.config.search.engines,
            )
            self.stats.queries_run += 1
            self.stats.results_seen += len(hits)
            for hit in hits:
                finding = analyze_hit(
                    query,
                    hit,
                    self.config.profile,
                    self.catalog,
                    self.config.search.exclude_domains,
                )
                if finding:
                    collected.append(finding)
                    self.stats.results_matched += 1
            return len(hits)

        for index, query in enumerate(queries, 1):
            self.event(
                "search",
                f"Query {index}/{len(queries)}: {query.label}",
                current=index,
                total=len(queries),
                query=query.as_dict(),
            )
            switched = False
            for engine in list(usable):
                if engine in disabled:
                    continue
                try:
                    consume(engine, query)
                    failures[engine] = 0
                except KeyboardInterrupt:
                    raise
                except (SearchEngineError, HttpError) as exc:
                    failures[engine] += 1
                    self.stats.errors += 1
                    self.stats.note("search", f"{engine_label(engine)}: {friendly_http_error(exc)}", "error")
                    if failures[engine] >= 2:
                        disabled.add(engine)
                        self.stats.note(
                            "search",
                            f"{engine_label(engine)} disabled for the rest of this scan after repeated errors.",
                            "warning",
                        )
                    if fallback and fallback not in usable and not switched:
                        usable.append(fallback)
                        failures.setdefault(fallback, 0)
                        try:
                            consume(fallback, query)
                            failures[fallback] = 0
                            disabled.add(engine)
                            switched = True
                            self.stats.note(
                                "search",
                                f"Fell back to {engine_label(fallback)} for this scan after "
                                f"{engine_label(engine)} failed.",
                                "warning",
                            )
                        except (SearchEngineError, HttpError) as fallback_exc:
                            failures[fallback] += 1
                            self.stats.errors += 1
                            self.stats.note(
                                "search",
                                f"{engine_label(fallback)}: {friendly_http_error(fallback_exc)}",
                                "error",
                            )
                except Exception as exc:
                    failures[engine] += 1
                    self.stats.errors += 1
                    self.stats.note(
                        "search",
                        f"{engine_label(engine)}: {type(exc).__name__}: {exc}",
                        "error",
                    )
                    if failures[engine] >= 2:
                        disabled.add(engine)
                if index < len(queries):
                    time.sleep(self.config.search.delay_seconds)
        return merge_findings(collected)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------
    def _run_checks(self):
        self.event("checks", "Running public profile and breach checks")
        runner = CheckRunner(
            self.config,
            self.http,
            on_check=lambda name: self.event("check", f"Checking {name}"),
        )
        outcome = runner.run()
        return outcome

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _store_findings(self, findings: Iterable[Finding], run_id: int) -> None:
        if not self.store:
            return
        for finding in findings:
            _finding_id, is_new, reappeared = self.store.upsert_finding(finding, run_id)
            if is_new:
                self.stats.new_findings += 1
            else:
                self.stats.updated_findings += 1
            if reappeared:
                self.stats.note(
                    "status",
                    f"A previously removed result reappeared: {finding.title}",
                    "warning",
                )


def scan_exit_code(result: ScanResult) -> int:
    if not result.ok:
        return 2
    # Zero matches is a valid result. Only fail the command if no query could
    # be completed at all (for example, every engine was unreachable).
    if result.stats.queries_run == 0 and not result.stats.checks_run:
        return 1
    return 0
