"""SQLite storage for findings, scans, and removal status."""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import Finding
from .util import ensure_private_dir, ensure_private_file, iso_now, severity_weight

FINDING_STATUSES = {
    "new",
    "confirmed",
    "removal_requested",
    "removed",
    "reappeared",
    "monitoring",
    "false_positive",
}
REQUEST_STATUSES = {
    "prepared",
    "awaiting_user",
    "submitted",
    "in_progress",
    "removed",
    "still_listed",
    "reappeared",
    "blocked",
    "failed",
}
BROKER_STATUSES = {
    "not_checked",
    "no_listing",
    "listed",
    "removal_requested",
    "removed",
    "blocked",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    mode TEXT NOT NULL DEFAULT 'scan',
    status TEXT NOT NULL DEFAULT 'running',
    queries INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    run_id INTEGER,
    kind TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    snippet TEXT NOT NULL DEFAULT '',
    identifier TEXT NOT NULL DEFAULT '',
    identifier_type TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence REAL NOT NULL DEFAULT 0.7,
    matched TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    notes TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);

CREATE TABLE IF NOT EXISTS removal_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_key TEXT NOT NULL UNIQUE,
    finding_id INTEGER,
    broker_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    verify_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'prepared',
    priority TEXT NOT NULL DEFAULT 'P2',
    created_at TEXT NOT NULL,
    submitted_at TEXT,
    due_at TEXT,
    last_checked_at TEXT,
    reference TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_status ON removal_requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_due ON removal_requests(due_at);

CREATE TABLE IF NOT EXISTS broker_status (
    broker_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'not_checked',
    updated_at TEXT,
    due_at TEXT,
    notes TEXT NOT NULL DEFAULT ''
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        ensure_private_dir(self.path.parent)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        ensure_private_file(self.path)

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------
    def start_run(self, mode: str = "scan") -> int:
        cursor = self.conn.execute(
            "INSERT INTO runs(started_at, mode, status) VALUES (?, ?, 'running')",
            (iso_now(), mode),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, summary: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ?, status = ?, queries = ?, requests = ?, errors = ?, summary_json = ? WHERE id = ?",
            (
                iso_now(),
                status,
                int(summary.get("queries_run", 0)),
                int(summary.get("requests", 0)),
                int(summary.get("errors", 0)),
                json.dumps(summary, ensure_ascii=False),
                run_id,
            ),
        )
        self.conn.commit()

    def list_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def upsert_finding(self, finding: Finding, run_id: int | None = None) -> tuple[int, bool, bool]:
        """Insert or update a finding.

        Returns (id, is_new, reappeared). User-managed statuses are preserved;
        a finding previously marked removed becomes ``reappeared`` if it is
        seen again in a later scan.
        """
        existing = self.conn.execute(
            "SELECT id, status, first_seen, details_json FROM findings WHERE fingerprint = ?",
            (finding.fingerprint,),
        ).fetchone()
        now = iso_now()
        if existing:
            reappeared = existing["status"] == "removed"
            status = "reappeared" if reappeared else existing["status"]
            details = dict(finding.details)
            try:
                old_details = json.loads(existing["details_json"] or "{}")
            except json.JSONDecodeError:
                old_details = {}
            if isinstance(old_details, dict):
                for key, value in old_details.items():
                    if key not in details:
                        details[key] = value
            self.conn.execute(
                """
                UPDATE findings SET
                    run_id = ?, kind = ?, category = ?, source = ?, title = ?, url = ?,
                    snippet = ?, severity = ?, confidence = ?, matched = ?,
                    details_json = ?, last_seen = ?, status = ?,
                    identifier = CASE WHEN ? != '' THEN ? ELSE identifier END,
                    identifier_type = CASE WHEN ? != '' THEN ? ELSE identifier_type END
                WHERE id = ?
                """,
                (
                    run_id,
                    finding.kind,
                    finding.category,
                    finding.source,
                    finding.title,
                    finding.url,
                    finding.snippet,
                    finding.severity,
                    finding.confidence,
                    finding.matched,
                    json.dumps(details, ensure_ascii=False),
                    now,
                    status,
                    finding.identifier,
                    finding.identifier,
                    finding.identifier_type,
                    finding.identifier_type,
                    existing["id"],
                ),
            )
            self.conn.commit()
            return int(existing["id"]), False, reappeared

        cursor = self.conn.execute(
            """
            INSERT INTO findings(
                fingerprint, run_id, kind, category, source, title, url, snippet,
                identifier, identifier_type, severity, confidence, matched,
                details_json, first_seen, last_seen, status, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', '')
            """,
            (
                finding.fingerprint,
                run_id,
                finding.kind,
                finding.category,
                finding.source,
                finding.title,
                finding.url,
                finding.snippet,
                finding.identifier,
                finding.identifier_type,
                finding.severity,
                finding.confidence,
                finding.matched,
                json.dumps(finding.details, ensure_ascii=False),
                finding.first_seen,
                now,
            ),
        )
        self.conn.commit()
        return int(cursor.lastrowid), True, False

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._decode_finding(row) if row else None

    def get_by_fingerprint(self, fingerprint_value: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint_value,)
        ).fetchone()
        return self._decode_finding(row) if row else None

    def find_by_url(self, url: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE url = ? ORDER BY id LIMIT 1", (url,)
        ).fetchone()
        return self._decode_finding(row) if row else None

    def list_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        kind: str | None = None,
        category: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status and status != "all":
            if status == "active":
                clauses.append("status NOT IN ('false_positive', 'removed')")
            else:
                clauses.append("status = ?")
                params.append(status)
        if severity and severity != "all":
            clauses.append("severity = ?")
            params.append(severity)
        if kind and kind != "all":
            clauses.append("kind = ?")
            params.append(kind)
        if category and category != "all":
            clauses.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"""
            SELECT * FROM findings {where}
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low' THEN 3 ELSE 4 END,
                confidence DESC, last_seen DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [self._decode_finding(row) for row in rows]

    def update_finding_title(self, finding_id: int, title: str) -> None:
        if not title:
            return
        self.conn.execute("UPDATE findings SET title = ? WHERE id = ?", (title, finding_id))
        self.conn.commit()

    def update_finding_details(self, finding_id: int, details: dict[str, Any]) -> dict[str, Any] | None:
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        self.conn.execute(
            "UPDATE findings SET details_json = ? WHERE id = ?",
            (json.dumps(details, ensure_ascii=False), finding_id),
        )
        self.conn.commit()
        return self.get_finding(finding_id)

    def update_finding(
        self,
        finding_id: int,
        status: str | None = None,
        notes: str | None = None,
        append_note: bool = True,
    ) -> dict[str, Any] | None:
        if status is not None and status not in FINDING_STATUSES:
            raise ValueError(f"invalid finding status: {status}")
        finding = self.get_finding(finding_id)
        if not finding:
            return None
        new_status = status or finding["status"]
        new_notes = finding["notes"]
        if notes is not None and notes.strip():
            if append_note and new_notes:
                new_notes = new_notes.rstrip() + "\n" + notes.strip()
            else:
                new_notes = notes.strip()
        self.conn.execute(
            "UPDATE findings SET status = ?, notes = ? WHERE id = ?",
            (new_status, new_notes, finding_id),
        )
        self.conn.commit()
        return self.get_finding(finding_id)

    def stats(self) -> dict[str, Any]:
        findings = self.list_findings(limit=10000)
        active = [item for item in findings if item["status"] not in {"false_positive", "removed"}]
        by_severity: dict[str, int] = {key: 0 for key in ["critical", "high", "medium", "low", "info"]}
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for item in findings:
            by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
            by_status[item["status"]] = by_status.get(item["status"], 0) + 1
            by_category[item["category"]] = by_category.get(item["category"], 0) + 1
            by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        weighted = sum(severity_weight(item["severity"]) for item in active)
        # A soft saturation curve keeps the score informative after the first
        # few findings instead of pinning every real exposure list at 100.
        score = int(round(100 * (1 - math.exp(-weighted / 80)))) if weighted else 0
        score = min(100, score)
        if score >= 70:
            band = "Severe"
        elif score >= 45:
            band = "High"
        elif score >= 20:
            band = "Moderate"
        else:
            band = "Low"
        return {
            "total": len(findings),
            "active": len(active),
            "removed": by_status.get("removed", 0),
            "score": score,
            "band": band,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_category": dict(sorted(by_category.items(), key=lambda pair: (-pair[1], pair[0]))),
            "by_kind": dict(sorted(by_kind.items(), key=lambda pair: (-pair[1], pair[0]))),
        }

    def category_breakdown(self) -> list[tuple[str, int]]:
        rows = self.conn.execute(
            "SELECT category, COUNT(*) AS count FROM findings GROUP BY category ORDER BY count DESC"
        ).fetchall()
        return [(row["category"], row["count"]) for row in rows]

    def _decode_finding(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        return item

    # ------------------------------------------------------------------
    # Removal requests
    # ------------------------------------------------------------------
    def create_request(self, request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        key = str(request["request_key"])
        existing = self.get_request_by_key(key)
        if existing:
            return existing, False
        now = iso_now()
        cursor = self.conn.execute(
            """
            INSERT INTO removal_requests(
                request_key, finding_id, broker_id, title, method, url, verify_url,
                status, priority, created_at, submitted_at, due_at, last_checked_at,
                reference, evidence, notes, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                request.get("finding_id"),
                request.get("broker_id", ""),
                request.get("title", ""),
                request.get("method", ""),
                request.get("url", ""),
                request.get("verify_url", ""),
                request.get("status", "prepared"),
                request.get("priority", "P2"),
                request.get("created_at") or now,
                request.get("submitted_at"),
                request.get("due_at"),
                request.get("last_checked_at"),
                request.get("reference", ""),
                request.get("evidence", ""),
                request.get("notes", ""),
                json.dumps(request.get("details", {}), ensure_ascii=False),
            ),
        )
        self.conn.commit()
        created = self.get_request(int(cursor.lastrowid))
        return created or {}, True

    def get_request(self, request_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM removal_requests WHERE id = ?", (request_id,)
        ).fetchone()
        return self._decode_request(row) if row else None

    def get_request_by_key(self, key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM removal_requests WHERE request_key = ?", (key,)
        ).fetchone()
        return self._decode_request(row) if row else None

    def list_requests(
        self,
        status: str | None = None,
        *,
        due_only: bool = False,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status and status != "all":
            if status == "open":
                clauses.append(
                    "status NOT IN ('removed', 'failed')"
                )
            else:
                clauses.append("status = ?")
                params.append(status)
        if due_only:
            clauses.append("due_at IS NOT NULL AND due_at != '' AND due_at <= ?")
            params.append(iso_now())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM removal_requests {where} ORDER BY "
            "CASE status WHEN 'reappeared' THEN 0 WHEN 'still_listed' THEN 1 "
            "WHEN 'submitted' THEN 2 WHEN 'in_progress' THEN 3 ELSE 4 END, "
            "due_at IS NULL, due_at, id LIMIT ?",
            params,
        ).fetchall()
        return [self._decode_request(row) for row in rows]

    def update_request(self, request_id: int, **fields: Any) -> dict[str, Any] | None:
        allowed = {
            "status",
            "priority",
            "submitted_at",
            "due_at",
            "last_checked_at",
            "reference",
            "evidence",
            "notes",
            "details",
            "title",
            "method",
            "url",
            "verify_url",
        }
        current = self.get_request(request_id)
        if not current:
            return None
        values: dict[str, Any] = {}
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"unsupported request field: {key}")
            if key == "details":
                values["details_json"] = json.dumps(value or {}, ensure_ascii=False)
            elif key == "notes":
                new_notes = str(value or "")
                if current.get("notes") and new_notes:
                    values["notes"] = current["notes"].rstrip() + "\n" + new_notes
                else:
                    values["notes"] = new_notes or current.get("notes", "")
            else:
                values[key] = value
        if not values:
            return current
        assignments = ", ".join(f"{key} = ?" for key in values)
        self.conn.execute(
            f"UPDATE removal_requests SET {assignments} WHERE id = ?",
            (*values.values(), request_id),
        )
        self.conn.commit()
        return self.get_request(request_id)

    def _decode_request(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
        return item

    def request_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS count FROM removal_requests GROUP BY status"
        ).fetchall()
        return {row["status"]: row["count"] for row in rows}

    # ------------------------------------------------------------------
    # Broker status
    # ------------------------------------------------------------------
    def get_broker_statuses(self) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM broker_status").fetchall()
        return {row["broker_id"]: dict(row) for row in rows}

    def update_broker(
        self,
        broker_id: str,
        status: str,
        notes: str | None = None,
        due_at: str | None = None,
    ) -> dict[str, Any]:
        if status not in BROKER_STATUSES:
            raise ValueError(f"invalid broker status: {status}")
        existing = self.conn.execute(
            "SELECT * FROM broker_status WHERE broker_id = ?", (broker_id,)
        ).fetchone()
        now = iso_now()
        if existing:
            new_notes = existing["notes"]
            if notes is not None and notes.strip():
                new_notes = (new_notes.rstrip() + "\n" + notes.strip()) if new_notes else notes.strip()
            self.conn.execute(
                "UPDATE broker_status SET status = ?, notes = ?, due_at = ?, updated_at = ? WHERE broker_id = ?",
                (status, new_notes, due_at if due_at is not None else existing["due_at"], now, broker_id),
            )
        else:
            self.conn.execute(
                "INSERT INTO broker_status(broker_id, status, updated_at, due_at, notes) VALUES (?, ?, ?, ?, ?)",
                (broker_id, status, now, due_at, (notes or "").strip()),
            )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM broker_status WHERE broker_id = ?", (broker_id,)
        ).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------
    def export_rows(self, status: str | None = None) -> list[dict[str, Any]]:
        return self.list_findings(status=status, limit=100000)

    def counts_by_status(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT status, COUNT(*) AS count FROM findings GROUP BY status").fetchall()
        return {row["status"]: row["count"] for row in rows}

    def status_summary(self, statuses: Iterable[str]) -> int:
        placeholders = ",".join("?" for _ in statuses)
        row = self.conn.execute(
            f"SELECT COUNT(*) AS count FROM findings WHERE status IN ({placeholders})",
            tuple(statuses),
        ).fetchone()
        return int(row["count"]) if row else 0
