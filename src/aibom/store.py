from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from typing import Any
import uuid

from aibom.models import ScanResult


DEFAULT_DB_PATH = Path.home() / ".aibom" / "history.db"


@dataclass(slots=True)
class StoredScan:
    scan_id: str
    created_at: str
    command: str
    root: str
    output_format: str
    result: ScanResult


def get_db_path(path: str | None = None) -> Path:
    return Path(path).expanduser() if path else DEFAULT_DB_PATH


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                command TEXT NOT NULL,
                root TEXT NOT NULL,
                output_format TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan(result: ScanResult, command: str, output_format: str, db_path: str | None = None) -> str:
    resolved = get_db_path(db_path)
    init_db(resolved)
    scan_id = uuid.uuid4().hex[:12]
    created_at = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(result.to_dict(), sort_keys=True)
    with closing(sqlite3.connect(resolved)) as conn:
        conn.execute(
            """
            INSERT INTO scans (scan_id, created_at, command, root, output_format, result_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, created_at, command, result.root, output_format, payload),
        )
        conn.commit()
    return scan_id


def list_scans(db_path: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    resolved = get_db_path(db_path)
    init_db(resolved)
    with closing(sqlite3.connect(resolved)) as conn:
        rows = conn.execute(
            """
            SELECT scan_id, created_at, command, root, output_format, result_json
            FROM scans
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_summary(row) for row in rows]


def get_scan(scan_id: str, db_path: str | None = None) -> StoredScan:
    resolved = get_db_path(db_path)
    init_db(resolved)
    with closing(sqlite3.connect(resolved)) as conn:
        row = conn.execute(
            """
            SELECT scan_id, created_at, command, root, output_format, result_json
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
    if row is None:
        raise KeyError(f"Unknown scan id: {scan_id}")
    return row_to_scan(row)


def diff_scans(left_scan_id: str, right_scan_id: str, db_path: str | None = None) -> dict[str, Any]:
    left = get_scan(left_scan_id, db_path=db_path)
    right = get_scan(right_scan_id, db_path=db_path)

    left_raw = {finding_stable_identity(item): item for item in left.result.findings}
    right_raw = {finding_stable_identity(item): item for item in right.result.findings}
    ignored_identities = {
        key for key, item in {**left_raw, **right_raw}.items()
        if (key in left_raw and left_raw[key].metadata.get("baseline_ignore"))
        or (key in right_raw and right_raw[key].metadata.get("baseline_ignore"))
    }

    left_index = {key: item for key, item in left_raw.items() if key not in ignored_identities}
    right_index = {key: item for key, item in right_raw.items() if key not in ignored_identities}

    added = sorted(right_index.keys() - left_index.keys())
    removed = sorted(left_index.keys() - right_index.keys())
    shared = sorted(left_index.keys() & right_index.keys())
    severity_changes = []
    for key in shared:
        left_finding = left_index[key]
        right_finding = right_index[key]
        if left_finding.severity != right_finding.severity:
            severity_changes.append(
                {
                    "rule_id": left_finding.rule_id,
                    "path": left_finding.path,
                    "name": left_finding.name,
                    "from_severity": left_finding.severity,
                    "to_severity": right_finding.severity,
                }
            )

    return {
        "left_scan_id": left.scan_id,
        "right_scan_id": right.scan_id,
        "left_root": left.root,
        "right_root": right.root,
        "added": [serialize_identity(item) for item in added],
        "removed": [serialize_identity(item) for item in removed],
        "severity_changes": severity_changes,
        "unchanged_count": len(shared) - len(severity_changes),
    }


def row_to_summary(row: tuple[Any, ...]) -> dict[str, Any]:
    result = json.loads(row[5])
    summary = result.get("summary", {})
    return {
        "scan_id": row[0],
        "created_at": row[1],
        "command": row[2],
        "root": row[3],
        "output_format": row[4],
        "total_findings": summary.get("total_findings", 0),
        "files_scanned": summary.get("files_scanned", 0),
    }


def row_to_scan(row: tuple[Any, ...]) -> StoredScan:
    result = ScanResult.from_dict(json.loads(row[5]))
    return StoredScan(
        scan_id=row[0],
        created_at=row[1],
        command=row[2],
        root=row[3],
        output_format=row[4],
        result=result,
    )


def finding_identity(finding: Any) -> tuple[str, str, str, str]:
    return (finding.rule_id, finding.path, finding.name, finding.severity)


def finding_stable_identity(finding: Any) -> tuple[str, str, str]:
    return (finding.rule_id, finding.path, finding.name)




def serialize_identity(identity: tuple[str, ...]) -> dict[str, str]:
    payload = {
        "rule_id": identity[0],
        "path": identity[1],
        "name": identity[2],
    }
    if len(identity) > 3:
        payload["severity"] = identity[3]
    return payload
