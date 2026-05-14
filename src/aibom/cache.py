"""Per-file fingerprint cache for incremental scans.

The cache is keyed by:

    (sha256(file_content), scanner_version)

When a key hits, the cached findings (per-file slice) are reused
instead of re-running the regex / dataset / prompt-risk layers. The
binary-artifact / IaC / GHA / MLflow layers are tree-level (not
per-file) so they aren't cached here — they're cheap.

Storage: a single SQLite file (default ~/.aibom/cache.db) sharing the
same on-disk neighborhood as the existing scan-history store.
Schema is intentionally tiny:

    file_findings(content_sha256, scanner_version, rel_path, payload_json)

Cache invalidation is automatic — when scanner_version bumps the cache
self-prunes on lookup. Manual reset: `aibom cache clear`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from aibom import __version__
from aibom.models import Finding


_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_findings (
    content_sha256   TEXT NOT NULL,
    scanner_version  TEXT NOT NULL,
    rel_path         TEXT NOT NULL,
    payload_json     TEXT NOT NULL,
    cached_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (content_sha256, scanner_version, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_file_findings_version ON file_findings(scanner_version);
"""


@dataclass(frozen=True, slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    inserted: int = 0


def default_cache_path() -> Path:
    return Path.home() / ".aibom" / "cache.db"


def open_cache(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or default_cache_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def fingerprint_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def lookup(
    conn: sqlite3.Connection,
    *,
    content_sha256: str,
    rel_path: str,
    scanner_version: str = __version__,
) -> list[Finding] | None:
    """Returns cached findings for this file or None on miss."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT payload_json FROM file_findings WHERE content_sha256=? AND scanner_version=? AND rel_path=?",
            (content_sha256, scanner_version, rel_path),
        )
        row = cur.fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row[0])
    except json.JSONDecodeError:
        return None
    return [Finding.from_dict(item) for item in payload]


def store(
    conn: sqlite3.Connection,
    *,
    content_sha256: str,
    rel_path: str,
    findings: list[Finding],
    scanner_version: str = __version__,
) -> None:
    """Idempotent — REPLACE so re-scans overwrite stale slices safely."""
    payload = json.dumps([f.to_dict() for f in findings])
    with closing(conn.cursor()) as cur:
        cur.execute(
            """INSERT OR REPLACE INTO file_findings
               (content_sha256, scanner_version, rel_path, payload_json)
               VALUES (?, ?, ?, ?)""",
            (content_sha256, scanner_version, rel_path, payload),
        )
    conn.commit()


def prune_other_versions(conn: sqlite3.Connection, *, scanner_version: str = __version__) -> int:
    with closing(conn.cursor()) as cur:
        cur.execute("DELETE FROM file_findings WHERE scanner_version != ?", (scanner_version,))
        deleted = cur.rowcount
    conn.commit()
    return deleted or 0


def clear_all(conn: sqlite3.Connection) -> int:
    with closing(conn.cursor()) as cur:
        cur.execute("DELETE FROM file_findings")
        deleted = cur.rowcount
    conn.commit()
    return deleted or 0


def stats_for_version(conn: sqlite3.Connection, *, scanner_version: str = __version__) -> dict[str, Any]:
    with closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT COUNT(*), MIN(cached_at), MAX(cached_at) FROM file_findings WHERE scanner_version=?",
            (scanner_version,),
        )
        count, min_ts, max_ts = cur.fetchone()
    return {
        "scanner_version": scanner_version,
        "rows": count or 0,
        "oldest_unix": min_ts,
        "newest_unix": max_ts,
    }


def relabel_findings_path(findings: Iterable[Finding], rel_path: str) -> list[Finding]:
    """When a cache hit happens at a different relative path (e.g. file moved)
    we update the path field in the cached findings before returning them.
    Helpful for monorepo refactors where content is identical but path differs.
    """
    out: list[Finding] = []
    for f in findings:
        if f.path == rel_path:
            out.append(f)
            continue
        out.append(Finding(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            category=f.category,
            name=f.name,
            severity=f.severity,
            confidence=f.confidence,
            path=rel_path,
            detector=f.detector,
            entity_type=f.entity_type,
            source_kind=f.source_kind,
            summary=f.summary,
            evidence=list(f.evidence),
            metadata=dict(f.metadata),
        ))
    return out
