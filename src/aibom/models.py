from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class MatchEvidence:
    line: int
    snippet: str
    match: str


@dataclass(slots=True)
class Finding:
    finding_id: str
    rule_id: str
    category: str
    name: str
    severity: str
    confidence: str
    path: str
    detector: str
    entity_type: str
    source_kind: str
    summary: str
    evidence: list[MatchEvidence] = field(default_factory=list)
    metadata: dict[str, str | int | bool | list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["evidence"] = [asdict(item) for item in self.evidence]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Finding":
        evidence = [MatchEvidence(**item) for item in payload.get("evidence", [])]
        return cls(
            finding_id=payload["finding_id"],
            rule_id=payload["rule_id"],
            category=payload["category"],
            name=payload["name"],
            severity=payload["severity"],
            confidence=payload["confidence"],
            path=payload["path"],
            detector=payload["detector"],
            entity_type=payload["entity_type"],
            source_kind=payload["source_kind"],
            summary=payload["summary"],
            evidence=evidence,
            metadata=payload.get("metadata", {}),
        )


@dataclass(slots=True)
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0


@dataclass(slots=True)
class ScanResult:
    root: str
    findings: list[Finding]
    stats: ScanStats

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "summary": {
                "total_findings": len(self.findings),
                "files_scanned": self.stats.files_scanned,
                "files_skipped": self.stats.files_skipped,
                "bytes_scanned": self.stats.bytes_scanned,
            },
            "findings": [item.to_dict() for item in self.findings],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanResult":
        summary = payload.get("summary", {})
        return cls(
            root=payload["root"],
            findings=[Finding.from_dict(item) for item in payload.get("findings", [])],
            stats=ScanStats(
                files_scanned=int(summary.get("files_scanned", 0)),
                files_skipped=int(summary.get("files_skipped", 0)),
                bytes_scanned=int(summary.get("bytes_scanned", 0)),
            ),
        )
