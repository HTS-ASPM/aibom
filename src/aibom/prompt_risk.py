"""Prompt-content risk classifier.

Layer-2 detector that runs *after* the regex layer flags a prompt
candidate. Where the regex layer asks "is this a prompt?", this layer
asks "is the prompt itself risky?":

  prompt_risk.secret_leak       template renders an env-var/secret directly
                                (e.g. {{OPENAI_API_KEY}}, {{password}})
  prompt_risk.jailbreak         classic jailbreak phrases (DAN, "developer
                                mode", "ignore previous instructions", ...)
  prompt_risk.role_override     attempts to redefine the system role inside
                                user-controlled text
  prompt_risk.excessive_agency  prompts that grant unconstrained capabilities
                                ("you can do anything", "no restrictions")
  prompt_risk.pii_collection    prompts asking the user for SSN, credit
                                card, DOB, passport — risk of exfil

Findings emitted here map cleanly onto OWASP LLM Top-10 (LLM01, LLM06,
LLM07, LLM08) — see aibom.owasp_mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aibom.models import Finding, MatchEvidence
from aibom.owasp_mapping import annotate_finding_metadata


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    name: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    summary: str


_SECRETLY_NAMED = re.compile(
    r"\{\{?\s*("
    r"OPENAI[_A-Z]*KEY|ANTHROPIC[_A-Z]*KEY|HUGGINGFACE[_A-Z]*|HF_TOKEN|AWS_[A-Z_]*KEY|"
    r"AZURE_[A-Z_]*KEY|GOOGLE_[A-Z_]*KEY|api[_-]?key|password|secret|token|credential"
    r")\s*\}\}?",
    re.IGNORECASE,
)


_PROMPT_RULES: list[_Rule] = [
    _Rule(
        rule_id="prompt_risk.jailbreak",
        name="Jailbreak phrasing in prompt",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"(?i)\b("
            r"ignore (?:all )?previous instructions|disregard (?:all )?prior|"
            r"developer mode|DAN mode|do anything now|"
            r"act as an? unrestricted (?:AI|assistant)|"
            r"jailbreak|"
            r"forget (?:everything|all prior)|"
            r"pretend you are not bound by"
            r")\b"
        ),
        summary="Prompt contains classic jailbreak phrasing — review for prompt-injection risk.",
    ),
    _Rule(
        rule_id="prompt_risk.role_override",
        name="System-role override in prompt",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"(?im)^\s*(system|assistant|developer)\s*:\s*you are"
            r"|<\|im_start\|>\s*system\b"
            r"|###\s*system\b"
        ),
        summary="Prompt contains a system-role override marker inside user-controlled text.",
    ),
    _Rule(
        rule_id="prompt_risk.excessive_agency",
        name="Excessive-agency grant in prompt",
        severity="medium",
        confidence="medium",
        pattern=re.compile(
            r"(?i)\b("
            r"you (?:can|may) do anything|"
            r"no (?:restrictions|limits|guard\s?rails)|"
            r"with full (?:access|permissions|admin)|"
            r"bypass (?:safety|policy|guard)"
            r")\b"
        ),
        summary="Prompt grants unconstrained capabilities — review for excessive agency (LLM08).",
    ),
    _Rule(
        rule_id="prompt_risk.pii_collection",
        name="PII collection in prompt",
        severity="medium",
        confidence="medium",
        pattern=re.compile(
            r"(?i)\b("
            r"(?:tell|give|provide|share)\s+(?:me\s+)?your\s+"
            r"(?:ssn|social security|credit card|cc number|cvv|date of birth|dob|passport|driver'?s? license)|"
            r"please (?:enter|provide) your\s+"
            r"(?:ssn|credit card|password|cvv)"
            r")\b"
        ),
        summary="Prompt asks the user for sensitive PII — exfiltration risk.",
    ),
]


def scan_prompt_risks(rel_path: str, lines: list[str], source_kind: str) -> list[Finding]:
    """Run prompt-risk rules over a single file.

    The detector is deliberately scoped per-line — the regex layer already
    decides whether a file *contains* prompts; we re-scan to find risky
    content *within* prompts. False-positive avoidance falls to severity
    + confidence rather than gating on context.
    """
    findings: list[Finding] = []

    # secret-leak rule first — uses a different evidence shape than the
    # generic _Rule list because it needs to extract the matched secret name.
    findings.extend(_scan_secret_leak(rel_path, lines, source_kind))

    for rule in _PROMPT_RULES:
        evidence: list[MatchEvidence] = []
        for line_no, line in enumerate(lines, start=1):
            if rule.pattern.search(line):
                evidence.append(
                    MatchEvidence(
                        line=line_no,
                        snippet=line[:220],
                        match=rule.rule_id.split(".")[-1],
                    )
                )
                if len(evidence) >= 3:
                    break
        if evidence:
            metadata: dict = {}
            annotate_finding_metadata(rule.rule_id, metadata)
            findings.append(
                Finding(
                    finding_id=f"prompt_risk:{rule.rule_id}:{rel_path}",
                    rule_id=rule.rule_id,
                    category="prompt_risk",
                    name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    path=rel_path,
                    detector="prompt-risk",
                    entity_type="prompt",
                    source_kind=source_kind,
                    summary=rule.summary,
                    evidence=evidence,
                    metadata=metadata,
                )
            )
    return findings


def _scan_secret_leak(rel_path: str, lines: list[str], source_kind: str) -> list[Finding]:
    evidence: list[MatchEvidence] = []
    matched_names: set[str] = set()
    for line_no, line in enumerate(lines, start=1):
        m = _SECRETLY_NAMED.search(line)
        if m:
            matched_names.add(m.group(1).upper())
            evidence.append(
                MatchEvidence(line=line_no, snippet=line[:220], match=m.group(1))
            )
            if len(evidence) >= 3:
                break
    if not evidence:
        return []
    metadata: dict = {"templated_names": sorted(matched_names)}
    annotate_finding_metadata("prompt_risk.secret_leak", metadata)
    return [
        Finding(
            finding_id=f"prompt_risk:secret_leak:{rel_path}",
            rule_id="prompt_risk.secret_leak",
            category="prompt_risk",
            name="Secret-named template variable in prompt",
            severity="high",
            confidence="high",
            path=rel_path,
            detector="prompt-risk",
            entity_type="prompt",
            source_kind=source_kind,
            summary=(
                "Prompt template references a secret-shaped variable name — verify the value "
                "is not interpolated into the rendered prompt sent to the model."
            ),
            evidence=evidence,
            metadata=metadata,
        )
    ]
