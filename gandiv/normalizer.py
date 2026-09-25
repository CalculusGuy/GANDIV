"""
GANDIV Finding Normalizer
Deduplicates findings across modules/sources, applies corroboration-weighted
confidence scoring, classifies risk, and filters obvious false positives.
"""
from __future__ import annotations

import re
from typing import Dict, List

from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, RiskLevel

log = get_logger()

# Base trust score per source, used when a finding doesn't already carry one.
SOURCE_BASE_SCORES: Dict[str, float] = {
    "crt.sh": 0.95,
    "whois": 0.90,
    "dns": 0.90,
    "virustotal": 0.85,
    "shodan": 0.85,
    "censys": 0.85,
    "hibp": 0.90,
    "ssl": 0.85,
    "hackertarget": 0.75,
    "wayback_machine": 0.70,
    "github": 0.65,
    "github_api": 0.65,
    "google_search": 0.50,
    "google_dork": 0.50,
    "paste_search": 0.50,
    "dork_generation": 1.0,
    "fingerprint": 0.65,
    "headers": 0.85,
    "path_discovery": 0.80,
    "pattern_generation": 0.40,
    "gravatar": 0.80,
    "cross_reference": 0.90,
}

# Obvious placeholder / test values that shouldn't be reported as findings.
FALSE_POSITIVE_VALUES = {
    "example.com", "test.com", "localhost", "127.0.0.1", "0.0.0.0",
    "your-email@example.com", "n/a", "none", "null", "undefined", "",
}

FALSE_POSITIVE_PATTERNS = [
    re.compile(r"^\*+$"),
    re.compile(r"^x{3,}$", re.IGNORECASE),
    re.compile(r"^placeholder", re.IGNORECASE),
]


def _score_to_confidence(score: float) -> Confidence:
    if score >= 0.80:
        return Confidence.HIGH
    if score >= 0.60:
        return Confidence.MEDIUM
    return Confidence.LOW


def is_false_positive(finding: Finding) -> bool:
    value = (finding.value or "").strip().lower()
    if value in FALSE_POSITIVE_VALUES:
        return True
    if any(p.match(value) for p in FALSE_POSITIVE_PATTERNS):
        return True
    return False


def _corroboration_bonus(n_sources: int) -> float:
    if n_sources >= 3:
        return 0.10
    if n_sources == 2:
        return 0.05
    return 0.0


def normalize(findings: List[Finding]) -> List[Finding]:
    """Deduplicate by (type, value), merge corroborating sources, recompute
    confidence, and drop obvious false positives. Returns a new list."""

    # Filter false positives first
    findings = [f for f in findings if not is_false_positive(f)]

    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.dedup_key(), []).append(f)

    normalized: List[Finding] = []
    for key, group in grouped.items():
        sources = sorted({f.source for f in group})
        base_scores = [
            f.score if f.score else SOURCE_BASE_SCORES.get(f.source, 0.5)
            for f in group
        ]
        base_score = max(base_scores)
        final_score = min(1.0, base_score + _corroboration_bonus(len(sources)))

        # Keep the richest finding as the representative, merge metadata
        representative = max(group, key=lambda f: len(f.metadata))
        merged_metadata = {}
        for f in group:
            merged_metadata.update(f.metadata)

        # Highest risk across the group wins (never silently downgrade risk)
        risk_order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        highest_risk = max((f.risk for f in group), key=lambda r: risk_order.index(r))

        normalized.append(Finding(
            type=representative.type,
            value=representative.value,
            source=sources[0] if len(sources) == 1 else "multiple",
            module=representative.module,
            confidence=_score_to_confidence(final_score),
            risk=highest_risk,
            score=round(final_score, 3),
            corroborated_by=sources,
            metadata=merged_metadata,
            first_seen=min(f.first_seen for f in group),
        ))

    log.info(f"Normalizer: {len(findings)} raw findings -> {len(normalized)} deduplicated findings")
    return sorted(normalized, key=lambda f: (-_risk_weight(f.risk), -f.score))


def _risk_weight(risk: RiskLevel) -> int:
    weights = {
        RiskLevel.CRITICAL: 4,
        RiskLevel.HIGH: 3,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 1,
        RiskLevel.INFO: 0,
    }
    return weights.get(risk, 0)
