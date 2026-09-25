"""
GANDIV Data Models
Core data structures shared across all modules.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TargetType(str, Enum):
    # Infrastructure / web
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    ORG = "org"
    WEB = "web"
    INFRA = "infra"

    # Generic people
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"

    # People OSINT (menu-driven)
    PEOPLE_EMAIL = "people-email"
    PEOPLE_PHONE = "people-phone"
    PEOPLE_USERNAME = "people-username"
    PEOPLE_NAME = "people-name"

    # Special
    PHONE = "phone"
    BREACH = "breach"
    IMAGE = "image"

    # Meta
    FULL = "full"
    CUSTOM = "custom"

    UNKNOWN = "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """A single, atomic piece of OSINT intelligence."""
    type: str
    value: str
    source: str
    module: str
    confidence: Confidence = Confidence.MEDIUM
    risk: RiskLevel = RiskLevel.INFO
    score: float = 0.5
    corroborated_by: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=_now_iso)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def dedup_key(self) -> str:
        return f"{self.type}:{self.value.strip().lower()}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        d["risk"] = self.risk.value
        return d


@dataclass
class ModuleResult:
    """Outcome of running one module against a target."""
    module_name: str
    success: bool
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    sources_used: List[str] = field(default_factory=list)
    sources_failed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_name": self.module_name,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 2),
            "sources_used": self.sources_used,
            "sources_failed": self.sources_failed,
        }


@dataclass
class Target:
    raw: str
    type: TargetType
    normalized: str

    def to_dict(self) -> Dict[str, Any]:
        return {"raw": self.raw, "type": self.type.value, "normalized": self.normalized}


@dataclass
class ScanResult:
    """Aggregated results for a complete scan of one target."""
    target: Target
    started_at: str = field(default_factory=_now_iso)
    finished_at: Optional[str] = None
    module_results: List[ModuleResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    stats: Dict[str, Any] = field(default_factory=dict)

    def compute_stats(self) -> None:
        by_conf: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_module: Dict[str, int] = {}
        for f in self.findings:
            by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1
            by_risk[f.risk.value] = by_risk.get(f.risk.value, 0) + 1
            by_type[f.type] = by_type.get(f.type, 0) + 1
            by_module[f.module] = by_module.get(f.module, 0) + 1
        self.stats = {
            "total_findings": len(self.findings),
            "by_confidence": by_conf,
            "by_risk": by_risk,
            "by_type": by_type,
            "by_module": by_module,
            "modules_run": len(self.module_results),
            "modules_succeeded": sum(1 for m in self.module_results if m.success),
            "modules_failed": sum(1 for m in self.module_results if not m.success),
        }

    def to_dict(self) -> Dict[str, Any]:
        self.compute_stats()
        return {
            "scan_id": self.scan_id,
            "target": self.target.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": self.stats,
            "module_results": [m.to_dict() for m in self.module_results],
            "findings": [f.to_dict() for f in self.findings],
        }