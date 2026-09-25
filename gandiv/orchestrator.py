"""
GANDIV Orchestrator
Coordinates which modules run against a target, in what order, collects
results, normalizes findings, supports checkpoint/resume, dispatches
report generation, and optionally enriches results via Gemini LLM analysis.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel, ScanResult, Target, TargetType
from gandiv.normalizer import normalize
from gandiv.utils.validators import detect_target_type, normalize_target

from gandiv.modules import (
    domain_recon,
    web_recon,
    email_recon,
    person_recon,
    infra_recon,
    osint_aggregator,
)

# New people-OSINT modules — imported lazily so the tool still runs if a
# specific module has a missing optional dependency.
try:
    from gandiv.modules import email_osint
except ImportError:
    email_osint = None

try:
    from gandiv.modules import phone_osint
except ImportError:
    phone_osint = None

try:
    from gandiv.modules import username_osint
except ImportError:
    username_osint = None

try:
    from gandiv.modules import name_osint
except ImportError:
    name_osint = None

try:
    from gandiv.modules import breach_osint
except ImportError:
    breach_osint = None

try:
    from gandiv.modules import image_osint
except ImportError:
    image_osint = None

log = get_logger()

# Which modules apply to which target types.
MODULE_MAP = {
    # Existing infra / web
    TargetType.DOMAIN: ["domain_recon", "web_recon", "infra_recon", "osint_aggregator"],
    TargetType.URL: ["web_recon", "osint_aggregator"],
    TargetType.EMAIL: ["email_recon", "osint_aggregator"],
    TargetType.USERNAME: ["email_recon", "osint_aggregator"],
    TargetType.IP: ["infra_recon", "osint_aggregator"],
    TargetType.ORG: ["person_recon", "domain_recon", "osint_aggregator"],
    TargetType.PERSON: ["person_recon", "email_recon", "osint_aggregator"],

    # Menu-driven direct actions
    TargetType.WEB: ["web_recon"],
    TargetType.INFRA: ["infra_recon"],
    TargetType.BREACH: ["breach_osint"],
    TargetType.IMAGE: ["image_osint"],

    # People OSINT (menu-driven)
    TargetType.PEOPLE_EMAIL: ["email_osint", "breach_osint"],
    TargetType.PEOPLE_PHONE: ["phone_osint"],
    TargetType.PEOPLE_USERNAME: ["username_osint"],
    TargetType.PEOPLE_NAME: ["name_osint"],

    # Full sweep
    TargetType.FULL: [
        "domain_recon", "web_recon", "infra_recon",
        "email_recon", "person_recon",
        "osint_aggregator",
    ],
}


def _module_registry():
    """Resolve module name -> callable. Kept as a function so we can check
    for None at runtime (module may be missing)."""
    return {
        "domain_recon": domain_recon,
        "web_recon": web_recon,
        "email_recon": email_recon,
        "person_recon": person_recon,
        "infra_recon": infra_recon,
        "osint_aggregator": osint_aggregator,
        "email_osint": email_osint,
        "phone_osint": phone_osint,
        "username_osint": username_osint,
        "name_osint": name_osint,
        "breach_osint": breach_osint,
        "image_osint": image_osint,
    }


def _run_module(module_name: str, target: Target, config: Config,
                 prior_findings: Optional[List[Finding]] = None) -> ModuleResult:
    log.info(f"Running module: {module_name}")

    registry = _module_registry()
    module = registry.get(module_name)

    if module is None:
        log.warning(f"Module '{module_name}' is not available (import failed).")
        return ModuleResult(
            module_name=module_name,
            success=False,
            error=f"module '{module_name}' not available",
        )

    try:
        # ---- Existing modules ----
        if module_name == "domain_recon":
            domain = target.normalized
            if target.type == TargetType.ORG:
                domain = target.normalized.lower().replace(" ", "") + ".com"
            return module.run(domain, config)

        if module_name == "web_recon":
            return module.run(target.normalized, config)

        if module_name == "email_recon":
            return module.run(target.normalized, config)

        if module_name == "infra_recon":
            return module.run(target.normalized, config)

        if module_name == "person_recon":
            ttype = "org" if target.type == TargetType.ORG else "person"
            return module.run(target.normalized, config, target_type=ttype)

        if module_name == "osint_aggregator":
            return module.run(target.normalized, config, prior_findings=prior_findings)

        # ---- New people-OSINT modules ----
        if module_name == "email_osint":
            return module.run(target.normalized, config)

        if module_name == "phone_osint":
            return module.run(target.normalized, config)

        if module_name == "username_osint":
            return module.run(target.normalized, config)

        if module_name == "name_osint":
            return module.run(target.normalized, config)

        if module_name == "breach_osint":
            return module.run(target.normalized, config)

        if module_name == "image_osint":
            return module.run(target.normalized, config)

    except Exception as e:
        log.error(f"Module {module_name} crashed: {e}")
        return ModuleResult(module_name=module_name, success=False, error=str(e))

    return ModuleResult(module_name=module_name, success=False, error="unknown module")


def build_target(raw: str, forced_type: Optional[str] = None) -> Target:
    if forced_type:
        try:
            ttype = TargetType(forced_type)
        except ValueError:
            log.warning(f"Unknown forced type '{forced_type}', falling back to auto-detect")
            ttype = detect_target_type(raw)
    else:
        ttype = detect_target_type(raw)

    normalized = normalize_target(raw, ttype)
    return Target(raw=raw, type=ttype, normalized=normalized)


def run_scan(raw_target: str, config: Config, forced_type: Optional[str] = None,
             full: bool = False, threads: int = 10, parallel: bool = True,
             checkpoint_path: Optional[Path] = None) -> ScanResult:
    """Run a complete GANDIV scan against a target and return the aggregated result."""
    target = build_target(raw_target, forced_type)
    if target.type == TargetType.UNKNOWN:
        log.warning(f"Could not confidently detect target type for '{raw_target}'; defaulting to domain")
        target.type = TargetType.DOMAIN
        target.normalized = normalize_target(raw_target, TargetType.DOMAIN)

    log.info(f"Target detected as: {target.type.value} -> {target.normalized}")

    modules_to_run = MODULE_MAP.get(target.type, ["osint_aggregator"])

    if not full:
        modules_to_run = [m for m in modules_to_run if m != "osint_aggregator"] or modules_to_run

    scan = ScanResult(target=target)

    # osint_aggregator benefits from seeing findings gathered by other modules first
    ordered = [m for m in modules_to_run if m != "osint_aggregator"]
    run_aggregator = "osint_aggregator" in modules_to_run

    if parallel and len(ordered) > 1:
        with ThreadPoolExecutor(max_workers=min(threads, len(ordered))) as pool:
            futures = {pool.submit(_run_module, m, target, config): m for m in ordered}
            for fut in as_completed(futures):
                result = fut.result()
                scan.module_results.append(result)
                if checkpoint_path:
                    _save_checkpoint(scan, checkpoint_path)
    else:
        for m in ordered:
            result = _run_module(m, target, config)
            scan.module_results.append(result)
            if checkpoint_path:
                _save_checkpoint(scan, checkpoint_path)

    all_raw_findings: List[Finding] = []
    for mr in scan.module_results:
        all_raw_findings.extend(mr.findings)

    if run_aggregator:
        agg_result = _run_module("osint_aggregator", target, config, prior_findings=all_raw_findings)
        scan.module_results.append(agg_result)
        all_raw_findings.extend(agg_result.findings)
        if checkpoint_path:
            _save_checkpoint(scan, checkpoint_path)

    scan.findings = normalize(all_raw_findings)
    scan.finished_at = datetime.now(timezone.utc).isoformat()
    scan.compute_stats()

    # ---- LLM analysis via Gemini (if API key configured) ----
    try:
        from gandiv.llm_analyzer import analyze as llm_analyze
        llm_result = llm_analyze(target.normalized, scan.findings, config)
        if llm_result:
            scan.stats["llm_analysis"] = llm_result
            log.info("LLM analysis added to scan results")
    except Exception as e:
        log.warning(f"LLM analysis skipped: {e}")

    if checkpoint_path:
        _save_checkpoint(scan, checkpoint_path, final=True)

    log.info(
        f"Scan complete: {scan.stats['total_findings']} findings "
        f"({scan.stats['modules_succeeded']}/{scan.stats['modules_run']} modules succeeded)"
    )
    return scan


def _save_checkpoint(scan: ScanResult, path: Path, final: bool = False) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(scan.to_dict(), f, indent=2, default=str)
        if final:
            log.debug(f"Final checkpoint written to {path}")
    except OSError as e:
        log.warning(f"Could not write checkpoint: {e}")


def resume_scan(checkpoint_path: Path, config: Config) -> ScanResult:
    """Resume a scan from a checkpoint file: re-runs only modules that
    hadn't completed, then re-normalizes everything."""
    with open(checkpoint_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = Target(
        raw=data["target"]["raw"],
        type=TargetType(data["target"]["type"]),
        normalized=data["target"]["normalized"],
    )
    scan = ScanResult(target=target, scan_id=data.get("scan_id", ""))
    scan.started_at = data.get("started_at", scan.started_at)

    completed_modules = {m["module_name"] for m in data.get("module_results", []) if m.get("success")}
    all_modules = MODULE_MAP.get(target.type, ["osint_aggregator"])
    remaining = [m for m in all_modules if m not in completed_modules]

    log.info(f"Resuming scan {scan.scan_id}: {len(completed_modules)} modules already complete, "
             f"{len(remaining)} remaining")

    for m in data.get("module_results", []):
        if m["module_name"] in completed_modules:
            findings = [_finding_from_dict(fd) for fd in m.get("findings", [])]
            scan.module_results.append(ModuleResult(
                module_name=m["module_name"], success=m["success"], findings=findings,
                error=m.get("error"), duration_seconds=m.get("duration_seconds", 0.0),
                sources_used=m.get("sources_used", []), sources_failed=m.get("sources_failed", []),
            ))

    for m in remaining:
        result = _run_module(m, target, config,
                              prior_findings=[f for mr in scan.module_results for f in mr.findings])
        scan.module_results.append(result)

    all_findings = [f for mr in scan.module_results for f in mr.findings]
    scan.findings = normalize(all_findings)
    scan.finished_at = datetime.now(timezone.utc).isoformat()
    scan.compute_stats()

    # ---- LLM analysis via Gemini (if API key configured) ----
    try:
        from gandiv.llm_analyzer import analyze as llm_analyze
        llm_result = llm_analyze(target.normalized, scan.findings, config)
        if llm_result:
            scan.stats["llm_analysis"] = llm_result
            log.info("LLM analysis added to resumed scan results")
    except Exception as e:
        log.warning(f"LLM analysis skipped: {e}")

    return scan


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        type=d["type"], value=d["value"], source=d["source"], module=d["module"],
        confidence=Confidence(d.get("confidence", "medium")),
        risk=RiskLevel(d.get("risk", "info")),
        score=d.get("score", 0.5),
        corroborated_by=d.get("corroborated_by", []),
        metadata=d.get("metadata", {}),
        first_seen=d.get("first_seen", ""),
        id=d.get("id", ""),
    )