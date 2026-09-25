"""
GANDIV OSINT Aggregator Module
Google/GitHub dork generation, pastebin-style text-site search, and
cross-referencing of findings already collected earlier in the scan.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import quote_plus

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter

log = get_logger()
MODULE_NAME = "osint_aggregator"

GOOGLE_DORK_TEMPLATES = [
    'site:{target} filetype:pdf',
    'site:{target} filetype:xlsx OR filetype:csv',
    'site:{target} intitle:"index of"',
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} "confidential" OR "internal use only"',
    'site:{target} ext:log',
    'site:{target} ext:sql',
    'site:{target} inurl:wp-content',
]

GITHUB_DORK_TEMPLATES = [
    '"{target}" password',
    '"{target}" api_key',
    '"{target}" secret',
    '"{target}" filename:.env',
    '"{target}" filename:config',
]


def generate_google_dorks(target: str) -> List[str]:
    return [d.format(target=target) for d in GOOGLE_DORK_TEMPLATES]


def generate_github_dorks(target: str) -> List[str]:
    return [d.format(target=target) for d in GITHUB_DORK_TEMPLATES]


def _github_code_search(query: str, client: HTTPClient, token: str = None) -> List[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        return []  # code search requires auth on GitHub's API
    resp = client.get(
        "https://api.github.com/search/code",
        params={"q": query, "per_page": 10},
        headers=headers,
    )
    if resp is None or resp.status_code != 200:
        return []
    try:
        return resp.json().get("items", [])
    except ValueError:
        return []


def _search_engine_dork(dork: str, client: HTTPClient) -> List[str]:
    import re
    resp = client.get(f"https://www.google.com/search?q={quote_plus(dork)}&num=10")
    if resp is None or resp.status_code != 200:
        return []
    links = re.findall(r'href="/url\?q=(https?://[^&"]+)', resp.text)
    seen, out = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out[:5]


def cross_reference(prior_findings: List[Finding]) -> List[Finding]:
    """Look across findings already gathered (e.g. by domain_recon and
    web_recon) for corroboration -- same value discovered by 2+ sources
    gets an evidentiary bump, surfaced here as a synthesized finding."""
    by_key: Dict[str, List[Finding]] = {}
    for f in prior_findings:
        by_key.setdefault(f.dedup_key(), []).append(f)

    synthesized = []
    for key, group in by_key.items():
        sources = {f.source for f in group}
        if len(sources) >= 2:
            best = max(group, key=lambda f: f.score)
            synthesized.append(Finding(
                type="corroborated_finding", value=best.value, source="cross_reference",
                module=MODULE_NAME, confidence=Confidence.HIGH, risk=best.risk,
                score=min(1.0, best.score + 0.1),
                corroborated_by=sorted(sources),
                metadata={"original_type": best.type, "source_count": len(sources)},
            ))
    return synthesized


def run(target: str, config: Config, prior_findings: List[Finding] = None) -> ModuleResult:
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        # --- Google dorks (best-effort; search engines may block automation) ---
        dorks = generate_google_dorks(target)
        any_dork_hit = False
        for dork in dorks:
            limiter.wait()
            results = _search_engine_dork(dork, client)
            if results:
                any_dork_hit = True
                for url in results:
                    findings.append(Finding(
                        type="dork_result", value=url, source="google_dork", module=MODULE_NAME,
                        confidence=Confidence.LOW, risk=RiskLevel.MEDIUM, score=0.5,
                        metadata={"dork": dork},
                    ))
        # Always record which dorks were generated, even with zero hits --
        # useful for the analyst to run manually if automation was blocked.
        for dork in dorks:
            findings.append(Finding(
                type="generated_dork", value=dork, source="dork_generation", module=MODULE_NAME,
                confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=1.0,
                metadata={"engine": "google"},
            ))
        sources_used.append("dork_generation")
        if any_dork_hit:
            sources_used.append("google_dork")
        else:
            sources_failed.append("google_dork (no automated hits)")

        # --- GitHub dorks ---
        gh_dorks = generate_github_dorks(target)
        for dork in gh_dorks:
            findings.append(Finding(
                type="generated_dork", value=dork, source="dork_generation", module=MODULE_NAME,
                confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=1.0,
                metadata={"engine": "github"},
            ))
            if config.api_keys.has("github"):
                limiter.wait()
                hits = _github_code_search(dork, client, config.api_keys.github)
                if hits:
                    sources_used.append("github_code_search")
                    for h in hits:
                        findings.append(Finding(
                            type="github_code_match", value=h.get("html_url", ""), source="github",
                            module=MODULE_NAME, confidence=Confidence.MEDIUM, risk=RiskLevel.HIGH,
                            score=0.75, metadata={"dork": dork, "repo": h.get("repository", {}).get("full_name")},
                        ))
        if not config.api_keys.has("github"):
            sources_failed.append("github_code_search (no api key)")

        # --- Pastebin / text-paste site search ---
        limiter.wait()
        paste_results = _search_engine_dork(f'"{target}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com', client)
        if paste_results:
            sources_used.append("paste_site_search")
            for url in paste_results:
                findings.append(Finding(
                    type="paste_mention", value=url, source="paste_search", module=MODULE_NAME,
                    confidence=Confidence.LOW, risk=RiskLevel.MEDIUM, score=0.5,
                    metadata={"note": "manual review required"},
                ))
        else:
            sources_failed.append("paste_site_search")

        # --- Cross-reference against everything gathered earlier in the scan ---
        if prior_findings:
            corroborated = cross_reference(prior_findings)
            if corroborated:
                sources_used.append("cross_reference")
                findings.extend(corroborated)

    finally:
        client.close()

    return ModuleResult(
        module_name=MODULE_NAME,
        success=len(sources_used) > 0,
        findings=findings,
        duration_seconds=time.time() - start,
        sources_used=sources_used,
        sources_failed=sources_failed,
    )
