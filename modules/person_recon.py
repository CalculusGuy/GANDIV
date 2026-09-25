"""
GANDIV Person / Organization Reconnaissance Module
LinkedIn / GitHub presence discovery via search engines and the GitHub API,
plus news mentions and simple leaked-credential-site search hooks.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote_plus

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter

log = get_logger()
MODULE_NAME = "person_recon"


def _google_search_snippet(query: str, client: HTTPClient) -> List[str]:
    """Lightweight scrape of a Google search results page. Best-effort only:
    Google may serve a consent/captcha page for automated clients, in which
    case this simply returns nothing rather than failing the whole module."""
    resp = client.get(f"https://www.google.com/search?q={quote_plus(query)}&num=10")
    if resp is None or resp.status_code != 200:
        return []
    import re
    links = re.findall(r'href="/url\?q=(https?://[^&"]+)', resp.text)
    seen, out = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out[:10]


def _github_search_users(query: str, client: HTTPClient, token: str = None) -> List[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.get(
        "https://api.github.com/search/users",
        params={"q": query, "per_page": 10},
        headers=headers,
    )
    if resp is None or resp.status_code != 200:
        return []
    try:
        return resp.json().get("items", [])
    except ValueError:
        return []


def _github_org(org_login: str, client: HTTPClient, token: str = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.get(f"https://api.github.com/orgs/{org_login}", headers=headers)
    if resp is None or resp.status_code != 200:
        return {}
    try:
        return resp.json()
    except ValueError:
        return {}


def run(target: str, config: Config, target_type: str = "person") -> ModuleResult:
    """Run person/org OSINT. `target_type` is 'person' or 'org'."""
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        # --- LinkedIn presence via search engine (no direct scraping of LinkedIn) ---
        limiter.wait()
        li_results = _google_search_snippet(f'site:linkedin.com/in "{target}"', client)
        if li_results:
            sources_used.append("google_search")
            for url in li_results:
                if "linkedin.com/in" in url:
                    findings.append(Finding(
                        type="linkedin_profile", value=url, source="google_search",
                        module=MODULE_NAME, confidence=Confidence.LOW, risk=RiskLevel.INFO,
                        score=0.5,
                    ))
        else:
            sources_failed.append("google_search (linkedin)")

        # --- News / media mentions ---
        limiter.wait()
        news_results = _google_search_snippet(f'"{target}" news', client)
        for url in news_results[:5]:
            findings.append(Finding(
                type="media_mention", value=url, source="google_search", module=MODULE_NAME,
                confidence=Confidence.LOW, risk=RiskLevel.INFO, score=0.4,
            ))

        # --- GitHub ---
        gh_users = _github_search_users(target, client, config.api_keys.github)
        if gh_users:
            sources_used.append("github_api")
            for u in gh_users:
                findings.append(Finding(
                    type="github_account", value=u.get("login", ""), source="github_api",
                    module=MODULE_NAME, confidence=Confidence.MEDIUM, risk=RiskLevel.INFO,
                    score=0.65, metadata={"profile_url": u.get("html_url")},
                ))
        else:
            sources_failed.append("github_api")

        if target_type == "org":
            org_data = _github_org(target.replace(" ", "").lower(), client, config.api_keys.github)
            if org_data:
                sources_used.append("github_org")
                for key in ("name", "blog", "email", "location", "public_repos"):
                    if org_data.get(key):
                        findings.append(Finding(
                            type=f"org_{key}", value=str(org_data[key]), source="github_api",
                            module=MODULE_NAME, confidence=Confidence.HIGH, risk=RiskLevel.INFO,
                            score=0.85,
                        ))

        # --- Pastebin / leaked credential surface search (search-engine based, non-intrusive) ---
        limiter.wait()
        paste_results = _google_search_snippet(f'"{target}" site:pastebin.com', client)
        for url in paste_results[:5]:
            findings.append(Finding(
                type="pastebin_mention", value=url, source="google_search", module=MODULE_NAME,
                confidence=Confidence.LOW, risk=RiskLevel.MEDIUM, score=0.5,
                metadata={"note": "manual review required - potential credential/data leak"},
            ))

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
