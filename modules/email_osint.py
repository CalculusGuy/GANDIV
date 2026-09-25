"""
GANDIV Email OSINT Module
Investigates an email address across public sources:
  - HIBP breach lookup (optional API key)
  - Holehe-style registration check (best-effort, low confidence)
  - Gravatar profile lookup
  - Google dork generation for the email
  - Pastebin / leak-site mentions via search
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import quote_plus

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import AsyncHTTPClient, HTTPClient, RateLimiter

log = get_logger()
MODULE_NAME = "email_osint"


# ──────────────────────────────────────────────────────────────────────
# Registration check sites
#
# IMPORTANT: These checks are BEST-EFFORT and LOW CONFIDENCE.
# Most login/signup pages return HTTP 200 regardless of whether the email
# is actually registered. Real Holehe uses response-time deltas, specific
# error strings, and per-site API endpoints. This simplified version can
# only give a weak signal that an email MIGHT be registered somewhere.
# Treat all `email_registered_on` findings as LOW confidence and verify
# manually.
# ──────────────────────────────────────────────────────────────────────

REGISTRATION_SITES: List[Tuple[str, str, str, str]] = [
    # name, url_template, method, positive_indicator
    ("GitHub",      "https://api.github.com/search/users?q={email}+in:email", "GET", "status_200"),
    ("Reddit",      "https://www.reddit.com/login", "GET", "status_200"),
    ("Twitter",     "https://api.twitter.com/i/users/email_available.json?email={email}", "GET", "text:valid"),
]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _google_dorks(email: str) -> List[str]:
    return [
        f'"{email}"',
        f'"{email}" site:pastebin.com',
        f'"{email}" site:linkedin.com',
        f'"{email}" site:github.com',
        f'"{email}" filetype:pdf',
        f'"{email}" filetype:xlsx',
        f'"{email}" "password"',
        f'"{email}" "leak"',
    ]


def _search_engine_hits(query: str, client: HTTPClient) -> List[str]:
    resp = client.get(f"https://www.google.com/search?q={quote_plus(query)}&num=10")
    if resp is None or resp.status_code != 200:
        return []
    links = re.findall(r'href="/url\?q=(https?://[^&"]+)', resp.text)
    seen, out = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out[:5]


def _gravatar_lookup(email: str, client: HTTPClient) -> Optional[dict]:
    """Gravatar's public profile endpoint — returns profile JSON if it exists."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    resp = client.get(f"https://gravatar.com/{email_hash}.json")
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.json().get("entry", [{}])[0]
    except (ValueError, IndexError):
        return None


def _hibp_lookup(email: str, client: HTTPClient, api_key: str) -> List[dict]:
    resp = client.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={"hibp-api-key": api_key, "User-Agent": "GANDIV-OSINT"},
        params={"truncateResponse": "false"},
    )
    if resp is None or resp.status_code == 404:
        return []
    if resp.status_code == 200:
        try:
            return resp.json()
        except ValueError:
            return []
    return []


# ──────────────────────────────────────────────────────────────────────
# Async registration check
# ──────────────────────────────────────────────────────────────────────

async def _check_site_async(name: str, url_template: str, method: str,
                             indicator: str, email: str,
                             client: AsyncHTTPClient) -> Optional[Finding]:
    url = url_template.format(email=email)
    try:
        result = await client.get(url)
        if not result:
            return None

        status = result["status"]
        body = result.get("text", "") or ""

        hit = False
        if indicator == "status_200" and status == 200:
            hit = True
        elif indicator == "not_404" and status not in (404,):
            hit = True
        elif indicator.startswith("text:") and indicator.split(":", 1)[1].lower() in body.lower():
            hit = True

        if not hit:
            return None

        # LOW confidence — this is a weak signal, not proof of registration.
        return Finding(
            type="email_may_be_registered",
            value=name,
            source="holehe_style_check",
            module=MODULE_NAME,
            confidence=Confidence.LOW,
            risk=RiskLevel.INFO,
            score=0.35,
            metadata={
                "url": url,
                "status_code": status,
                "note": "best-effort signal — manual verification required",
            },
        )
    except Exception:
        return None


async def _check_all_sites(email: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    async with AsyncHTTPClient(timeout=config.default_timeout, concurrency=10,
                                user_agent=config.user_agent) as client:
        tasks = [
            _check_site_async(name, url, method, indicator, email, client)
            for (name, url, method, indicator) in REGISTRATION_SITES
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Finding):
            findings.append(r)
    return findings


# ──────────────────────────────────────────────────────────────────────
# Main entry
# ──────────────────────────────────────────────────────────────────────

def run(target: str, config: Config) -> ModuleResult:
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    email = target.strip().lower()
    client = HTTPClient(
        timeout=config.default_timeout,
        max_retries=config.max_retries,
        user_agent=config.user_agent,
    )
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        # --- Gravatar ---
        limiter.wait()
        grav = _gravatar_lookup(email, client)
        if grav:
            sources_used.append("gravatar")
            for key in ("displayName", "aboutMe", "profileUrl", "preferredUsername"):
                if grav.get(key):
                    findings.append(Finding(
                        type=f"gravatar_{key}",
                        value=str(grav[key]),
                        source="gravatar",
                        module=MODULE_NAME,
                        confidence=Confidence.HIGH,
                        risk=RiskLevel.INFO,
                        score=0.85,
                    ))
            if grav.get("accounts"):
                for acc in grav["accounts"]:
                    findings.append(Finding(
                        type="gravatar_linked_account",
                        value=acc.get("url", ""),
                        source="gravatar",
                        module=MODULE_NAME,
                        confidence=Confidence.HIGH,
                        risk=RiskLevel.INFO,
                        score=0.85,
                        metadata={"shortname": acc.get("shortname")},
                    ))
        else:
            sources_failed.append("gravatar")

        # --- HIBP breach lookup (optional API key) ---
        if config.api_keys and getattr(config.api_keys, "hibp", None):
            limiter.wait()
            breaches = _hibp_lookup(email, client, config.api_keys.hibp)
            if breaches:
                sources_used.append("hibp")
                for b in breaches:
                    findings.append(Finding(
                        type="breach_exposure",
                        value=b.get("Name", "unknown"),
                        source="hibp",
                        module=MODULE_NAME,
                        confidence=Confidence.HIGH,
                        risk=RiskLevel.HIGH,
                        score=0.95,
                        metadata={
                            "breach_date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                            "pwn_count": b.get("PwnCount"),
                        },
                    ))
            else:
                sources_used.append("hibp (no breaches found)")
        else:
            sources_failed.append("hibp (no api key)")

        # --- Holehe-style registration checks (low confidence) ---
        try:
            registrations = asyncio.run(_check_all_sites(email, config))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                registrations = loop.run_until_complete(_check_all_sites(email, config))
            finally:
                loop.close()

        if registrations:
            sources_used.append("holehe_style_check")
            findings.extend(registrations)
        else:
            sources_failed.append("holehe_style_check")

        # --- Google dorks (always generated) ---
        dorks = _google_dorks(email)
        for dork in dorks:
            findings.append(Finding(
                type="generated_dork",
                value=dork,
                source="dork_generation",
                module=MODULE_NAME,
                confidence=Confidence.HIGH,
                risk=RiskLevel.INFO,
                score=1.0,
                metadata={"engine": "google"},
            ))
        sources_used.append("dork_generation")

        # --- Execute a few dorks ---
        any_hits = False
        for dork in dorks[:4]:
            limiter.wait()
            hits = _search_engine_hits(dork, client)
            if hits:
                any_hits = True
                for url in hits:
                    findings.append(Finding(
                        type="email_mention",
                        value=url,
                        source="google_search",
                        module=MODULE_NAME,
                        confidence=Confidence.LOW,
                        risk=RiskLevel.MEDIUM,
                        score=0.5,
                        metadata={"dork": dork},
                    ))
        if any_hits:
            sources_used.append("google_search")
        else:
            sources_failed.append("google_search")

        # --- Pastebin dork ---
        limiter.wait()
        paste_hits = _search_engine_hits(
            f'"{email}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com',
            client,
        )
        if paste_hits:
            sources_used.append("paste_site_search")
            for url in paste_hits:
                findings.append(Finding(
                    type="email_paste_mention",
                    value=url,
                    source="paste_search",
                    module=MODULE_NAME,
                    confidence=Confidence.LOW,
                    risk=RiskLevel.HIGH,
                    score=0.55,
                    metadata={"note": "manual review required — potential leak"},
                ))
        else:
            sources_failed.append("paste_site_search")

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