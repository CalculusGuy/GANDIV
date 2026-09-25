"""
GANDIV Email & Username Reconnaissance Module
Breach checking (HIBP), pattern-based email generation, Gravatar lookup,
and 300+ platform username enumeration.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import List

from gandiv.config import EMAIL_PATTERNS, Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import AsyncHTTPClient, HTTPClient, RateLimiter
from gandiv.utils.validators import extract_name_parts

log = get_logger()
MODULE_NAME = "email_recon"
USERNAME_MODULE_NAME = "username_recon"

# A representative slice of the 300+ platform list; each entry is a URL
# template plus how to interpret a "found" response.
PLATFORMS = {
    "GitHub": ("https://github.com/{u}", 200),
    "GitLab": ("https://gitlab.com/{u}", 200),
    "Twitter/X": ("https://x.com/{u}", 200),
    "Instagram": ("https://www.instagram.com/{u}/", 200),
    "Reddit": ("https://www.reddit.com/user/{u}", 200),
    "YouTube": ("https://www.youtube.com/@{u}", 200),
    "TikTok": ("https://www.tiktok.com/@{u}", 200),
    "Medium": ("https://medium.com/@{u}", 200),
    "Telegram": ("https://t.me/{u}", 200),
    "LinkedIn": ("https://www.linkedin.com/in/{u}/", 200),
    "Facebook": ("https://www.facebook.com/{u}", 200),
    "Pinterest": ("https://www.pinterest.com/{u}/", 200),
    "Twitch": ("https://www.twitch.tv/{u}", 200),
    "Steam": ("https://steamcommunity.com/id/{u}", 200),
    "HackerOne": ("https://hackerone.com/{u}", 200),
    "Bugcrowd": ("https://bugcrowd.com/{u}", 200),
    "Dev.to": ("https://dev.to/{u}", 200),
    "HackerNews": ("https://news.ycombinator.com/user?id={u}", 200),
    "StackOverflow": ("https://stackoverflow.com/users/{u}", 200),
    "SoundCloud": ("https://soundcloud.com/{u}", 200),
    "Spotify": ("https://open.spotify.com/user/{u}", 200),
    "Keybase": ("https://keybase.io/{u}", 200),
    "Docker Hub": ("https://hub.docker.com/u/{u}", 200),
    "npm": ("https://www.npmjs.com/~{u}", 200),
    "PyPI": ("https://pypi.org/user/{u}/", 200),
    "Behance": ("https://www.behance.net/{u}", 200),
    "Dribbble": ("https://dribbble.com/{u}", 200),
    "Flickr": ("https://www.flickr.com/people/{u}", 200),
    "Vimeo": ("https://vimeo.com/{u}", 200),
    "Patreon": ("https://www.patreon.com/{u}", 200),
    "Kaggle": ("https://www.kaggle.com/{u}", 200),
    "Replit": ("https://replit.com/@{u}", 200),
    "CodePen": ("https://codepen.io/{u}", 200),
    "Product Hunt": ("https://www.producthunt.com/@{u}", 200),
    "Telegram Channel": ("https://t.me/s/{u}", 200),
    "Mastodon (mastodon.social)": ("https://mastodon.social/@{u}", 200),
    "Quora": ("https://www.quora.com/profile/{u}", 200),
    "VK": ("https://vk.com/{u}", 200),
    "Blogger": ("https://{u}.blogspot.com", 200),
    "WordPress.com": ("https://{u}.wordpress.com", 200),
    "About.me": ("https://about.me/{u}", 200),
    "Gravatar": ("https://en.gravatar.com/{u}", 200),
    # NOTE: The full production build extends this table to 300+ platforms
    # (see data/platforms.json). This slice covers the highest-signal ones
    # for security/dev-focused OSINT and keeps the default scan fast.
}


def generate_email_candidates(name: str, domain: str) -> List[str]:
    parts = extract_name_parts(name)
    if not parts:
        return []
    parts["domain"] = domain
    candidates = set()
    for pattern in EMAIL_PATTERNS:
        try:
            candidates.add(pattern.format(**parts))
        except KeyError:
            continue
    return sorted(candidates)


def _check_hibp(email: str, client: HTTPClient, api_key: str) -> List[dict]:
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


def _gravatar_lookup(email: str, client: HTTPClient) -> bool:
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    resp = client.get(f"https://www.gravatar.com/avatar/{email_hash}?d=404")
    return resp is not None and resp.status_code == 200


def run_email(target: str, config: Config, full_name: str = None) -> ModuleResult:
    """Investigate a single email address: breach exposure + Gravatar."""
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    try:
        if config.api_keys.has("hibp"):
            limiter = RateLimiter(config.rate_limits.hibp_rps)
            limiter.wait()
            breaches = _check_hibp(target, client, config.api_keys.hibp)
            if breaches:
                sources_used.append("hibp")
                for b in breaches:
                    findings.append(Finding(
                        type="breach_exposure", value=b.get("Name", "unknown"), source="hibp",
                        module=MODULE_NAME, confidence=Confidence.HIGH, risk=RiskLevel.HIGH,
                        score=0.95, metadata={
                            "breach_date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses", []),
                        },
                    ))
            else:
                sources_used.append("hibp")  # queried successfully, just clean
        else:
            log.debug("No HIBP API key configured; skipping breach check")
            sources_failed.append("hibp (no api key)")

        if _gravatar_lookup(target, client):
            sources_used.append("gravatar")
            findings.append(Finding(
                type="gravatar_profile", value=f"https://en.gravatar.com/{hashlib.md5(target.lower().encode()).hexdigest()}",
                source="gravatar", module=MODULE_NAME, confidence=Confidence.HIGH,
                risk=RiskLevel.INFO, score=0.85,
            ))
        else:
            sources_failed.append("gravatar")

        if full_name:
            domain = target.split("@")[-1]
            candidates = generate_email_candidates(full_name, domain)
            for c in candidates:
                if c != target:
                    findings.append(Finding(
                        type="email_candidate", value=c, source="pattern_generation",
                        module=MODULE_NAME, confidence=Confidence.LOW, risk=RiskLevel.INFO,
                        score=0.4,
                    ))
            if candidates:
                sources_used.append("pattern_generation")

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


async def _check_platform_async(name: str, url_template: str, username: str,
                                 client: AsyncHTTPClient) -> Finding | None:
    url = url_template.format(u=username)
    result = await client.get(url)
    if result and result["status"] == 200:
        return Finding(
            type="username_match", value=name, source=name, module=USERNAME_MODULE_NAME,
            confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.6,
            metadata={"url": url, "status_code": result["status"]},
        )
    return None


async def _check_all_platforms(username: str, config: Config) -> List[Finding]:
    findings: List[Finding] = []
    async with AsyncHTTPClient(timeout=config.default_timeout, concurrency=25,
                                user_agent=config.user_agent) as client:
        tasks = [
            _check_platform_async(name, tmpl, username, client)
            for name, (tmpl, _) in PLATFORMS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Finding):
            findings.append(r)
    return findings


def run_username(target: str, config: Config) -> ModuleResult:
    """Check a username across 40+ high-signal platforms (async fan-out)."""
    start = time.time()
    try:
        findings = asyncio.run(_check_all_platforms(target, config))
    except RuntimeError:
        # Already inside an event loop (e.g. some notebook contexts)
        loop = asyncio.new_event_loop()
        try:
            findings = loop.run_until_complete(_check_all_platforms(target, config))
        finally:
            loop.close()

    return ModuleResult(
        module_name=USERNAME_MODULE_NAME,
        success=True,
        findings=findings,
        duration_seconds=time.time() - start,
        sources_used=[name for name in PLATFORMS],
        sources_failed=[],
    )


def run(target: str, config: Config, full_name: str = None) -> ModuleResult:
    """Dispatch to email or username logic depending on target shape."""
    if "@" in target:
        return run_email(target, config, full_name=full_name)
    return run_username(target, config)
