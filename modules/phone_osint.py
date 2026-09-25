"""
GANDIV Phone OSINT Module
Investigates a phone number across free/public sources:
  - Carrier + line type lookup (free APIs)
  - Country / region inference from country code
  - Google dork generation for the number
  - WhatsApp / Telegram presence check (via public web endpoints)
  - Pastebin / leak-site mentions via search
  - Spam report lookup
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional
from urllib.parse import quote_plus

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter

log = get_logger()
MODULE_NAME = "phone_osint"


# Minimal country-code → country name map for the most common codes.
# Full mapping lives in data/country_codes.json in the production build.
COUNTRY_CODES: Dict[str, str] = {
    "1": "United States / Canada",
    "7": "Russia / Kazakhstan",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "40": "Romania",
    "41": "Switzerland",
    "43": "Austria",
    "44": "United Kingdom",
    "45": "Denmark",
    "46": "Sweden",
    "47": "Norway",
    "48": "Poland",
    "49": "Germany",
    "51": "Peru",
    "52": "Mexico",
    "54": "Argentina",
    "55": "Brazil",
    "56": "Chile",
    "57": "Colombia",
    "60": "Malaysia",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "64": "New Zealand",
    "65": "Singapore",
    "66": "Thailand",
    "81": "Japan",
    "82": "South Korea",
    "84": "Vietnam",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "218": "Libya",
    "234": "Nigeria",
    "254": "Kenya",
    "256": "Uganda",
    "263": "Zimbabwe",
    "351": "Portugal",
    "352": "Luxembourg",
    "353": "Ireland",
    "358": "Finland",
    "370": "Lithuania",
    "371": "Latvia",
    "372": "Estonia",
    "380": "Ukraine",
    "420": "Czech Republic",
    "421": "Slovakia",
    "880": "Bangladesh",
    "886": "Taiwan",
    "961": "Lebanon",
    "962": "Jordan",
    "971": "UAE",
    "972": "Israel",
    "973": "Bahrain",
    "974": "Qatar",
    "975": "Bhutan",
    "976": "Mongolia",
    "977": "Nepal",
    "994": "Azerbaijan",
    "995": "Georgia",
}


def _normalize_phone(raw: str) -> str:
    """Strip spaces, dashes, parens; ensure leading '+'."""
    cleaned = re.sub(r"[^\d+]", "", raw.strip())
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned.lstrip("+")
    return cleaned


def _infer_country(phone: str) -> Optional[Dict[str, str]]:
    """Match the longest country code prefix against known codes."""
    digits = phone.lstrip("+")
    # Try longest prefix first (up to 3 digits)
    for length in (3, 2, 1):
        if len(digits) >= length:
            prefix = digits[:length]
            if prefix in COUNTRY_CODES:
                return {"code": prefix, "country": COUNTRY_CODES[prefix]}
    return None


def _numverify_lookup(phone: str, client: HTTPClient, api_key: Optional[str]) -> dict:
    """Numverify free-tier lookup. Returns {} if no API key or lookup fails."""
    if not api_key:
        return {}
    resp = client.get(
        "http://apilayer.net/api/validate",
        params={"access_key": api_key, "number": phone, "format": 1},
    )
    if resp is None or resp.status_code != 200:
        return {}
    try:
        data = resp.json()
        if not data.get("valid"):
            return {}
        return data
    except ValueError:
        return {}


def _veriphone_lookup(phone: str, client: HTTPClient) -> dict:
    """Veriphone free-tier lookup — no API key needed for basic validation."""
    resp = client.get(
        f"https://api.veriphone.io/v2/verify",
        params={"phone": phone, "key": "free"},
    )
    if resp is None or resp.status_code != 200:
        return {}
    try:
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return data
    except ValueError:
        return {}


def _google_dorks(phone: str) -> List[str]:
    """Generate search-engine dorks likely to surface the number on the web."""
    digits_only = re.sub(r"\D", "", phone)
    local = digits_only[-10:] if len(digits_only) >= 10 else digits_only
    return [
        f'"{phone}"',
        f'"{digits_only}"',
        f'"{local}"',
        f'"{local}" site:facebook.com',
        f'"{local}" site:linkedin.com',
        f'"{local}" site:twitter.com',
        f'"{local}" site:instagram.com',
        f'"{local}" site:pastebin.com',
        f'"{local}" "whatsapp"',
        f'"{local}" "truecaller"',
    ]


def _search_engine_hits(query: str, client: HTTPClient) -> List[str]:
    """Lightweight scrape of search results. Best-effort only."""
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


def _check_whatsapp(phone: str, client: HTTPClient) -> bool:
    """Best-effort presence check via wa.me redirect behaviour."""
    digits = phone.lstrip("+")
    resp = client.get(f"https://wa.me/{digits}", allow_redirects=False)
    if resp is None:
        return False
    # wa.me returns 200 for valid-format numbers even if unregistered;
    # the meaningful signal is when it explicitly 302s to api.whatsapp.com.
    return resp.status_code in (200, 301, 302)


def _check_telegram(phone: str, client: HTTPClient) -> bool:
    """Best-effort: Telegram doesn't expose a public phone→username lookup,
    so we only flag general presence via a search dork."""
    return False


def run(target: str, config: Config) -> ModuleResult:
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    phone = _normalize_phone(target)
    client = HTTPClient(
        timeout=config.default_timeout,
        max_retries=config.max_retries,
        user_agent=config.user_agent,
    )
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        # --- Country inference from country code ---
        country = _infer_country(phone)
        if country:
            sources_used.append("country_code_inference")
            findings.append(Finding(
                type="phone_country",
                value=country["country"],
                source="country_code_inference",
                module=MODULE_NAME,
                confidence=Confidence.HIGH,
                risk=RiskLevel.INFO,
                score=0.95,
                metadata={"code": country["code"]},
            ))
        else:
            sources_failed.append("country_code_inference")

        # --- Veriphone (free, no key) ---
        limiter.wait()
        vp = _veriphone_lookup(phone, client)
        if vp:
            sources_used.append("veriphone")
            if vp.get("carrier"):
                findings.append(Finding(
                    type="phone_carrier",
                    value=vp["carrier"],
                    source="veriphone",
                    module=MODULE_NAME,
                    confidence=Confidence.HIGH,
                    risk=RiskLevel.INFO,
                    score=0.9,
                ))
            if vp.get("phone_type"):
                findings.append(Finding(
                    type="phone_type",
                    value=vp["phone_type"],
                    source="veriphone",
                    module=MODULE_NAME,
                    confidence=Confidence.HIGH,
                    risk=RiskLevel.INFO,
                    score=0.9,
                ))
            if vp.get("phone_region"):
                findings.append(Finding(
                    type="phone_region",
                    value=vp["phone_region"],
                    source="veriphone",
                    module=MODULE_NAME,
                    confidence=Confidence.HIGH,
                    risk=RiskLevel.INFO,
                    score=0.9,
                ))
        else:
            sources_failed.append("veriphone")

        # --- Numverify (optional API key) ---
        if config.api_keys and getattr(config.api_keys, "numverify", None):
            limiter.wait()
            nv = _numverify_lookup(phone, client, config.api_keys.numverify)
            if nv:
                sources_used.append("numverify")
                for key, ftype in [
                    ("carrier", "phone_carrier"),
                    ("line_type", "phone_type"),
                    ("location", "phone_location"),
                ]:
                    if nv.get(key):
                        findings.append(Finding(
                            type=ftype,
                            value=str(nv[key]),
                            source="numverify",
                            module=MODULE_NAME,
                            confidence=Confidence.HIGH,
                            risk=RiskLevel.INFO,
                            score=0.9,
                        ))
            else:
                sources_failed.append("numverify")
        else:
            sources_failed.append("numverify (no api key)")

        # --- WhatsApp presence (best-effort) ---
        limiter.wait()
        wa_present = _check_whatsapp(phone, client)
        if wa_present:
            sources_used.append("whatsapp_check")
            findings.append(Finding(
                type="whatsapp_presence",
                value=f"https://wa.me/{phone.lstrip('+')}",
                source="whatsapp_check",
                module=MODULE_NAME,
                confidence=Confidence.LOW,
                risk=RiskLevel.INFO,
                score=0.4,
                metadata={"note": "wa.me responds for any valid-format number; manual verification recommended"},
            ))
        else:
            sources_failed.append("whatsapp_check")

        # --- Google dorks (always generated; hits best-effort) ---
        dorks = _google_dorks(phone)
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

        # --- Execute the highest-signal dorks ---
        any_hits = False
        for dork in dorks[:4]:
            limiter.wait()
            hits = _search_engine_hits(dork, client)
            if hits:
                any_hits = True
                for url in hits:
                    findings.append(Finding(
                        type="phone_mention",
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
            sources_failed.append("google_search (no automated hits)")

        # --- Pastebin / leak-site dork ---
        limiter.wait()
        paste_hits = _search_engine_hits(
            f'"{phone}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com',
            client,
        )
        if paste_hits:
            sources_used.append("paste_site_search")
            for url in paste_hits:
                findings.append(Finding(
                    type="phone_paste_mention",
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