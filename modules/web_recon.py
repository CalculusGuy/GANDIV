"""
GANDIV Web Reconnaissance Module
Technology fingerprinting, WAF detection, security header analysis, JS/secret
scanning, and discovery of commonly exposed files.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from gandiv.config import COMMON_PATHS, SECRET_PATTERNS, Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter

log = get_logger()
MODULE_NAME = "web_recon"

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Drupal": [r"Drupal.settings", r"/sites/default/files"],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "React": [r"__REACT_DEVTOOLS", r"react-root", r"data-reactroot"],
    "Vue.js": [r"__vue__", r"data-v-"],
    "Angular": [r"ng-version", r"ng-app"],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Express": [r"X-Powered-By: Express"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "Bootstrap": [r"bootstrap(\.min)?\.css"],
    "Nginx": [r"Server: nginx"],
    "Apache": [r"Server: Apache"],
    "PHP": [r"X-Powered-By: PHP", r"\.php"],
}

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF/CloudFront": ["x-amz-cf-id", "awselb"],
    "Akamai": ["akamai", "akamaighost"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap"],
    "F5 BIG-IP": ["bigipserver", "f5-"],
}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection",
]


def _base_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"https://{target.rstrip('/')}"


def _detect_tech(body: str, headers: dict) -> List[str]:
    found = []
    haystack = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    for tech, patterns in TECH_SIGNATURES.items():
        if any(re.search(p, haystack, re.IGNORECASE) for p in patterns):
            found.append(tech)
    return found


def _detect_waf(headers: dict, cookies: str) -> List[str]:
    found = []
    haystack = (" ".join(f"{k}:{v}" for k, v in headers.items()) + " " + cookies).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(sig in haystack for sig in sigs):
            found.append(waf)
    return found


def _analyze_headers(headers: dict) -> dict:
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    return {"present": present, "missing": missing}


def _extract_js_urls(base_url: str, body: str) -> List[str]:
    urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE)
    return list({urljoin(base_url, u) for u in urls})[:25]  # cap for politeness


def _scan_secrets(text: str, source_label: str) -> List[Finding]:
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            snippet = match.group(0)
            redacted = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else "[redacted]"
            findings.append(Finding(
                type="potential_secret", value=f"{name}: {redacted}", source=source_label,
                module=MODULE_NAME, confidence=Confidence.MEDIUM, risk=RiskLevel.HIGH,
                score=0.7, metadata={"secret_type": name, "location": source_label},
            ))
    return findings


def run(target: str, config: Config) -> ModuleResult:
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    base_url = _base_url(target)
    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        limiter.wait()
        resp = client.get(base_url, allow_redirects=True)
        if resp is not None:
            sources_used.append("http_fetch")
            headers = dict(resp.headers)
            cookies = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
            body = resp.text or ""

            for tech in _detect_tech(body, headers):
                findings.append(Finding(
                    type="technology", value=tech, source="fingerprint", module=MODULE_NAME,
                    confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.7,
                ))

            for waf in _detect_waf(headers, cookies):
                findings.append(Finding(
                    type="waf", value=waf, source="fingerprint", module=MODULE_NAME,
                    confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.7,
                ))

            header_analysis = _analyze_headers(headers)
            for h, v in header_analysis["present"].items():
                findings.append(Finding(
                    type="security_header_present", value=f"{h}: {v}", source="headers",
                    module=MODULE_NAME, confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.9,
                ))
            for h in header_analysis["missing"]:
                findings.append(Finding(
                    type="security_header_missing", value=h, source="headers", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=RiskLevel.MEDIUM, score=0.85,
                ))

            findings.extend(_scan_secrets(body, "html_body"))

            js_urls = _extract_js_urls(base_url, body)
            for js_url in js_urls:
                limiter.wait()
                js_resp = client.get(js_url)
                if js_resp is not None and js_resp.status_code == 200:
                    findings.extend(_scan_secrets(js_resp.text, js_url))
        else:
            sources_failed.append("http_fetch")

        # --- Common file / path discovery ---
        for path in COMMON_PATHS:
            limiter.wait()
            url = urljoin(base_url + "/", path)
            probe = client.head(url) or client.get(url)
            if probe is not None and probe.status_code == 200:
                findings.append(Finding(
                    type="exposed_path", value=path, source="path_discovery", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=(
                        RiskLevel.HIGH if path in (".env", ".git/config", "wp-config.php.bak", ".env.local")
                        else RiskLevel.LOW
                    ),
                    score=0.85, metadata={"url": url, "status_code": probe.status_code},
                ))
        sources_used.append("path_discovery")

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
