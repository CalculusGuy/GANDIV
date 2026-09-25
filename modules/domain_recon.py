"""
GANDIV Domain Reconnaissance Module
Certificate Transparency, subdomain enumeration, DNS records, WHOIS,
zone transfer attempts, and Wayback Machine historical URLs.
"""
from __future__ import annotations

import json
import time
from typing import List, Set

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter
from gandiv.utils.validators import is_subdomain_of

log = get_logger()

MODULE_NAME = "domain_recon"


def _crtsh_subdomains(domain: str, client: HTTPClient, limiter: RateLimiter) -> Set[str]:
    subs: Set[str] = set()
    limiter.wait()
    resp = client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not resp or resp.status_code != 200:
        return subs
    try:
        entries = json.loads(resp.text)
    except (json.JSONDecodeError, ValueError):
        return subs
    for entry in entries:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lstrip("*.").lower()
            if line and is_subdomain_of(line, domain) and "*" not in line:
                subs.add(line)
    return subs


def _hackertarget_subdomains(domain: str, client: HTTPClient, limiter: RateLimiter) -> Set[str]:
    subs: Set[str] = set()
    limiter.wait()
    resp = client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not resp or resp.status_code != 200 or "error" in resp.text.lower():
        return subs
    for line in resp.text.strip().split("\n"):
        host = line.split(",")[0].strip().lower()
        if host and is_subdomain_of(host, domain):
            subs.add(host)
    return subs


def _wayback_urls(domain: str, client: HTTPClient, limiter: RateLimiter, limit: int = 200) -> List[str]:
    limiter.wait()
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    resp = client.get(url)
    if not resp or resp.status_code != 200:
        return []
    try:
        rows = resp.json()
    except (json.JSONDecodeError, ValueError):
        return []
    return [r[0] for r in rows[1:]] if rows else []  # skip header row


def _dns_records(domain: str) -> dict:
    records: dict = {}
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for rtype in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"):
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r).strip('"') for r in answers]
            except Exception:
                continue
    except ImportError:
        log.debug("dnspython not installed; skipping DNS record enumeration")
    return records


def _attempt_zone_transfer(domain: str, nameservers: List[str]) -> List[str]:
    """Attempt AXFR against each authoritative nameserver. Almost always
    refused on properly configured domains -- that refusal is itself a
    (non-)finding worth noting when it *succeeds*."""
    results: List[str] = []
    try:
        import dns.zone
        import dns.query
        import dns.resolver
        for ns in nameservers:
            try:
                ns_host = ns.rstrip(".")
                answers = dns.resolver.resolve(ns_host, "A", lifetime=5)
                ns_ip = str(answers[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                names = [str(n) for n in zone.nodes.keys()]
                if names:
                    results.append(ns_host)
            except Exception:
                continue
    except ImportError:
        pass
    return results


def _whois_lookup(domain: str) -> dict:
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        return {
            "registrar": _first(w.get("registrar")),
            "creation_date": _stringify(w.get("creation_date")),
            "expiration_date": _stringify(w.get("expiration_date")),
            "updated_date": _stringify(w.get("updated_date")),
            "name_servers": _listify(w.get("name_servers")),
            "org": _first(w.get("org")),
            "emails": _listify(w.get("emails")),
            "country": _first(w.get("country")),
        }
    except ImportError:
        log.debug("python-whois not installed; skipping WHOIS lookup")
        return {}
    except Exception as e:
        log.debug(f"WHOIS lookup failed for {domain}: {e}")
        return {}


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _listify(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _stringify(v):
    v = _first(v)
    return str(v) if v is not None else None


def run(target: str, config: Config) -> ModuleResult:
    """Run full domain reconnaissance against `target` (a bare domain)."""
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    try:
        # --- Certificate Transparency ---
        crt_limiter = RateLimiter(config.rate_limits.crtsh_rps)
        crt_subs = _crtsh_subdomains(target, client, crt_limiter)
        if crt_subs:
            sources_used.append("crt.sh")
            for sub in crt_subs:
                findings.append(Finding(
                    type="subdomain", value=sub, source="crt.sh", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.95,
                    metadata={"discovery_method": "certificate_transparency"},
                ))
        else:
            sources_failed.append("crt.sh")

        # --- HackerTarget passive DNS ---
        ht_limiter = RateLimiter(config.rate_limits.hackertarget_rps)
        ht_subs = _hackertarget_subdomains(target, client, ht_limiter)
        if ht_subs:
            sources_used.append("hackertarget")
            for sub in ht_subs:
                findings.append(Finding(
                    type="subdomain", value=sub, source="hackertarget", module=MODULE_NAME,
                    confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.75,
                    metadata={"discovery_method": "passive_dns"},
                ))
        else:
            sources_failed.append("hackertarget")

        # --- DNS records for the apex domain ---
        dns_records = _dns_records(target)
        if dns_records:
            sources_used.append("dns")
            for rtype, values in dns_records.items():
                for val in values:
                    findings.append(Finding(
                        type=f"dns_{rtype.lower()}", value=val, source="dns", module=MODULE_NAME,
                        confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.9,
                        metadata={"record_type": rtype},
                    ))
        else:
            sources_failed.append("dns")

        # --- Zone transfer attempt ---
        ns_records = dns_records.get("NS", [])
        if ns_records:
            vulnerable_ns = _attempt_zone_transfer(target, ns_records)
            for ns in vulnerable_ns:
                findings.append(Finding(
                    type="zone_transfer_allowed", value=ns, source="dns", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=RiskLevel.CRITICAL, score=0.98,
                    metadata={"nameserver": ns, "note": "AXFR succeeded - full zone disclosed"},
                ))

        # --- WHOIS ---
        whois_data = _whois_lookup(target)
        if whois_data:
            sources_used.append("whois")
            for key, val in whois_data.items():
                if not val:
                    continue
                items = val if isinstance(val, list) else [val]
                for item in items:
                    findings.append(Finding(
                        type=f"whois_{key}", value=str(item), source="whois", module=MODULE_NAME,
                        confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.9,
                    ))
        else:
            sources_failed.append("whois")

        # --- Wayback Machine historical URLs ---
        wb_limiter = RateLimiter(config.rate_limits.wayback_rps)
        wb_urls = _wayback_urls(target, client, wb_limiter)
        if wb_urls:
            sources_used.append("wayback_machine")
            for u in wb_urls[:200]:
                findings.append(Finding(
                    type="historical_url", value=u, source="wayback_machine", module=MODULE_NAME,
                    confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.7,
                ))
        else:
            sources_failed.append("wayback_machine")

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
