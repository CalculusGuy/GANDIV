"""
GANDIV Infrastructure Reconnaissance Module
IP resolution, ASN lookup, Shodan/Censys integration, SSL/TLS certificate
analysis, and basic cloud storage bucket enumeration.
"""
from __future__ import annotations

import socket
import ssl
import time
from typing import List

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Confidence, Finding, ModuleResult, RiskLevel
from gandiv.utils.http_client import HTTPClient, RateLimiter
from gandiv.utils.validators import is_valid_ip

log = get_logger()
MODULE_NAME = "infra_recon"

BUCKET_PROVIDERS = {
    "AWS S3": "https://{name}.s3.amazonaws.com",
    "GCP Storage": "https://storage.googleapis.com/{name}",
    "Azure Blob": "https://{name}.blob.core.windows.net",
}


def _resolve_ips(hostname: str, timeout: float = 5.0) -> List[str]:
    ips = set()
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(hostname, None, family)
                ips.update(i[4][0] for i in infos)
            except (socket.gaierror, socket.timeout):
                continue
    except Exception as e:
        log.debug(f"DNS resolution failed for {hostname}: {e}")
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return sorted(ips)


def _asn_lookup(ip: str, client: HTTPClient) -> dict:
    resp = client.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
    if resp is None or resp.status_code != 200 or "error" in resp.text.lower():
        return {}
    parts = resp.text.strip().strip('"').split(",")
    if len(parts) >= 3:
        return {"ip": parts[0], "asn": parts[1], "org": ",".join(parts[2:])}
    return {}


def _shodan_lookup(ip: str, client: HTTPClient, api_key: str) -> dict:
    resp = client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key})
    if resp is None or resp.status_code != 200:
        return {}
    try:
        return resp.json()
    except ValueError:
        return {}


def _censys_lookup(ip: str, client: HTTPClient, api_id: str, api_secret: str) -> dict:
    resp = client.get(
        f"https://search.censys.io/api/v2/hosts/{ip}",
        auth=(api_id, api_secret),
    )
    if resp is None or resp.status_code != 200:
        return {}
    try:
        return resp.json().get("result", {})
    except ValueError:
        return {}


def _ssl_cert_info(hostname: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cert_bin = ssock.getpeercert(binary_form=True)
        # Reconnect properly to get parsed cert with verification off, cert may be empty
        # dict when verify_mode is CERT_NONE; fall back to a minimal summary.
        san = []
        if cert.get("subjectAltName"):
            san = [v for k, v in cert["subjectAltName"] if k == "DNS"]
        return {
            "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {},
            "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {},
            "not_after": cert.get("notAfter"),
            "not_before": cert.get("notBefore"),
            "san": san,
            "has_cert": cert_bin is not None,
        }
    except Exception as e:
        log.debug(f"SSL cert fetch failed for {hostname}: {e}")
        return {}


def _check_bucket(name: str, client: HTTPClient) -> List[dict]:
    hits = []
    for provider, template in BUCKET_PROVIDERS.items():
        url = template.format(name=name)
        resp = client.get(url)
        if resp is not None and resp.status_code in (200, 403):
            # 403 still confirms the bucket *exists* (access denied vs not found)
            hits.append({"provider": provider, "url": url, "status_code": resp.status_code})
    return hits


def run(target: str, config: Config) -> ModuleResult:
    """Run infra recon against a hostname or bare IP."""
    start = time.time()
    findings: List[Finding] = []
    sources_used: List[str] = []
    sources_failed: List[str] = []

    client = HTTPClient(timeout=config.default_timeout, max_retries=config.max_retries,
                         user_agent=config.user_agent)
    limiter = RateLimiter(config.rate_limits.default_rps)

    try:
        ips = [target] if is_valid_ip(target) else _resolve_ips(target)
        if ips:
            sources_used.append("dns_resolution")
            for ip in ips:
                findings.append(Finding(
                    type="resolved_ip", value=ip, source="dns", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.9,
                ))
        else:
            sources_failed.append("dns_resolution")

        for ip in ips[:5]:  # cap external API calls
            limiter.wait()
            asn = _asn_lookup(ip, client)
            if asn:
                sources_used.append("asn_lookup")
                findings.append(Finding(
                    type="asn", value=asn.get("asn", ""), source="hackertarget", module=MODULE_NAME,
                    confidence=Confidence.MEDIUM, risk=RiskLevel.INFO, score=0.75,
                    metadata={"org": asn.get("org"), "ip": ip},
                ))

            if config.api_keys.has("shodan"):
                limiter.wait()
                shodan_data = _shodan_lookup(ip, client, config.api_keys.shodan)
                if shodan_data:
                    sources_used.append("shodan")
                    for port_data in shodan_data.get("data", []):
                        port = port_data.get("port")
                        product = port_data.get("product", "unknown")
                        findings.append(Finding(
                            type="open_port", value=f"{ip}:{port}", source="shodan",
                            module=MODULE_NAME, confidence=Confidence.HIGH,
                            risk=RiskLevel.MEDIUM if port not in (80, 443) else RiskLevel.LOW,
                            score=0.9, metadata={"product": product, "port": port},
                        ))
                    for vuln in shodan_data.get("vulns", []):
                        findings.append(Finding(
                            type="cve_exposure", value=vuln, source="shodan", module=MODULE_NAME,
                            confidence=Confidence.HIGH, risk=RiskLevel.CRITICAL, score=0.95,
                            metadata={"ip": ip},
                        ))
                else:
                    sources_failed.append("shodan")
            else:
                sources_failed.append("shodan (no api key)")

            if config.api_keys.has("censys_id") and config.api_keys.has("censys_secret"):
                limiter.wait()
                censys_data = _censys_lookup(ip, client, config.api_keys.censys_id,
                                              config.api_keys.censys_secret)
                if censys_data:
                    sources_used.append("censys")
                    for svc in censys_data.get("services", []):
                        findings.append(Finding(
                            type="open_service", value=f"{ip}:{svc.get('port')}", source="censys",
                            module=MODULE_NAME, confidence=Confidence.HIGH, risk=RiskLevel.MEDIUM,
                            score=0.9, metadata={"service_name": svc.get("service_name")},
                        ))
                else:
                    sources_failed.append("censys")
            else:
                sources_failed.append("censys (no api key)")

        if not is_valid_ip(target):
            cert = _ssl_cert_info(target)
            if cert:
                sources_used.append("ssl_analysis")
                findings.append(Finding(
                    type="ssl_certificate", value=target, source="ssl", module=MODULE_NAME,
                    confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.9,
                    metadata=cert,
                ))
                for san in cert.get("san", []):
                    findings.append(Finding(
                        type="ssl_san_entry", value=san, source="ssl", module=MODULE_NAME,
                        confidence=Confidence.HIGH, risk=RiskLevel.INFO, score=0.85,
                    ))
            else:
                sources_failed.append("ssl_analysis")

            base_name = target.split(".")[0]
            bucket_hits = _check_bucket(base_name, client)
            if bucket_hits:
                sources_used.append("bucket_enum")
                for hit in bucket_hits:
                    findings.append(Finding(
                        type="cloud_bucket", value=hit["url"], source=hit["provider"],
                        module=MODULE_NAME, confidence=Confidence.MEDIUM,
                        risk=RiskLevel.HIGH if hit["status_code"] == 200 else RiskLevel.MEDIUM,
                        score=0.7, metadata=hit,
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
