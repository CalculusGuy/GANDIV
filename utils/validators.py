"""
GANDIV Input Validators
Target type detection, normalization, and assorted small helpers.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

from gandiv.models import TargetType

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,39}$")


def is_valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(DOMAIN_RE.match(value.strip().lower()))


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


def is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_private
    except ValueError:
        return False


def is_valid_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value.strip()))


def is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0]
    v = v.split(":")[0]
    if v.startswith("www."):
        v = v[4:]
    return v


def sanitize_filename(value: str) -> str:
    value = re.sub(r"[^\w\-.]", "_", value.strip())
    return value[:200] or "target"


def extract_domain_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.split(":")[0].lower()


def detect_target_type(raw: str) -> TargetType:
    """Best-effort auto-detection of what kind of target the user gave us."""
    value = raw.strip()

    if is_valid_url(value):
        return TargetType.URL
    if is_valid_ip(value):
        return TargetType.IP
    if is_valid_email(value):
        return TargetType.EMAIL
    if is_valid_domain(value):
        return TargetType.DOMAIN
    # Two capitalized words with no corporate suffix -> likely a person's name
    if re.match(r"^[A-Z][a-z]+ [A-Z][a-z]+$", value) and not re.search(
        r"\b(inc|llc|ltd|corp|corporation|technologies|pvt)\b", value, re.IGNORECASE
    ):
        return TargetType.PERSON
    # Org names typically contain spaces or a corporate suffix
    if re.search(r"\s", value) or re.search(r"\b(inc|llc|ltd|corp|corporation|technologies|pvt)\b", value, re.IGNORECASE):
        return TargetType.ORG
    # Bare word with no dots/spaces and valid handle characters -> username
    if is_valid_username(value) and "." not in value:
        return TargetType.USERNAME
    return TargetType.UNKNOWN


def normalize_target(raw: str, target_type: TargetType) -> str:
    if target_type == TargetType.DOMAIN:
        return normalize_domain(raw)
    if target_type == TargetType.URL:
        return raw.strip()
    if target_type == TargetType.EMAIL:
        return raw.strip().lower()
    if target_type == TargetType.IP:
        return raw.strip()
    if target_type == TargetType.USERNAME:
        return raw.strip().lstrip("@")
    return raw.strip()


def extract_name_parts(value: str) -> Optional[dict]:
    """Split 'John Smith' into first/last for email-pattern generation."""
    parts = [p for p in re.split(r"\s+", value.strip()) if p]
    if len(parts) < 2:
        return None
    first, last = parts[0], parts[-1]
    return {
        "first": first.lower(),
        "last": last.lower(),
        "f": first[0].lower(),
        "l": last[0].lower(),
    }


def is_subdomain_of(candidate: str, parent_domain: str) -> bool:
    candidate = candidate.strip().lower().rstrip(".")
    parent_domain = parent_domain.strip().lower().rstrip(".")
    return candidate == parent_domain or candidate.endswith("." + parent_domain)
