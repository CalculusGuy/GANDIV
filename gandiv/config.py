"""
GANDIV Configuration Management
Loads API keys and runtime settings from environment variables / .env file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv is optional; fall back to plain os.environ
    pass


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    val = os.environ.get(key, default)
    return val if val not in ("", None) else default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


@dataclass
class APIKeys:
    virustotal: Optional[str] = field(default_factory=lambda: _env("VT_API_KEY"))
    shodan: Optional[str] = field(default_factory=lambda: _env("SHODAN_API_KEY"))
    censys_id: Optional[str] = field(default_factory=lambda: _env("CENSYS_API_ID"))
    censys_secret: Optional[str] = field(default_factory=lambda: _env("CENSYS_API_SECRET"))
    hibp: Optional[str] = field(default_factory=lambda: _env("HIBP_API_KEY"))
    dehashed_email: Optional[str] = field(default_factory=lambda: _env("DEHASHED_EMAIL"))
    dehashed_key: Optional[str] = field(default_factory=lambda: _env("DEHASHED_API_KEY"))
    github: Optional[str] = field(default_factory=lambda: _env("GITHUB_TOKEN"))
    gemini: Optional[str] = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    numverify: Optional[str] = field(default_factory=lambda: _env("NUMVERIFY_API_KEY"))

    def has(self, name: str) -> bool:
        return bool(getattr(self, name, None))


@dataclass
class RateLimits:
    """Requests-per-second ceilings, per source, to stay polite to free APIs."""
    default_rps: float = field(default_factory=lambda: _env_float("GANDIV_DEFAULT_RPS", 3.0))
    crtsh_rps: float = 1.0
    hackertarget_rps: float = 1.0
    wayback_rps: float = 2.0
    shodan_rps: float = 1.0
    censys_rps: float = 1.0
    hibp_rps: float = 1.5  # HIBP enforces its own throttling server-side
    github_rps: float = 2.0
    platform_check_rps: float = 8.0  # username enumeration across platforms
    gemini_rps: float = 1.0  # Gemini free tier limits


# Common first/last-name based email patterns used for enumeration
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{l}@{domain}",
    "{first}@{domain}",
    "{last}.{first}@{domain}",
    "{first}_{last}@{domain}",
    "{f}.{last}@{domain}",
    "{last}@{domain}",
]

# Files/paths commonly probed during web recon (kept deliberately small & non-destructive)
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".env.local", ".git/config",
    "config.php.bak", "web.config", ".well-known/security.txt",
    "package.json", "composer.json", "wp-config.php.bak",
    ".DS_Store", "backup.zip", "admin/", "server-status",
]

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,45}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Private Key Block": r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic Secret": r"(?i)(secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][^'\"]{8,64}['\"]",
    "Firebase URL": r"[a-z0-9-]+\.firebaseio\.com",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
}


@dataclass
class Config:
    api_keys: APIKeys = field(default_factory=APIKeys)
    rate_limits: RateLimits = field(default_factory=RateLimits)

    output_dir: Path = field(default_factory=lambda: Path(_env("GANDIV_OUTPUT_DIR", "gandiv_reports")))
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".gandiv" / "cache")
    log_dir: Path = field(default_factory=lambda: Path.home() / ".gandiv" / "logs")
    checkpoint_dir: Path = field(default_factory=lambda: Path.home() / ".gandiv" / "checkpoints")

    default_timeout: int = field(default_factory=lambda: _env_int("GANDIV_TIMEOUT", 10))
    max_retries: int = field(default_factory=lambda: _env_int("GANDIV_MAX_RETRIES", 3))
    default_threads: int = field(default_factory=lambda: _env_int("GANDIV_THREADS", 10))
    user_agent: str = "GANDIV-OSINT/1.0 (+authorized-recon)"
    debug: bool = field(default_factory=lambda: _env("GANDIV_DEBUG", "0") == "1")

    def ensure_dirs(self) -> None:
        for d in (self.output_dir, self.cache_dir, self.log_dir, self.checkpoint_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_config() -> Config:
    cfg = Config()
    cfg.ensure_dirs()
    return cfg