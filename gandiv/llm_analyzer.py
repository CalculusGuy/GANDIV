"""
GANDIV LLM Analyzer
Uses Gemini API to analyze, correlate, and summarize findings from all modules.
"""
from __future__ import annotations

import json
from typing import List, Optional

from gandiv.config import Config
from gandiv.logger import get_logger
from gandiv.models import Finding

log = get_logger()
MODULE_NAME = "llm_analyzer"


def _build_prompt(target: str, findings: List[Finding]) -> str:
    """Build the analysis prompt for Gemini."""
    findings_summary = []
    for f in findings[:200]:
        findings_summary.append({
            "type": f.type,
            "value": f.value,
            "source": f.source,
            "confidence": f.confidence.value,
            "risk": f.risk.value,
        })

    prompt = f"""You are a cybersecurity OSINT analyst. Analyze the following reconnaissance findings for target: {target}

FINDINGS:
{json.dumps(findings_summary, indent=2)}

Provide a structured analysis in Markdown:

## Executive Summary
(2-3 sentences: What is this target's exposure?)

## Key Findings
(Top 5 most significant findings with brief reasoning)

## Risk Assessment
Overall risk level (Critical/High/Medium/Low) with justification.

## Attack Surface
What could an attacker do with this information?

## Correlations
Any patterns or connections between findings.

## Recommendations
3-5 actionable security recommendations.

Be concise, factual, and actionable. Do not invent data not present in the findings.
"""
    return prompt


def _call_gemini(prompt: str, api_key: str, timeout: int = 60) -> Optional[str]:
    """Call Gemini API with the analysis prompt, with retry + fallback models."""
    try:
        import requests
        import time as _time
    except ImportError:
        log.error("requests not installed; cannot call Gemini API")
        return None

    # Try these models in order — first one that responds wins.
    # Google occasionally deprecates or overloads specific models.
    MODELS = [
        "gemini-3.8-flash",
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-2.0-flash",
    ]

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 2048,
        },
    }

    last_error = None
    for model in MODELS:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/"
            f"models/{model}:generateContent?key={api_key}"
        )
        for attempt in range(2):  # 2 attempts per model
            try:
                resp = requests.post(url, json=payload, timeout=timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            text = parts[0].get("text", "")
                            if text.strip():
                                log.info(f"Gemini analysis via {model}")
                                return text.strip()
                elif resp.status_code in (503, 429):
                    # Transient — try next model or retry
                    last_error = f"{model}: {resp.status_code}"
                    _time.sleep(2)
                    continue
                else:
                    last_error = f"{model}: {resp.status_code} - {resp.text[:200]}"
                    break  # non-transient for this model, try next
            except Exception as e:
                last_error = f"{model}: {e}"
                _time.sleep(1)
                continue

    log.warning(f"All Gemini models failed. Last error: {last_error}")
    return None


def analyze(target: str, findings: List[Finding], config: Config) -> Optional[str]:
    """Analyze findings using Gemini API."""
    if not config.api_keys or not getattr(config.api_keys, "gemini", None):
        log.debug("No Gemini API key configured; skipping LLM analysis")
        return None

    if not findings:
        log.debug("No findings to analyze")
        return None

    prompt = _build_prompt(target, findings)
    log.info("Calling Gemini API for findings analysis...")
    analysis = _call_gemini(prompt, config.api_keys.gemini, timeout=config.default_timeout + 50)

    if analysis:
        log.info(f"LLM analysis complete ({len(analysis)} chars)")
    else:
        log.warning("LLM analysis failed or returned empty")

    return analysis