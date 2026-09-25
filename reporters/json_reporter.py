"""GANDIV JSON Reporter - structured, machine-readable, integration-friendly."""
from __future__ import annotations

import json
from pathlib import Path

from gandiv.models import ScanResult


def generate(scan_result: ScanResult, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_result.to_dict(), f, indent=2, default=str)
    return output_path
