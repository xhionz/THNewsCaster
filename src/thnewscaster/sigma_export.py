"""Write LLM-generated Sigma rules to individual .yml files.

Hypotheses may carry a ``sigma_rule`` (raw YAML string) produced by the
LLM. We don't parse/validate the YAML here beyond a sanity check that it
looks like a Sigma rule, since the platform has no YAML dependency; the
files are written verbatim for a human or `sigma` CLI to consume.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import HuntPackage

_SIGMA_HINT = re.compile(r"\b(detection|logsource)\b", re.IGNORECASE)
_FENCE = re.compile(r"^```(?:ya?ml)?\s*|\s*```$", re.MULTILINE)


def _clean(yaml_text: str) -> str:
    return _FENCE.sub("", yaml_text).strip()


def looks_like_sigma(text: str) -> bool:
    return bool(text and _SIGMA_HINT.search(text))


def export_all(pkg: HuntPackage, out_dir: Path) -> int:
    sigma_dir = out_dir / "sigma"
    written = 0
    for b in pkg.briefings:
        for h in b.hypotheses:
            rule = _clean(h.sigma_rule)
            if not looks_like_sigma(rule):
                continue
            if written == 0:
                sigma_dir.mkdir(parents=True, exist_ok=True)
            (sigma_dir / f"{h.id}.yml").write_text(rule + "\n")
            written += 1
    return written
