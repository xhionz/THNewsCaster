"""Tests for the OpenAI-compatible LLM generator.

Network is fully mocked via monkeypatching the internal ``_post_chat`` so
these tests stay deterministic and offline.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster import llm  # noqa: E402
from thnewscaster.config import LLMConfig  # noqa: E402
from thnewscaster.extraction import extract  # noqa: E402
from thnewscaster.models import Article  # noqa: E402


def _article() -> Article:
    return Article(
        id="abcd1234ef567890",
        source="UnitTest",
        title="Akira ransomware exploits Cisco ASA VPN CVE-2026-0001",
        link="https://example.invalid/x",
        published="Wed, 21 May 2026 00:00:00 GMT",
        summary="Akira affiliates exploit Cisco ASA and move laterally via RDP.",
        raw_text="Akira ransomware Cisco ASA RDP CVE-2026-0001",
    )


def _good_payload() -> str:
    hyp = {
        "title": "Initial access via Cisco ASA",
        "statement": "An actor exploited the ASA VPN to gain access in the last 30 days.",
        "rationale": "Article cites active exploitation.",
        "confidence": "high",
        "mitre_attack": ["T1190"],
        "objectives": [
            {
                "title": f"Objective {i}",
                "falsification_criterion": "If no evidence, hypothesis is disproven.",
                "data_sources": ["EDR"],
                "suggested_query": "process | where x == 1",
                "mitre_attack": ["T1190"],
                "difficulty": "easy",
                "points": 100,
            }
            for i in range(1, 4)  # exactly 3 objectives
        ],
    }
    return json.dumps({"hypotheses": [hyp, hyp, hyp]})  # 3 hypotheses


def _cfg() -> LLMConfig:
    return LLMConfig(enabled=True, base_url="https://fake/v1", api_key="k", model="m")


def test_llm_parses_valid_payload(monkeypatch) -> None:
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: _good_payload())
    art = _article()
    hyps = llm.generate_llm(art, extract(art), _cfg())
    assert hyps is not None
    assert len(hyps) == 3
    for h in hyps:
        assert h.id.startswith("H-abcd1234-")
        assert 3 <= len(h.objectives) <= 5
        assert h.objectives[0].id == f"{h.id}-O1"


def test_llm_handles_code_fenced_json(monkeypatch) -> None:
    fenced = "```json\n" + _good_payload() + "\n```"
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: fenced)
    art = _article()
    assert llm.generate_llm(art, extract(art), _cfg()) is not None


def test_llm_returns_none_when_contract_unmet(monkeypatch) -> None:
    # Only one hypothesis -> fails the >= 3 contract -> caller falls back.
    one = json.dumps({"hypotheses": [json.loads(_good_payload())["hypotheses"][0]]})
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: one)
    art = _article()
    assert llm.generate_llm(art, extract(art), _cfg()) is None


def test_llm_returns_none_on_garbage(monkeypatch) -> None:
    monkeypatch.setattr(llm, "_post_chat", lambda *a, **k: "not json at all")
    art = _article()
    assert llm.generate_llm(art, extract(art), _cfg()) is None


def test_llm_skipped_when_unconfigured() -> None:
    art = _article()
    assert llm.generate_llm(art, extract(art), LLMConfig(enabled=False)) is None
