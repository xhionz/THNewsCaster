"""Tests for the agentic generator and tools (transport fully mocked)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from thnewscaster import agent, llm  # noqa: E402
from thnewscaster.agent import AgentConfig, generate_agentic  # noqa: E402
from thnewscaster.config import LLMConfig  # noqa: E402
from thnewscaster.extraction import extract  # noqa: E402
from thnewscaster.models import Article  # noqa: E402
from thnewscaster.tools import ToolRegistry  # noqa: E402


def _article() -> Article:
    return Article(
        id="abcd1234ef567890", source="UnitTest",
        title="Akira ransomware exploits Cisco ASA VPN CVE-2026-0001",
        link="https://example.invalid/x", published="2026-05-22",
        summary="Akira affiliates exploit Cisco ASA and move laterally via RDP.",
        raw_text="Akira ransomware Cisco ASA RDP CVE-2026-0001",
    )


def _final_payload() -> str:
    hyp = {
        "title": "Initial access via Cisco ASA",
        "statement": "An actor exploited the ASA VPN to gain access in the last 30 days.",
        "rationale": "Confirmed exploited in the wild.",
        "confidence": "high",
        "mitre_attack": ["T1190"],
        "sigma_rule": "title: ASA exploit\nlogsource:\n  product: firewall\ndetection:\n  sel:\n    uri: '*'\n  condition: sel",
        "objectives": [
            {"title": f"Obj {i}", "falsification_criterion": "Null result disproves it.",
             "data_sources": ["EDR"], "suggested_query": "q | where i==1",
             "mitre_attack": ["T1190"], "difficulty": "easy", "points": 100}
            for i in range(1, 4)
        ],
    }
    return json.dumps({"action": "final", "hypotheses": [hyp, hyp, hyp]})


def _cfg() -> LLMConfig:
    return LLMConfig(enabled=True, base_url="https://fake/v1", api_key="k", model="m")


def test_agent_uses_tool_then_finalises(monkeypatch):
    # Scripted transport: first a tool call, then the final package, then
    # (critic) an "accept" verdict.
    scripted = [
        json.dumps({"action": "use_tool", "tool": "lookup_cve",
                    "args": {"cve": "CVE-2026-0001"}, "thought": "confirm KEV"}),
        _final_payload(),
        json.dumps({"verdict": "accept", "issues": []}),
    ]
    calls = {"tool": 0}

    def fake_chat(cfg, messages, json_mode=True):
        return scripted.pop(0)

    def fake_call(self, name, args):
        calls["tool"] += 1
        return {"cve": args.get("cve"), "known_exploited": True}

    monkeypatch.setattr(agent, "chat_raw", fake_chat)
    monkeypatch.setattr(ToolRegistry, "call", fake_call)

    art = _article()
    hyps = generate_agentic(art, extract(art), _cfg(),
                            AgentConfig(enabled=True, critic=True), offline=False)
    assert hyps is not None and len(hyps) == 3
    assert calls["tool"] == 1, "agent should have invoked exactly one tool"
    assert hyps[0].sigma_rule and "detection" in hyps[0].sigma_rule


def test_agent_critic_can_force_revision(monkeypatch):
    scripted = [
        _final_payload(),                                   # initial final
        json.dumps({"verdict": "revise", "issues": ["objectives too vague"]}),  # critic
        _final_payload(),                                   # revised final
    ]
    monkeypatch.setattr(agent, "chat_raw", lambda *a, **k: scripted.pop(0))
    art = _article()
    # Force the critic to run even though the output is high-confidence.
    hyps = generate_agentic(art, extract(art), _cfg(),
                            AgentConfig(enabled=True, critic=True, critic_always=True,
                                        max_steps=2), offline=False)
    assert hyps is not None and len(hyps) == 3
    assert not scripted, "all scripted turns (final, critic, revision) should be consumed"


def test_critic_skipped_when_all_high_confidence(monkeypatch):
    # Only the final is scripted; if the critic tried to run, pop() would fail.
    scripted = [_final_payload()]
    monkeypatch.setattr(agent, "chat_raw", lambda *a, **k: scripted.pop(0))
    art = _article()
    trace: list[str] = []
    hyps = generate_agentic(art, extract(art), _cfg(),
                            AgentConfig(enabled=True, critic=True, critic_always=False),
                            offline=False, trace=trace)
    assert hyps is not None and len(hyps) == 3
    assert scripted == [], "the single final turn should be consumed, critic skipped"
    assert any("skipped (high confidence)" in t for t in trace)


def test_agent_disabled_returns_none():
    art = _article()
    assert generate_agentic(art, extract(art), _cfg(),
                            AgentConfig(enabled=False), offline=False) is None


def test_tools_offline_are_failsafe():
    reg = ToolRegistry(offline=True, enabled={"fetch_article", "lookup_cve", "lookup_mitre"})
    assert "error" in reg.call("fetch_article", {"url": "https://x"})
    assert "error" in reg.call("lookup_cve", {"cve": "CVE-2026-0001"})
    # MITRE lookup is offline-capable (bundled catalog).
    res = reg.call("lookup_mitre", {"query": "T1190"})
    assert res["matches"][0]["id"] == "T1190"


def test_tool_not_enabled_is_rejected():
    reg = ToolRegistry(offline=False, enabled={"lookup_mitre"})
    assert "error" in reg.call("fetch_article", {})


def test_fetch_article_blocks_ssrf_to_internal_hosts():
    # Even online, fetching is pinned to the article URL and private/loopback
    # targets are refused (no network call happens).
    for bad in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
                "http://localhost:8080/", "file:///etc/passwd"):
        reg = ToolRegistry(offline=False, enabled={"fetch_article"}, article_url=bad)
        assert "error" in reg.fetch_article(), f"should refuse {bad}"


def test_fetch_article_ignores_model_supplied_url():
    # The model cannot redirect the fetch: only article_url is ever used, and a
    # missing article_url yields an error rather than fetching attacker input.
    reg = ToolRegistry(offline=False, enabled={"fetch_article"}, article_url="")
    assert "error" in reg.call("fetch_article", {"url": "http://169.254.169.254/"})
