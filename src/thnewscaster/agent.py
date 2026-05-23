"""Agentic hypothesis generation.

A portable ReAct-style loop that works on any chat model (no native
function-calling required): on each turn the model returns a single JSON
object that is either a tool call or the final hunt package. We execute
tools, feed results back, and iterate within a step budget. A second
"critic" agent then reviews the package against a rubric and can force a
single revision.

Falls back (returns ``None``) on any failure so the caller can drop to the
single-shot LLM generator and then the heuristic engine.
"""
from __future__ import annotations

import json
import logging
import urllib.error
from dataclasses import dataclass

from .config import LLMConfig

_NET_ERRORS = (urllib.error.URLError, TimeoutError, OSError)
from .llm import (
    _SCHEMA_HINT,
    _build_user_prompt,
    _meets_contract,
    _parse_hypotheses,
    chat_raw,
    coerce_json,
)
from .models import Article, Extraction, Hypothesis
from .tools import ToolRegistry, kev_enrich

log = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    enabled: bool = False
    max_steps: int = 4          # max tool-calling turns before forcing a final
    critic: bool = True         # run the critic + (one) revision pass
    critic_always: bool = False  # False = only critique low/medium-confidence output
    tools: tuple[str, ...] = ("fetch_article", "lookup_cve", "lookup_mitre")


def _tools_block(registry: ToolRegistry) -> str:
    specs = registry.schema()
    if not specs:
        return "No tools are available; reason from the provided indicators only."
    lines = ["You may call these tools to gather context before answering:"]
    for s in specs:
        args = ", ".join(f"{k}: {v}" for k, v in s["args"].items())
        lines.append(f"- {s['name']}({args}) — {s['description']}")
    return "\n".join(lines)


def _system_prompt(registry: ToolRegistry, max_steps: int) -> str:
    return (
        "You are a senior threat-hunting analyst agent. Your job is to turn a "
        "security news item into testable hunting hypotheses with CTF-style "
        "FALSIFICATION objectives (finite checks whose NULL result disproves the "
        "hypothesis) and a Sigma detection rule per hypothesis.\n\n"
        f"{_tools_block(registry)}\n\n"
        f"You have a budget of {max_steps} tool calls. Use tools when they would "
        "materially improve accuracy (e.g. confirm a CVE is exploited in the wild, "
        "read the full article, resolve ATT&CK ids). Do not call a tool twice with "
        "the same arguments.\n\n"
        "On EVERY turn respond with a SINGLE JSON object, nothing else:\n"
        '  to use a tool:  {"action":"use_tool","tool":"<name>","args":{...},"thought":"why"}\n'
        '  when finished:  {"action":"final", ...the hunt package...}\n\n'
        "When finished, the JSON object must also carry the fields described here "
        f"(use the 'hypotheses' array exactly as specified):\n{_SCHEMA_HINT}"
    )


def _run_react(cfg: LLMConfig, agent_cfg: AgentConfig, registry: ToolRegistry,
               article: Article, ext: Extraction, trace: list[str],
               enrichment: dict) -> list[Hypothesis] | None:
    messages = [
        {"role": "system", "content": _system_prompt(registry, agent_cfg.max_steps)},
        {"role": "user", "content": _build_user_prompt(article, ext, enrichment)},
    ]
    tool_calls_used = 0
    for _step in range(agent_cfg.max_steps + 2):  # +2 turns to allow a final after budget
        content = chat_raw(cfg, messages)
        obj = coerce_json(content)
        action = str(obj.get("action", "")).lower()

        if action == "use_tool" and tool_calls_used < agent_cfg.max_steps:
            name = str(obj.get("tool", ""))
            args = obj.get("args", {}) if isinstance(obj.get("args"), dict) else {}
            result = registry.call(name, args)
            tool_calls_used += 1
            status = "error" if "error" in result else "ok"
            log.info("agent tool %s(%s) -> %s", name, args, status)
            trace.append(f"tool {name}({json.dumps(args)}) -> {status}")
            messages.append({"role": "assistant", "content": content})
            messages.append({
                "role": "user",
                "content": f"TOOL RESULT ({name}): {json.dumps(result)[:4000]}",
            })
            continue

        if action == "final" or "hypotheses" in obj:
            return _parse_hypotheses(obj, article)

        # Budget exhausted or malformed: demand a final next turn.
        messages.append({"role": "assistant", "content": content})
        messages.append({
            "role": "user",
            "content": 'Stop using tools. Respond now with {"action":"final","hypotheses":[...]} '
                       "following the required schema.",
        })
    return None


def _critique_and_revise(cfg: LLMConfig, article: Article, ext: Extraction,
                         hyps: list[Hypothesis], trace: list[str],
                         enrichment: dict) -> list[Hypothesis]:
    rubric = (
        "You are a hunt-quality reviewer. Assess the hypotheses below against: "
        "(1) each hypothesis is specific and testable; (2) objectives are true "
        "FALSIFICATION tests (null result disproves), not confirmations; (3) "
        "ATT&CK ids are plausible; (4) the Sigma rule is syntactically valid. "
        'Respond with JSON: {"verdict":"accept"|"revise","issues":["..."]}'
    )
    payload = json.dumps(
        {"hypotheses": [
            {"title": h.title, "statement": h.statement,
             "objectives": [o.falsification_criterion for o in h.objectives],
             "sigma_rule": h.sigma_rule[:600]}
            for h in hyps
        ]}, ensure_ascii=False,
    )
    try:
        review = coerce_json(chat_raw(cfg, [
            {"role": "system", "content": rubric},
            {"role": "user", "content": payload},
        ]))
    except (ValueError, KeyError, OSError) as exc:
        log.warning("critic failed (%s); keeping original", exc)
        trace.append("critic: skipped (error)")
        return hyps

    if str(review.get("verdict", "accept")).lower() != "revise":
        trace.append("critic: accept")
        return hyps
    issues = review.get("issues", [])
    log.info("critic requested revision: %s", issues)
    trace.append(f"critic: revise ({'; '.join(str(i) for i in issues)[:200]})")

    revise_prompt = (
        "Revise your hunt package to fix these issues, keeping the same JSON "
        f"schema (>=3 hypotheses, 3-5 falsification objectives each):\n{json.dumps(issues)}\n\n"
        f"Original article + indicators:\n{_build_user_prompt(article, ext, enrichment)}"
    )
    try:
        revised = _parse_hypotheses(
            coerce_json(chat_raw(cfg, [
                {"role": "system", "content": "You are a senior threat-hunting analyst. "
                                              "Return the corrected JSON only."},
                {"role": "user", "content": revise_prompt},
            ])),
            article,
        )
    except (ValueError, KeyError, OSError) as exc:
        log.warning("revision failed (%s); keeping original", exc)
        return hyps
    return revised if _meets_contract(revised) else hyps


def generate_agentic(article: Article, ext: Extraction, cfg: LLMConfig,
                     agent_cfg: AgentConfig, *, offline: bool,
                     trace: list[str] | None = None) -> list[Hypothesis] | None:
    if not cfg.is_usable or not agent_cfg.enabled:
        return None
    trace = trace if trace is not None else []
    timeout = cfg.timeout / 3 or 10.0
    registry = ToolRegistry(offline=offline, enabled=set(agent_cfg.tools), timeout=timeout,
                            article_url=article.link)
    # Pre-fetch KEV for extracted CVEs so the agent doesn't burn a tool turn
    # confirming exploitation it could have been handed up front.
    enrichment = kev_enrich(ext.cves, offline=offline, timeout=timeout)
    if enrichment:
        trace.append(f"kev: {len(enrichment)} CVE(s) in CISA KEV")

    try:
        hyps = _run_react(cfg, agent_cfg, registry, article, ext, trace, enrichment)
    except _NET_ERRORS as exc:
        log.warning("agent transport error for '%s': %s", article.title[:60], exc)
        return None
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        log.warning("agent produced unusable output for '%s': %s", article.title[:60], exc)
        return None

    if hyps is None or not _meets_contract(hyps):
        log.warning("agent output failed contract for '%s'; falling back", article.title[:60])
        return None

    if agent_cfg.critic:
        # Confidence-gated: skip the critic round-trip when the agent is already
        # confident across the board (saves ~1-2 model calls/article).
        all_high = hyps and all(h.confidence == "high" for h in hyps)
        if all_high and not agent_cfg.critic_always:
            trace.append("critic: skipped (high confidence)")
        else:
            hyps = _critique_and_revise(cfg, article, ext, hyps, trace, enrichment)

    log.info("agent produced %d hypotheses for '%s'", len(hyps), article.title[:60])
    return hyps
