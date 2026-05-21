"""Hypothesis generation backed by a custom OpenAI-compatible endpoint.

Talks to ``POST {base_url}/chat/completions`` using only the standard
library, so it works against OpenAI, Azure OpenAI (with a compatible
gateway), vLLM, Ollama's OpenAI shim, LM Studio, or any other
OpenAI-protocol server.

The LLM is the *primary* generator. If the endpoint is unreachable, the
response is malformed, or the result fails our structural contract
(>= 3 hypotheses, each with 3-5 objectives), the caller falls back to the
deterministic heuristic generator so a run never fails.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from .config import LLMConfig
from .models import Article, Extraction, Hypothesis, Objective

log = logging.getLogger(__name__)

_MIN_HYP = 3
_MIN_OBJ = 3
_MAX_OBJ = 5
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

_SYSTEM_PROMPT = (
    "You are a senior threat-hunting analyst. Given a security news article and "
    "pre-extracted indicators, produce concrete, testable threat-hunting hypotheses. "
    "Each hypothesis must include CTF-style FALSIFICATION objectives: finite checks "
    "whose NULL result (absence of evidence) would disprove or weaken the hypothesis. "
    "Map everything to MITRE ATT&CK technique IDs where possible. Suggested queries "
    "should be SIEM-agnostic pseudo-queries an analyst can adapt. "
    "Respond with a SINGLE JSON object and nothing else."
)

_SCHEMA_HINT = """Return JSON of exactly this shape:
{
  "hypotheses": [
    {
      "title": "short title",
      "statement": "what we believe happened, scoped to 'our environment' and a time window",
      "rationale": "why this hypothesis follows from the article/indicators",
      "confidence": "low" | "medium" | "high",
      "mitre_attack": ["T1190", "..."],
      "sigma_rule": "a valid Sigma detection rule as a YAML string (title, logsource, detection, condition); use \\n for newlines",
      "objectives": [
        {
          "title": "short objective title",
          "falsification_criterion": "what null result would disprove the hypothesis",
          "data_sources": ["EDR", "DNS logs", "..."],
          "suggested_query": "SIEM-agnostic pseudo-query",
          "mitre_attack": ["T1071"],
          "difficulty": "easy" | "medium" | "hard",
          "points": 100
        }
      ]
    }
  ]
}
Rules: provide AT LEAST 3 hypotheses; each hypothesis MUST have between 3 and 5 objectives.
The sigma_rule must be syntactically valid Sigma YAML embedded as a JSON string.
"""


def _build_user_prompt(article: Article, ext: Extraction) -> str:
    signals = {
        "cves": ext.cves,
        "threat_actors": ext.threat_actors,
        "malware_families": ext.malware_families,
        "products": ext.products,
        "vectors": ext.vectors,
        "actions": ext.actions,
        "sectors": ext.sectors,
        "mitre_techniques": ext.mitre_techniques,
        "ip_iocs": ext.ips,
        "domain_iocs": ext.domains,
        "sha256": ext.hashes_sha256,
    }
    signals = {k: v for k, v in signals.items() if v}
    return (
        f"ARTICLE TITLE: {article.title}\n"
        f"SOURCE: {article.source}\n"
        f"PUBLISHED: {article.published}\n"
        f"SUMMARY: {article.summary}\n\n"
        f"EXTRACTED INDICATORS (JSON): {json.dumps(signals, ensure_ascii=False)}\n\n"
        f"{_SCHEMA_HINT}"
    )


def _post_chat(cfg: LLMConfig, system: str, user: str) -> str:
    url = f"{cfg.base_url}/chat/completions"
    body = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "response_format": {"type": "json_object"},
    }
    if cfg.disable_thinking:
        # vLLM/SGLang pass these through to the chat template; Qwen3 honours
        # enable_thinking=False. Harmless for servers that ignore it.
        body["chat_template_kwargs"] = {"enable_thinking": False}
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Some endpoints reject response_format; retry once without it.
        if exc.code in (400, 422):
            log.warning("LLM rejected response_format (%s); retrying without it", exc.code)
            body.pop("response_format", None)
            req2 = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
            )
            with urllib.request.urlopen(req2, timeout=cfg.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        else:
            raise
    return payload["choices"][0]["message"]["content"]


def _coerce_json(text: str) -> dict:
    text = text.strip()
    text = _FENCE_RE.sub("", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Salvage the outermost JSON object.
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _as_str_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _parse_objectives(raw_objs, hyp_id: str) -> list[Objective]:
    out: list[Objective] = []
    for idx, ro in enumerate(raw_objs[:_MAX_OBJ], start=1):
        if not isinstance(ro, dict):
            continue
        diff = str(ro.get("difficulty", "medium")).lower()
        if diff not in ("easy", "medium", "hard"):
            diff = "medium"
        try:
            points = int(ro.get("points", 100))
        except (TypeError, ValueError):
            points = 100
        out.append(
            Objective(
                id=f"{hyp_id}-O{idx}",
                title=str(ro.get("title", "Objective")).strip() or "Objective",
                falsification_criterion=str(ro.get("falsification_criterion", "")).strip(),
                data_sources=_as_str_list(ro.get("data_sources")),
                suggested_query=str(ro.get("suggested_query", "")).strip(),
                mitre_attack=_as_str_list(ro.get("mitre_attack")),
                difficulty=diff,
                points=points,
            )
        )
    return out


def _parse_hypotheses(parsed: dict, article: Article) -> list[Hypothesis]:
    raw_hyps = parsed.get("hypotheses")
    if not isinstance(raw_hyps, list):
        raise ValueError("LLM response missing 'hypotheses' list")
    hyps: list[Hypothesis] = []
    for n, rh in enumerate(raw_hyps, start=1):
        if not isinstance(rh, dict):
            continue
        hid = f"H-{article.id[:8]}-{n}"
        conf = str(rh.get("confidence", "medium")).lower()
        if conf not in ("low", "medium", "high"):
            conf = "medium"
        objs = _parse_objectives(rh.get("objectives", []), hid)
        sigma = rh.get("sigma_rule", "")
        hyps.append(
            Hypothesis(
                id=hid,
                title=str(rh.get("title", "Threat hunt")).strip() or "Threat hunt",
                statement=str(rh.get("statement", "")).strip(),
                rationale=str(rh.get("rationale", "")).strip(),
                confidence=conf,
                mitre_attack=_as_str_list(rh.get("mitre_attack")),
                objectives=objs,
                sigma_rule=sigma if isinstance(sigma, str) else "",
            )
        )
    return hyps


def _meets_contract(hyps: list[Hypothesis]) -> bool:
    if len(hyps) < _MIN_HYP:
        return False
    for h in hyps:
        if not (_MIN_OBJ <= len(h.objectives) <= _MAX_OBJ):
            return False
        if not h.statement:
            return False
        for o in h.objectives:
            if not o.falsification_criterion or not o.suggested_query:
                return False
    return True


def generate_llm(article: Article, ext: Extraction, cfg: LLMConfig) -> list[Hypothesis] | None:
    """Generate hypotheses via the configured endpoint.

    Returns a contract-satisfying list, or ``None`` if the endpoint failed
    or produced unusable output (caller should fall back to heuristics).
    """
    if not cfg.is_usable:
        return None
    try:
        content = _post_chat(cfg, _SYSTEM_PROMPT, _build_user_prompt(article, ext))
        parsed = _coerce_json(content)
        hyps = _parse_hypotheses(parsed, article)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.warning("LLM endpoint unreachable for '%s': %s", article.title[:60], exc)
        return None
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        log.warning("LLM response unusable for '%s': %s", article.title[:60], exc)
        return None

    if not _meets_contract(hyps):
        log.warning(
            "LLM output for '%s' failed structural contract (got %d hypotheses); falling back",
            article.title[:60], len(hyps),
        )
        return None
    log.info("LLM produced %d hypotheses for '%s'", len(hyps), article.title[:60])
    return hyps
