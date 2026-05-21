"""Runtime configuration, sourced from environment then CLI overrides.

Everything the daemon needs is expressible via environment variables so the
systemd unit can be driven by a single EnvironmentFile. CLI flags, when
present, win over the environment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .relevance import DEFAULT_THRESHOLD


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class LLMConfig:
    enabled: bool = False
    base_url: str = ""          # e.g. https://my-endpoint.example/v1
    api_key: str = ""
    model: str = "gpt-4o-mini"
    timeout: float = 60.0
    max_tokens: int = 4096
    temperature: float = 0.2
    # Turn off "thinking"/reasoning for models that support it (e.g. Qwen3
    # via vLLM). Reasoning models are far slower and their output is harder to
    # constrain to JSON, so disabling it is recommended for this workload.
    disable_thinking: bool = False

    @property
    def is_usable(self) -> bool:
        return self.enabled and bool(self.base_url)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        base_url = os.environ.get("THNC_OPENAI_BASE_URL", "").strip().rstrip("/")
        api_key = os.environ.get("THNC_OPENAI_API_KEY", "").strip()
        model = os.environ.get("THNC_OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
        # Default: enabled when a base URL is configured; explicit flag overrides.
        enabled = _env_bool("THNC_LLM_ENABLED", default=bool(base_url))
        return cls(
            enabled=enabled,
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout=float(_env_int("THNC_OPENAI_TIMEOUT", 60)),
            max_tokens=_env_int("THNC_OPENAI_MAX_TOKENS", 4096),
            temperature=float(os.environ.get("THNC_OPENAI_TEMPERATURE", "0.2") or 0.2),
            disable_thinking=_env_bool("THNC_OPENAI_DISABLE_THINKING", False),
        )


@dataclass
class AppConfig:
    out_dir: Path = Path("out")
    threshold: int = DEFAULT_THRESHOLD
    max_briefings: int = 25
    offline: bool = False
    write_html: bool = True
    write_markdown: bool = True
    llm: LLMConfig = None  # type: ignore[assignment]

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            out_dir=Path(os.environ.get("THNC_OUT_DIR", "out")),
            threshold=_env_int("THNC_THRESHOLD", DEFAULT_THRESHOLD),
            max_briefings=_env_int("THNC_MAX_BRIEFINGS", 25),
            offline=_env_bool("THNC_OFFLINE", False),
            write_html=_env_bool("THNC_WRITE_HTML", True),
            write_markdown=_env_bool("THNC_WRITE_MARKDOWN", True),
            llm=LLMConfig.from_env(),
        )
