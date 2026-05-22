"""Runtime configuration, sourced from environment then CLI overrides.

Everything the daemon needs is expressible via environment variables so the
systemd unit can be driven by a single EnvironmentFile. CLI flags, when
present, win over the environment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .criteria import FocusCriteria
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
    # Persistence / dedup
    dedup: bool = True
    state_db: Path | None = None
    retention_days: int = 14
    site_max: int = 50
    # Exports
    write_iocs: bool = True
    write_sigma: bool = True
    archive: bool = True
    # Notifications
    slack_webhook: str = ""
    notify_min_score: int = 60
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    criteria: FocusCriteria = field(default_factory=FocusCriteria)
    # Agentic generation
    agent_enabled: bool = False
    agent_max_steps: int = 4
    agent_critic: bool = True
    agent_tools: tuple[str, ...] = ("fetch_article", "lookup_cve", "lookup_mitre")
    agent_critic_always: bool = False  # False = only critique low/medium-confidence output
    # Model-driven triage (the model decides what's hunt-worthy)
    triage_enabled: bool = False
    triage_batch_size: int = 20
    # Generate briefings concurrently (helps if the endpoint batches requests)
    concurrency: int = 1

    @classmethod
    def from_env(cls) -> "AppConfig":
        out_dir = Path(os.environ.get("THNC_OUT_DIR", "out"))
        state_db_env = os.environ.get("THNC_STATE_DB", "").strip()
        state_db = Path(state_db_env) if state_db_env else (out_dir.parent / "state.db")
        return cls(
            out_dir=out_dir,
            threshold=_env_int("THNC_THRESHOLD", DEFAULT_THRESHOLD),
            max_briefings=_env_int("THNC_MAX_BRIEFINGS", 25),
            offline=_env_bool("THNC_OFFLINE", False),
            write_html=_env_bool("THNC_WRITE_HTML", True),
            write_markdown=_env_bool("THNC_WRITE_MARKDOWN", True),
            llm=LLMConfig.from_env(),
            dedup=_env_bool("THNC_DEDUP", True),
            state_db=state_db,
            retention_days=_env_int("THNC_RETENTION_DAYS", 14),
            site_max=_env_int("THNC_SITE_MAX", 50),
            write_iocs=_env_bool("THNC_WRITE_IOCS", True),
            write_sigma=_env_bool("THNC_WRITE_SIGMA", True),
            archive=_env_bool("THNC_ARCHIVE", True),
            slack_webhook=os.environ.get("THNC_SLACK_WEBHOOK", "").strip(),
            notify_min_score=_env_int("THNC_NOTIFY_MIN_SCORE", 60),
            smtp_host=os.environ.get("THNC_SMTP_HOST", "").strip(),
            smtp_port=_env_int("THNC_SMTP_PORT", 25),
            smtp_user=os.environ.get("THNC_SMTP_USER", "").strip(),
            smtp_password=os.environ.get("THNC_SMTP_PASSWORD", ""),
            smtp_from=os.environ.get("THNC_SMTP_FROM", "").strip(),
            smtp_to=os.environ.get("THNC_SMTP_TO", "").strip(),
            criteria=FocusCriteria.from_env(),
            agent_enabled=_env_bool("THNC_AGENT_ENABLED", False),
            agent_max_steps=_env_int("THNC_AGENT_MAX_STEPS", 4),
            agent_critic=_env_bool("THNC_AGENT_CRITIC", True),
            agent_tools=tuple(
                t.strip() for t in os.environ.get(
                    "THNC_AGENT_TOOLS", "fetch_article,lookup_cve,lookup_mitre"
                ).split(",") if t.strip()
            ),
            agent_critic_always=_env_bool("THNC_AGENT_CRITIC_ALWAYS", False),
            triage_enabled=_env_bool("THNC_TRIAGE_ENABLED", False),
            triage_batch_size=_env_int("THNC_TRIAGE_BATCH_SIZE", 20),
            concurrency=max(1, _env_int("THNC_CONCURRENCY", 1)),
        )
