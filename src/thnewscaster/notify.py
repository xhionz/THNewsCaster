"""Notifications for newly-published high-severity briefings.

Supports a Slack (or generic) incoming webhook and plain SMTP email. Both
are optional and entirely env-gated; if nothing is configured, this is a
no-op. Only briefings at/above ``notify_min_score`` from the *current run*
(i.e. genuinely new) are included, so you aren't pinged daily about the
same stories.
"""
from __future__ import annotations

import json
import logging
import smtplib
import urllib.error
import urllib.request
from email.mime.text import MIMEText

from .config import AppConfig
from .models import HuntBriefing

log = logging.getLogger(__name__)


def _summary_lines(briefings: list[HuntBriefing]) -> list[str]:
    lines = []
    for b in briefings:
        a = b.article
        link = f" — {a.link}" if a.link else ""
        lines.append(f"[{b.scoring.score}] {a.title} ({a.source}){link}")
    return lines


def _post_slack(webhook: str, text: str) -> None:
    data = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        log.info("slack notification sent")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.warning("slack notification failed: %s", exc)


def _send_email(cfg: AppConfig, subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from or cfg.smtp_user
    msg["To"] = cfg.smtp_to
    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=20) as s:
            try:
                s.starttls()
            except smtplib.SMTPException:
                pass  # server without STARTTLS
            if cfg.smtp_user:
                s.login(cfg.smtp_user, cfg.smtp_password)
            s.send_message(msg)
        log.info("email notification sent to %s", cfg.smtp_to)
    except (smtplib.SMTPException, OSError) as exc:
        log.warning("email notification failed: %s", exc)


def notify_new(cfg: AppConfig, new_briefings: list[HuntBriefing]) -> None:
    flagged = [b for b in new_briefings if b.scoring.score >= cfg.notify_min_score]
    if not flagged:
        return
    flagged.sort(key=lambda b: b.scoring.score, reverse=True)
    header = f"THNewsCaster: {len(flagged)} new hunt-worthy briefing(s) (score >= {cfg.notify_min_score})"
    body = header + "\n\n" + "\n".join(_summary_lines(flagged))

    if cfg.slack_webhook:
        _post_slack(cfg.slack_webhook, body)
    if cfg.smtp_host and cfg.smtp_to:
        _send_email(cfg, header, body)
