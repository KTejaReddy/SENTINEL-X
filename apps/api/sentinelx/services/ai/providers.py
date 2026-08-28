"""AI Provider abstraction.

The platform never hard-codes one AI vendor. A provider implements:
  analyze / classify / summarize / plan / explain

Default: the LocalProvider — a deterministic, evidence-driven reasoning engine
that only uses real platform data and never fabricates findings. An optional
OpenAI-compatible provider can be configured for free-form reasoning; its
output is always validated by Pydantic schemas before use.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from ...config import settings

logger = logging.getLogger(__name__)

PROMPT_VERSIONS = {
    "triage": "triage-v1",
    "incident": "incident-v1",
    "copilot": "copilot-v1",
    "action": "action-v1",
}


class AIProvider:
    name = "base"
    model = ""

    def analyze(self, task: str, context: dict[str, Any], system: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def summarize(self, text: str, max_len: int = 400) -> str:
        raise NotImplementedError

    def explain(self, result: dict[str, Any]) -> str:
        raise NotImplementedError


class LocalProvider(AIProvider):
    """Deterministic evidence-driven analyst. No generation, no hallucination.

    All outputs are derived from structured platform data with an explicit
    confidence and evidence trail.
    """

    name = "local"
    model = "local-heuristic-v1"

    def analyze(self, task: str, context: dict[str, Any], system: str = "") -> dict[str, Any]:
        return context  # structured context is the answer for the local provider

    def summarize(self, text: str, max_len: int = 400) -> str:
        text = " ".join(text.split())
        return text[:max_len] + ("…" if len(text) > max_len else "")

    def explain(self, result: dict[str, Any]) -> str:
        return result.get("explanation", "")


class OpenAICompatProvider(AIProvider):
    """Optional remote provider (OpenAI-compatible chat completions API).

    Only used when AI_PROVIDER=openai_compatible and AI_API_KEY is set.
    Callers must validate output against strict Pydantic schemas.
    """

    name = "openai_compatible"

    def __init__(self) -> None:
        self.model = settings.AI_MODEL or "gpt-4o-mini"
        self.base = settings.AI_API_BASE or "https://api.openai.com/v1"
        self.api_key = settings.AI_API_KEY or ""

    def analyze(self, task: str, context: dict[str, Any], system: str = "") -> dict[str, Any]:
        if not self.api_key:
            return {}
        try:
            resp = httpx.post(
                f"{self.base}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system or "You are a security analyst. Return JSON only."},
                        {"role": "user", "content": f"{task}\n\nContext:\n{context}"},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
                timeout=45,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            import json

            return json.loads(content)
        except Exception as exc:  # noqa: BLE001
            logger.warning("remote AI provider failed: %s", exc)
            return {}


_provider: AIProvider | None = None


def get_provider() -> AIProvider:
    global _provider
    if _provider is None:
        if settings.AI_PROVIDER == "openai_compatible" and settings.AI_API_KEY:
            _provider = OpenAICompatProvider()
        else:
            _provider = LocalProvider()
    return _provider
