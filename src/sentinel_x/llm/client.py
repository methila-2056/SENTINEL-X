"""Ollama LLM client: chat with JSON tool-calling support."""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentinel_x.common.logging import get_logger
from sentinel_x.common.settings import get_settings

logger = get_logger(__name__)


class LLMError(RuntimeError):
    pass


class OllamaClient:
    """Thin async-capable client for a local Ollama server."""

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model

    def is_available(self) -> bool:
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def generate(
        self,
        system: str,
        user: str,
        json_mode: bool = False,
        temperature: float = 0.1,
        num_predict: int = 1024,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json" if json_mode else None,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
                "num_ctx": 8192,
            },
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        response = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=180.0)
        if response.status_code != 200:
            raise LLMError(f"Ollama error {response.status_code}: {response.text[:300]}")
        return str(response.json()["message"]["content"])

    def generate_json(self, system: str, user: str, **kwargs: Any) -> dict[str, Any]:
        raw = self.generate(system, user, json_mode=True, **kwargs)
        return _parse_json_object(raw)


def _parse_json_object(raw: str) -> dict[str, Any]:
    """Parse the first JSON object found in the model output."""
    text = raw.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    raise LLMError(f"Model did not return valid JSON object: {raw[:200]}")
