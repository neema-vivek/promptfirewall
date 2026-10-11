"""OpenAI-compatible LLM adapter (optional, needs an API key)."""
from __future__ import annotations

import httpx

from app.config import settings
from app.llm.base import LLMAdapter, SYSTEM_PROMPT


class OpenAILLM(LLMAdapter):
    def __init__(self) -> None:
        if not settings.openai_api_key:
            raise RuntimeError(
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set."
            )
        self.base_url = settings.openai_base_url.rstrip("/")
        self.model = settings.openai_model
        self.api_key = settings.openai_api_key

    def chat(self, user_message: str, system_prompt: str = SYSTEM_PROMPT) -> str:
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "temperature": 0.2,
                },
                timeout=30.0,
            )
        except httpx.RequestError as exc:
            return f"[llm error] Could not reach the LLM API: {exc}"

        if resp.status_code == 401:
            return "[llm error] Authentication failed (401). Check OPENAI_API_KEY."
        if resp.status_code == 404:
            return (
                f"[llm error] Model '{self.model}' not found (404). "
                "Check OPENAI_MODEL."
            )
        if resp.status_code == 429:
            return "[llm error] Rate limited or out of quota (429). Try again later."
        if resp.status_code >= 400:
            return f"[llm error] API returned {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            return f"[llm error] Unexpected API response: {str(data)[:200]}"
