"""Select the LLM adapter based on config."""
from __future__ import annotations

from app.config import settings
from app.llm.base import LLMAdapter
from app.llm.mock import MockLLM


def get_llm() -> LLMAdapter:
    if settings.llm_provider == "openai":
        # Imported lazily so the demo runs without httpx creds configured.
        from app.llm.openai_adapter import OpenAILLM

        return OpenAILLM()
    return MockLLM()
