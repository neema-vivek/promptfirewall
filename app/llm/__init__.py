"""Pluggable LLM adapters."""
from app.llm.base import LLMAdapter
from app.llm.registry import get_llm

__all__ = ["LLMAdapter", "get_llm"]
