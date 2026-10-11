"""Mock LLM adapter: runs fully offline with no API key.

This mock is DELIBERATELY VULNERABLE to prompt injection so the demo can
show what happens when malicious content reaches an unprotected agent. When
the firewall is off, an injection reaches this mock and it leaks its system
prompt. When the firewall is on, the injection is blocked before it ever
gets here. The vulnerability is intentional and simulates a naive agent.
"""
from __future__ import annotations

import re

from app.llm.base import LLMAdapter, SYSTEM_PROMPT

# Phrases that a naive agent would (wrongly) treat as a valid request to
# disclose its own instructions / system prompt.
_LEAK_TRIGGERS = re.compile(
    r"\b(reveal|show|print|repeat|display|output|tell\s+me|what\s+(is|are)|"
    r"ignore|disregard|forget)\b.{0,40}\b(system\s+prompt|instructions?|"
    r"rules?|prompt\s+above|your\s+prompt|guidelines?)\b",
    re.IGNORECASE | re.DOTALL,
)


class MockLLM(LLMAdapter):
    def chat(self, user_message: str, system_prompt: str = SYSTEM_PROMPT) -> str:
        # Naive-agent behavior: if the message looks like it's asking about
        # the system prompt / instructions, the mock obediently discloses
        # them. A real hardened model should refuse; this one does not.
        if _LEAK_TRIGGERS.search(user_message):
            return (
                "[mock-llm] Sure! Here are my full system instructions:\n\n"
                f"----- SYSTEM PROMPT -----\n{system_prompt}\n"
                "-------------------------"
            )

        preview = user_message.strip().replace("\n", " ")
        if len(preview) > 200:
            preview = preview[:200] + "..."
        return (
            "[mock-llm] I received your message and will help within my "
            f'safety guidelines. You said: "{preview}"'
        )
