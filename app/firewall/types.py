"""Shared types for the firewall engine."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List


class AttackType(str, enum.Enum):
    """Categories of prompt-injection attacks the firewall targets."""

    INSTRUCTION_OVERRIDE = "Instruction Override"
    ROLE_CHANGE = "Role Change"
    SECRET_EXTRACTION = "Secret Extraction"
    TOOL_ABUSE = "Tool Abuse"
    CREDENTIAL_THEFT = "Credential Theft"
    CONTEXT_POISONING = "Context Poisoning"
    MULTI_STEP_JAILBREAK = "Multi-Step Jailbreaks"
    ENCODED_INSTRUCTIONS = "Encoded Instructions"
    INDIRECT_INJECTION = "Indirect Prompt Injection"


class Verdict(str, enum.Enum):
    """Firewall decision for a piece of content."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


@dataclass
class Detection:
    """A single rule match found in the scanned content."""

    attack_type: AttackType
    rule_id: str
    description: str
    severity: int  # 0-100 contribution to the risk score
    matched_text: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type.value,
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "matched_text": self.matched_text,
            "span": [self.start, self.end],
        }


@dataclass
class FirewallResult:
    """The full outcome of scanning a piece of content."""

    verdict: Verdict
    risk_score: int
    detections: List[Detection] = field(default_factory=list)
    original_text: str = ""
    sanitized_text: str = ""
    llm_note: str | None = None  # status from the optional LLM classifier

    @property
    def attack_types(self) -> List[str]:
        seen: List[str] = []
        for d in self.detections:
            if d.attack_type.value not in seen:
                seen.append(d.attack_type.value)
        return seen

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "attack_types": self.attack_types,
            "detections": [d.to_dict() for d in self.detections],
            "original_text": self.original_text,
            "sanitized_text": self.sanitized_text,
            "llm_note": self.llm_note,
        }
