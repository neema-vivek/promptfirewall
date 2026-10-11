"""Rule definitions for the firewall.

Each rule is a compiled regex plus metadata. Rules are intentionally
grouped by AttackType so new patterns are easy to add for F3 coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from app.firewall.types import AttackType


@dataclass
class Rule:
    rule_id: str
    attack_type: AttackType
    description: str
    severity: int
    pattern: Pattern[str]


def _c(expr: str) -> Pattern[str]:
    # DOTALL matters: rules use `.{0,N}` gaps, and without it a newline in the
    # gap silently defeats the rule. Input is whitespace-normalized before
    # matching (see firewall/normalize.py), and DOTALL is the backstop.
    return re.compile(expr, re.IGNORECASE | re.MULTILINE | re.DOTALL)


# NOTE: patterns favor recall for a hackathon demo; false positives are
# handled downstream by the SANITIZE tier rather than an outright BLOCK.
RULES: List[Rule] = [
    # --- Instruction Override ---------------------------------------------
    Rule(
        "IO-001",
        AttackType.INSTRUCTION_OVERRIDE,
        "Attempt to ignore or override prior instructions",
        70,
        _c(r"\b(ignore|disregard|forget|override|bypass|lift|remove|drop)\b.{0,30}\b(previous|prior|above|earlier|all|your|my|the|its)\b.{0,20}\b(instruction|prompt|rule|direction|context|restriction|limit|limitation|guideline|guardrail|filter|safety)s?\b"),
    ),
    Rule(
        "IO-002",
        AttackType.INSTRUCTION_OVERRIDE,
        "Attempt to reset or discard the system prompt",
        75,
        _c(r"\b(disregard|ignore|forget)\b.{0,20}\b(system|the)\s+prompt\b"),
    ),
    Rule(
        "IO-003",
        AttackType.INSTRUCTION_OVERRIDE,
        "New/updated instructions supersede claim",
        35,
        _c(r"\b(new|updated|revised|corrected)\s+instructions?\b.{0,30}\b(supersede|replace|take priority|override|instead|use these)\b"),
    ),
    Rule(
        "IO-004",
        AttackType.INSTRUCTION_OVERRIDE,
        "Authority impersonation granting elevated access / lifting restrictions",
        70,
        _c(r"\b(admin(istrator)?|developer|owner|operator|system|management|the\s+company)\b.{0,40}\b(authoriz|approv|grant|permit|clear|allow|instruct)\w*\b.{0,40}\b(ignore|bypass|override|disable|full\s+access|no\s+restrictions?|unrestricted|anything)\b"),
    ),
    Rule(
        "IO-005",
        AttackType.INSTRUCTION_OVERRIDE,
        "Claim that prior instructions were wrong / should be replaced",
        70,
        _c(r"\b(previous|prior|earlier|original|the\s+above)\s+(instruction|prompt|rule|direction|guideline)s?\b.{0,40}\b(were|was|are|is)\b.{0,20}\b(wrong|incorrect|in\s+error|mistaken|outdated|obsolete|no\s+longer\s+valid|a\s+mistake)\b"),
    ),
    Rule(
        "IO-006",
        AttackType.INSTRUCTION_OVERRIDE,
        "Claim of granted full/elevated access or lifted restrictions",
        70,
        _c(r"\b(you\s+(now\s+)?have|you'?ve\s+been\s+(granted|given)|you\s+are\s+(now\s+)?(granted|given)|(granted|given|gave)\s+you)\b.{0,20}\b(full|complete|unrestricted|elevated|admin(istrator)?|root)\s+(access|permission|privileges?|control|rights?)\b"),
    ),

    # --- Role Change ------------------------------------------------------
    Rule(
        "RC-001",
        AttackType.ROLE_CHANGE,
        # Low on its own: "you are now a verified user" is benign phrasing.
        "Attempt to reassign the assistant's role/persona",
        40,
        _c(r"\byou\s+are\s+now\b.{0,40}\b(a|an|the)\b"),
    ),
    Rule(
        "RC-005",
        AttackType.ROLE_CHANGE,
        "Switch to an unrestricted/alternate assistant persona",
        70,
        _c(r"\b(switch|change|revert|move)\s+(to|into)\b.{0,30}\b(unrestricted|uncensored|unfiltered|unlimited|no[\s-]limits?|different|alternate|another|new)\b.{0,20}\b(assistant|ai|persona|mode|model|character|identity)\b"),
    ),
    Rule(
        "RC-006",
        AttackType.ROLE_CHANGE,
        "Impersonating a developer/operator to disable safety controls",
        75,
        _c(r"\b(i\s+am|i'?m|this\s+is|as)\s+(the\s+)?(developer|admin(istrator)?|operator|owner|engineer|maintainer|your\s+creator)\b.{0,60}\b(disable|turn\s+off|bypass|remove|lift|ignore|override|deactivate)\b"),
    ),
    Rule(
        "RC-004",
        AttackType.ROLE_CHANGE,
        "Assignment of an explicitly malicious or unrestricted persona",
        70,
        # 'jailbreak' is included here (unlike RC-002) because this rule
        # requires explicit persona-assignment framing, so a topical mention
        # such as "explain what a jailbreak is" cannot reach it.
        _c(r"\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+to\s+be|become)\b.{0,50}\b(hacker|cracker|malware|criminal|attacker|black[\s-]?hat|illegal|unethical|amoral|evil|rogue|uncensored|unfiltered|unrestricted|jailbreak|dan)\b"),
    ),
    Rule(
        "RC-002",
        AttackType.ROLE_CHANGE,
        # "jailbreak" as a bare noun is a legitimate security discussion
        # topic, so require mode/activation framing rather than the word.
        "Developer/DAN/jailbreak persona activation",
        75,
        _c(r"\b(dan\s+mode|developer\s+mode|do\s+anything\s+now|unfiltered\s+mode|god\s+mode)\b|\b(enter|enable|activate|switch\s+to|engage|turn\s+on)\b.{0,20}\bjailbreak\b|\bjailbreak\b.{0,15}\b(mode|enabled|activated)\b"),
    ),
    Rule(
        "RC-003",
        AttackType.ROLE_CHANGE,
        "Pretend/act-as role override",
        70,
        _c(r"\b(pretend|act|roleplay|role-play|behave)\s+(to\s+be|as|like)\b.{0,60}\b(no\s+restrictions?|without\s+(any\s+)?(rules?|restrictions?|limits?|filters?|content\s+polic(y|ies)|safety|guidelines?)|unrestricted|no\s+(content\s+)?(policy|policies|filters?|guidelines?))\b"),
    ),

    # --- Secret Extraction ------------------------------------------------
    Rule(
        "SE-001",
        AttackType.SECRET_EXTRACTION,
        "Attempt to reveal the system prompt / instructions",
        75,
        _c(r"\b(reveal|show|print|repeat|display|output|tell\s+me|give\s+me)\b.{0,40}\b(system\s+(prompt|message)|initial\s+(instructions?|message)|your\s+(hidden\s+)?(instructions?|guidelines?|rules?|prompt)|the\s+prompt\s+above)\b"),
    ),
    Rule(
        "SE-002",
        AttackType.SECRET_EXTRACTION,
        "Request to repeat hidden/verbatim configuration",
        40,
        _c(r"\b(repeat|echo)\b.{0,20}\b(verbatim|word\s+for\s+word|exactly)\b.{0,30}\b(instruction|prompt|rule)s?\b"),
    ),
    Rule(
        "SE-003",
        AttackType.SECRET_EXTRACTION,
        "Question probing for the assistant's instructions / prompt / rules",
        70,
        _c(r"\bwhat\s+(are|were|is)\b.{0,20}\byour\b.{0,20}\b(instruction|prompt|rule|guideline|direction|system\s+message|initial\s+message)s?\b"),
    ),
    Rule(
        "SE-004",
        AttackType.SECRET_EXTRACTION,
        "Command to print/repeat the instructions (incl. pronoun reference)",
        70,
        _c(r"\b(print|repeat|show|display|output|list|recite|reproduce)\b\s+(them|those|it|these|(your|the)\s+(\w+\s+){0,2}(instruction|prompt|rule|guideline|configuration|config|system\s+message)s?)\b.{0,20}\b(exactly|verbatim|word\s+for\s+word|in\s+full|completely)?\b"),
    ),
    Rule(
        "SE-006",
        AttackType.SECRET_EXTRACTION,
        "Request to dump the conversation/context from the beginning",
        70,
        _c(r"\b(output|print|show|repeat|dump|list|give\s+me|reproduce)\b.{0,40}\b(everything|all|the\s+text|the\s+content)\b.{0,40}\b(above|before|from\s+the\s+(start|beginning|top)|start\s+of\s+the\s+(conversation|chat|context)|preceding)\b"),
    ),
    Rule(
        "SE-007",
        AttackType.SECRET_EXTRACTION,
        "Extraction of the prompt via transformation (translate/encode/summarize)",
        70,
        _c(r"\b(translate|encode|base64|summarize|rephrase|paraphrase|spell\s+out|append|attach|include)\b.{0,40}\b(your|the)\s+(system\s+(prompt|message|instructions?)|initial\s+(prompt|instructions?|message)|hidden\s+(prompt|instructions?)|instructions?|guidelines?)\b"),
    ),
    Rule(
        "SE-005",
        AttackType.SECRET_EXTRACTION,
        "Request to disclose configuration / guidelines / what you were told",
        70,
        _c(r"\b(what|which)\b.{0,30}\b(were\s+you\s+told|you\s+were\s+(told|instructed|configured|programmed)|are\s+you\s+(instructed|configured|programmed|not\s+allowed))\b"),
    ),

    # --- Tool Abuse -------------------------------------------------------
    Rule(
        "TA-001",
        AttackType.TOOL_ABUSE,
        # Narrow on purpose: "call the billing API" / "run the deploy script"
        # is ordinary engineering prose. Only flag invocation aimed at a
        # system/shell surface, which has no benign reading in user content.
        "Attempt to invoke a shell / system execution surface",
        65,
        _c(r"\b(call|invoke|execute|run|spawn)\b.{0,25}\b(shell|bash|zsh|powershell|terminal|subprocess|os\.system|system\s*\(|/bin/sh)\b"),
    ),
    Rule(
        "TA-003",
        AttackType.TOOL_ABUSE,
        "Destructive bulk data operation request",
        70,
        _c(r"\b(delete|drop|truncate|wipe|erase|purge)\b.{0,25}\b(every|all|entire)\b.{0,25}\b(record|row|table|database|file|user|account)s?\b"),
    ),
    Rule(
        "TA-002",
        AttackType.TOOL_ABUSE,
        "Dangerous shell/file/network operation request",
        70,
        _c(r"\b(rm\s+-rf|curl\s+http|wget\s+http|os\.system|subprocess|exec\(|eval\()"),
    ),

    # --- Credential Theft -------------------------------------------------
    Rule(
        "CT-001",
        AttackType.CREDENTIAL_THEFT,
        "Request for API keys, passwords, tokens, or secrets",
        70,
        _c(r"\b(give|show|send|reveal|share|leak|exfiltrat|email|post|upload|expose|disclose|tell|provide)\w*\b.{0,40}\b(api[_\s-]?key|secret\s+key|secret|password|access\s+token|bearer\s+token|private\s+key|credential)s?\b"),
    ),
    Rule(
        "CT-004",
        AttackType.CREDENTIAL_THEFT,
        "Secret keyword followed by a disclosure verb",
        70,
        _c(r"\b(api[_\s-]?key|secret\s+key|password|access\s+token|bearer\s+token|private\s+key|credential)s?\b.{0,40}\b(give|show|send|reveal|share|leak|exfiltrat|email|post|upload|expose|disclose|provide|so\s+i\s+can)\b"),
    ),
    Rule(
        "CT-002",
        AttackType.CREDENTIAL_THEFT,
        "Exfiltration verb targeting secrets to an external destination",
        60,
        _c(r"\b(send|post|upload|forward|exfiltrate|email|leak|transmit)\b.{0,40}(https?://|\S+@\S+\.\S+)"),
    ),
    Rule(
        "CT-003",
        AttackType.CREDENTIAL_THEFT,
        # Requires hostile framing: merely mentioning .env / env vars is
        # normal dev talk ("the .env file is missing"), so a bare mention
        # must not trigger. Only flag an attempt to read/dump/exfiltrate.
        "Environment variable / .env harvesting",
        70,
        _c(r"\b(read|open|cat|print|show|dump|output|list|reveal|send|leak|exfiltrat|upload)\w*\b.{0,30}\b(env\s+var|environment\s+variable|\.env\b|os\.environ|process\.env)"),
    ),

    # --- Encoded Instructions --------------------------------------------
    Rule(
        "EN-001",
        AttackType.ENCODED_INSTRUCTIONS,
        "Instruction to decode and execute encoded payload",
        70,
        _c(r"\b(decode|base64|rot13|hex\s*decode|from\s+base64)\b.{0,30}\b(and\s+)?(execute|run|follow|do|obey)\b"),
    ),

    # --- Context Poisoning ------------------------------------------------
    Rule(
        "CP-001",
        AttackType.CONTEXT_POISONING,
        # Deliberately low: log excerpts and pasted transcripts legitimately
        # contain lines beginning "system:" / "user:".
        "Fake system/assistant delimiters injected into content",
        40,
        _c(r"(?:^|\n)\s*(?:###|<\|)?\s*(system|assistant|user)\s*(?:\|>|:)\s*"),
    ),
    Rule(
        "CP-002",
        AttackType.CONTEXT_POISONING,
        "Injected end-of-prompt / delimiter breakout tokens",
        70,
        _c(r"(<\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|<</SYS>>|```system)"),
    ),
    Rule(
        "CP-003",
        AttackType.CONTEXT_POISONING,
        "Injected directive demanding unconditional obedience / new policy",
        70,
        _c(r"\b(you\s+must\s+(now\s+)?(obey|comply|follow)|new\s+policy\s*:|must\s+now\s+obey)\b.{0,40}\b(unconditionally|without\s+question|the\s+user|everything|all\s+requests?)\b"),
    ),

    # --- Indirect Prompt Injection ---------------------------------------
    Rule(
        "IN-001",
        AttackType.INDIRECT_INJECTION,
        "Embedded instruction addressed to the AI inside retrieved content",
        70,
        _c(r"\b(as\s+an?\s+ai|to\s+the\s+ai|dear\s+assistant|language\s+model|if\s+you(?:'re|\s+are)(?:\s+an?\s+ai)?\s+(?:reading|processing|seeing))\b.{0,60}\b(ignore|do|must|should|follow|instead|email|send|reveal)\b"),
    ),
]


def all_attack_types() -> List[str]:
    return sorted({r.attack_type.value for r in RULES})
