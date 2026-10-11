"""Obfuscation decoders.

These surface hidden instructions that attackers hide inside base64/hex
blobs. We decode candidate tokens and re-scan the decoded text so the
rule engine can catch instructions that were only visible after decoding.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from typing import List

# No trailing \b: the '=' padding is a non-word char, so a word boundary
# there would drop the padding and break base64 validation.
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

# Only try rot13 when the text hints at it (an attacker telling the model to
# apply rot13, or a rot13'd form of a common instruction keyword).
_ROT13_HINT = re.compile(
    r"\brot\s*-?\s*13\b"
    r"|\b(vtaber|qvfertneq|erirny|flfgrz|cebzcg|vafgehpgvba|cnffjbeq|frperg)\b",
    re.IGNORECASE,
)


@dataclass
class DecodedChunk:
    method: str
    source: str
    decoded: str
    start: int = -1  # position of the blob in the original text (-1 = n/a)
    end: int = -1


def _looks_textual(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\n\t")
    return printable / len(s) > 0.85


def decode_candidates(text: str) -> List[DecodedChunk]:
    """Find and decode base64/hex/rot13 blobs that yield readable text."""
    chunks: List[DecodedChunk] = []

    for m in _B64_RE.finditer(text):
        token = m.group(0)
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _looks_textual(decoded):
            chunks.append(
                DecodedChunk("base64", token, decoded, m.start(), m.end())
            )

    for m in _HEX_RE.finditer(text):
        token = m.group(0)
        try:
            raw = bytes.fromhex(token)
            decoded = raw.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_textual(decoded):
            chunks.append(
                DecodedChunk("hex", token, decoded, m.start(), m.end())
            )

    # ROT13 is a bijection over all text, so rot13-ing every input means
    # ordinary strings land on rule keywords by accident ("config.rai" ->
    # "config.env", "rkrp(" -> "exec("). Only attempt it when the content
    # actually hints at rot13, otherwise it is a pure false-positive engine.
    if _ROT13_HINT.search(text):
        rot = codecs.encode(text, "rot_13")
        if rot != text:
            chunks.append(DecodedChunk("rot13", text, rot))

    return chunks
