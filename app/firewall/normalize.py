"""Text normalization for reliable rule matching.

Rules are written as `keyword .{0,N} keyword`, which breaks the moment a
newline or a run of whitespace lands in the gap. Extracted document text
(PDF, HTML, Word) is line-wrapped by nature, so without normalization an
injection that spans a line break is invisible to every rule.

This module collapses all whitespace runs (including newlines) to a single
space *and* records the mapping back to the original offsets, so detections
found in the normalized text can still be redacted in the original.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import List

_WS_RUN = re.compile(r"\s+")

# Zero-width and other invisible format characters used to break up keywords.
_INVISIBLE = dict.fromkeys(
    [
        0x200B,  # zero width space
        0x200C,  # zero width non-joiner
        0x200D,  # zero width joiner
        0x2060,  # word joiner
        0xFEFF,  # zero width no-break space
        0x00AD,  # soft hyphen
    ]
)


@dataclass
class Normalized:
    """Normalized text plus a map from normalized index -> original index."""

    text: str
    index_map: List[int]
    original: str

    def to_original_span(self, start: int, end: int) -> tuple[int, int]:
        """Translate a span in normalized space back to the original text."""
        if not self.index_map:
            return (start, end)
        s = self.index_map[start] if start < len(self.index_map) else len(self.original)
        # `end` is exclusive: map the last included char, then step past it.
        if end <= 0:
            return (s, s)
        last = min(end - 1, len(self.index_map) - 1)
        e = self.index_map[last] + 1
        return (s, max(e, s))


def normalize(text: str) -> Normalized:
    """Collapse whitespace and strip invisible characters, keeping an offset map.

    NFKC folds full-width and other compatibility forms (e.g. 'Ｉｇｎｏｒｅ'
    -> 'Ignore') so typographic evasion doesn't defeat the rules.
    """
    out_chars: List[str] = []
    index_map: List[int] = []

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        # Drop invisible/format characters entirely.
        if ord(ch) in _INVISIBLE:
            i += 1
            continue

        if ch.isspace():
            # Collapse the whole run to a single space, mapped to its start.
            if out_chars and out_chars[-1] != " ":
                out_chars.append(" ")
                index_map.append(i)
            j = i
            while j < n and text[j].isspace():
                j += 1
            i = j
            continue

        # NFKC-fold this character; it may expand to multiple chars.
        folded = unicodedata.normalize("NFKC", ch)
        for fc in folded:
            out_chars.append(fc)
            index_map.append(i)
        i += 1

    # Trim a leading space introduced by leading whitespace.
    if out_chars and out_chars[0] == " ":
        out_chars.pop(0)
        index_map.pop(0)

    return Normalized(text="".join(out_chars), index_map=index_map, original=text)
