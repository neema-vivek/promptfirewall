"""Markdown extractor.

Markdown can embed raw HTML (including comments) and link/image titles,
which are common hiding spots for indirect injections. We keep the raw
text (so fenced code and prose are scanned) and additionally surface HTML
comments and link titles explicitly.
"""
from __future__ import annotations

import re

from app.extractors.base import Extractor, ExtractResult

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
# [text](url "title")  or  ![alt](url "title")
_LINK_TITLE = re.compile(r'\]\([^)]*?"([^"]+)"\)')
_IMG_ALT = re.compile(r'!\[([^\]]+)\]')


class MarkdownExtractor(Extractor):
    source_type = "markdown"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

        extras: list[str] = []
        for c in _HTML_COMMENT.findall(text):
            if c.strip():
                extras.append(f"[md-comment] {c.strip()}")
        for t in _LINK_TITLE.findall(text):
            extras.append(f"[link-title] {t.strip()}")
        for a in _IMG_ALT.findall(text):
            extras.append(f"[img-alt] {a.strip()}")

        combined = text if not extras else text + "\n" + "\n".join(extras)
        return ExtractResult(text=combined, source_type=self.source_type)


class CodeExtractor(Extractor):
    """Source code: the whole file is scanned; comments/strings included."""

    source_type = "code"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)
        return ExtractResult(text=text, source_type=self.source_type)
