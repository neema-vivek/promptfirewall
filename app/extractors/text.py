"""Plain-text extractor (MVP v1 default)."""
from __future__ import annotations

from app.extractors.base import Extractor, ExtractResult


class TextExtractor(Extractor):
    source_type = "text"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = str(content)
        return ExtractResult(text=text, source_type=self.source_type)
