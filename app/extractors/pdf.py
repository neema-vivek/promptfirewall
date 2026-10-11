"""PDF extractor (uses pypdf; degrades gracefully if missing)."""
from __future__ import annotations

import io

from app.extractors.base import Extractor, ExtractResult


class PDFExtractor(Extractor):
    source_type = "pdf"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        if not isinstance(content, (bytes, bytearray)):
            raise ValueError("PDFExtractor expects bytes")

        try:
            from pypdf import PdfReader
        except ModuleNotFoundError:
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={"error": "pypdf not installed; run pip install pypdf"},
            )

        reader = PdfReader(io.BytesIO(content))
        pages: list[str] = []
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception:  # noqa: BLE001 - skip unreadable pages
                continue

        text = "\n".join(pages).strip()
        return ExtractResult(
            text=text,
            source_type=self.source_type,
            meta={"pages": len(reader.pages)},
        )
