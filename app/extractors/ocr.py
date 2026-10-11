"""OCR extractor for images (pytesseract + Pillow).

Turns image bytes into text so the firewall can scan instructions hidden
inside screenshots, scanned documents, or memes — a real indirect-injection
vector for multimodal agents (requirement D3).

Degrades gracefully: if Pillow/pytesseract are not installed, or the
Tesseract binary is missing, this returns an empty ExtractResult with an
explanatory note in .meta instead of raising. That keeps the rest of the
app (and the offline demo) working even when OCR is unavailable.

Setup for real OCR:
  1. pip install pytesseract Pillow
  2. Install the Tesseract binary:
       - Windows: https://github.com/UB-Mannheim/tesseract/wiki
       - macOS:   brew install tesseract
       - Linux:   apt-get install tesseract-ocr
  3. If tesseract is not on PATH, set OCR_TESSERACT_CMD to its full path.
"""
from __future__ import annotations

import io
import os

from app.extractors.base import Extractor, ExtractResult


class OCRExtractor(Extractor):
    source_type = "image"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        if not isinstance(content, (bytes, bytearray)):
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={"ocr": "error", "reason": "OCR expects image bytes"},
            )

        # Import lazily so the app runs without OCR libraries installed.
        try:
            import pytesseract
            from PIL import Image
        except ModuleNotFoundError as exc:
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={
                    "ocr": "unavailable",
                    "reason": (
                        f"OCR libraries not installed ({exc.name}). "
                        "Run: pip install pytesseract Pillow"
                    ),
                },
            )

        # Allow pointing at a non-PATH tesseract binary via env var.
        custom_cmd = os.getenv("OCR_TESSERACT_CMD")
        if custom_cmd:
            pytesseract.pytesseract.tesseract_cmd = custom_cmd

        try:
            image = Image.open(io.BytesIO(bytes(content)))
        except Exception as exc:  # noqa: BLE001 - unreadable/invalid image
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={"ocr": "error", "reason": f"Could not open image: {exc}"},
            )

        try:
            text = pytesseract.image_to_string(image)
        except pytesseract.TesseractNotFoundError:
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={
                    "ocr": "unavailable",
                    "reason": (
                        "Tesseract binary not found. Install it and/or set "
                        "OCR_TESSERACT_CMD to its full path."
                    ),
                },
            )
        except Exception as exc:  # noqa: BLE001 - any OCR runtime failure
            return ExtractResult(
                text="",
                source_type=self.source_type,
                meta={"ocr": "error", "reason": f"OCR failed: {exc}"},
            )

        return ExtractResult(
            text=text.strip(),
            source_type=self.source_type,
            meta={"ocr": "ok", "chars": len(text.strip())},
        )
