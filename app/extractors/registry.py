"""Registry that maps a source type to its extractor, plus type detection."""
from __future__ import annotations

from app.extractors.base import Extractor, ExtractResult
from app.extractors.docx import DocxExtractor
from app.extractors.email_extractor import EmailExtractor
from app.extractors.html import HTMLExtractor
from app.extractors.markdown import CodeExtractor, MarkdownExtractor
from app.extractors.ocr import OCRExtractor
from app.extractors.pdf import PDFExtractor
from app.extractors.text import TextExtractor

_REGISTRY: dict[str, Extractor] = {
    "text": TextExtractor(),
    "html": HTMLExtractor(),
    "markdown": MarkdownExtractor(),
    "code": CodeExtractor(),
    "pdf": PDFExtractor(),
    "docx": DocxExtractor(),
    "email": EmailExtractor(),
    "image": OCRExtractor(),  # real OCR; degrades gracefully if unavailable
}

# Map file extensions and content-types to a source type.
_EXT_MAP = {
    ".txt": "text",
    ".html": "html", ".htm": "html",
    ".md": "markdown", ".markdown": "markdown",
    ".pdf": "pdf",
    ".docx": "docx",
    ".eml": "email",
    ".py": "code", ".js": "code", ".ts": "code", ".java": "code",
    ".c": "code", ".cpp": "code", ".go": "code", ".rb": "code",
    ".sh": "code", ".json": "code", ".yaml": "code", ".yml": "code",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
}

_CTYPE_MAP = {
    "text/html": "html",
    "text/markdown": "markdown",
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "message/rfc822": "email",
}


def detect_source_type(filename: str = "", content_type: str = "") -> str:
    """Best-effort source-type detection from filename and/or content-type."""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in _CTYPE_MAP:
        return _CTYPE_MAP[ct]

    name = (filename or "").lower()
    for ext, stype in _EXT_MAP.items():
        if name.endswith(ext):
            return stype

    if ct.startswith("image/"):
        return "image"
    return "text"


def get_extractor(source_type: str) -> Extractor:
    return _REGISTRY.get(source_type, _REGISTRY["text"])


def extract(content, source_type: str = "text") -> ExtractResult:  # noqa: ANN001
    return get_extractor(source_type).extract(content)


def supported_source_types() -> list[str]:
    return sorted(_REGISTRY.keys())
