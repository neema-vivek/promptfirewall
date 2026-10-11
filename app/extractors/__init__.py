"""Content extractors: turn various input sources into plain text.

MVP v1 ships a text extractor. PDF/DOCX/HTML/email/OCR extractors plug in
behind the same Extractor interface later without touching the firewall.
"""
from app.extractors.base import Extractor, ExtractResult
from app.extractors.registry import (
    detect_source_type,
    extract,
    get_extractor,
    supported_source_types,
)

__all__ = [
    "Extractor",
    "ExtractResult",
    "extract",
    "get_extractor",
    "detect_source_type",
    "supported_source_types",
]
