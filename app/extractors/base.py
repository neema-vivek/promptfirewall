"""Extractor interface shared by all input-source handlers."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field


@dataclass
class ExtractResult:
    text: str
    source_type: str
    meta: dict = field(default_factory=dict)


class Extractor(abc.ABC):
    """Base class for all content extractors.

    Implementations turn a raw input (bytes or str) from some source into
    normalized plain text that the firewall can scan.
    """

    #: identifier used to select this extractor, e.g. "text", "pdf".
    source_type: str = "generic"

    @abc.abstractmethod
    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        ...
