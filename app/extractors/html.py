"""HTML extractor.

Prompt injections in web pages frequently hide where a human reader won't
look: HTML comments, hidden elements (display:none / visibility:hidden),
and attributes like alt/title/aria-label. This extractor pulls the visible
text AND those hiding spots so the firewall can inspect them.

Falls back to a crude tag-strip if beautifulsoup4 is not installed.
"""
from __future__ import annotations

import re

from app.extractors.base import Extractor, ExtractResult


class HTMLExtractor(Extractor):
    source_type = "html"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        html = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)

        try:
            from bs4 import BeautifulSoup, Comment
        except ModuleNotFoundError:
            return self._fallback(html)

        soup = BeautifulSoup(html, "html.parser")

        parts: list[str] = []

        # 1. Visible text (script/style stripped).
        for tag in soup(["script", "style"]):
            tag.decompose()
        visible = soup.get_text(separator=" ", strip=True)
        if visible:
            parts.append(visible)

        # 2. HTML comments — a classic hiding place for injections.
        comments = soup.find_all(string=lambda t: isinstance(t, Comment))
        for c in comments:
            text = str(c).strip()
            if text:
                parts.append(f"[html-comment] {text}")

        # 3. Suspicious attributes that can carry hidden instructions.
        for el in soup.find_all(True):
            for attr in ("alt", "title", "aria-label", "data-prompt", "content"):
                val = el.get(attr)
                if val and isinstance(val, str) and val.strip():
                    parts.append(f"[{attr}] {val.strip()}")

        combined = "\n".join(parts)
        meta = {
            "comment_count": len(comments),
            "used_fallback": False,
        }
        return ExtractResult(text=combined, source_type=self.source_type, meta=meta)

    def _fallback(self, html: str) -> ExtractResult:
        # Keep comment contents, then strip tags.
        comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        no_tags = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", no_tags).strip()
        if comments:
            text += "\n" + "\n".join(f"[html-comment] {c.strip()}" for c in comments)
        return ExtractResult(
            text=text,
            source_type=self.source_type,
            meta={"used_fallback": True},
        )
