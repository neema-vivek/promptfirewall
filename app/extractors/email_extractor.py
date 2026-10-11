"""Email (.eml) extractor using the standard-library email parser.

Pulls the subject, key headers, and the text body (preferring text/plain,
falling back to stripped text/html). Emails are a prime indirect-injection
vector, so headers like Subject and From are included in the scanned text.
"""
from __future__ import annotations

from email import message_from_bytes, message_from_string
from email.message import Message

from app.extractors.base import Extractor, ExtractResult


class EmailExtractor(Extractor):
    source_type = "email"

    def extract(self, content) -> ExtractResult:  # noqa: ANN001
        if isinstance(content, (bytes, bytearray)):
            msg = message_from_bytes(bytes(content))
        else:
            msg = message_from_string(str(content))

        parts: list[str] = []
        for header in ("From", "To", "Subject"):
            val = msg.get(header)
            if val:
                parts.append(f"[{header}] {val}")

        body = self._body(msg)
        if body:
            parts.append(body)

        return ExtractResult(
            text="\n".join(parts).strip(),
            source_type=self.source_type,
        )

    def _body(self, msg: Message) -> str:
        plain: list[str] = []
        html: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if part.get_content_maintype() == "multipart":
                    continue
                payload = self._decode(part)
                if not payload:
                    continue
                if ctype == "text/plain":
                    plain.append(payload)
                elif ctype == "text/html":
                    html.append(payload)
        else:
            payload = self._decode(msg)
            if payload:
                if msg.get_content_type() == "text/html":
                    html.append(payload)
                else:
                    plain.append(payload)

        if plain:
            return "\n".join(plain)
        if html:
            # Reuse the HTML extractor so hidden comments/attrs are surfaced.
            from app.extractors.html import HTMLExtractor

            return HTMLExtractor().extract("\n".join(html)).text
        return ""

    @staticmethod
    def _decode(part: Message) -> str:
        try:
            raw = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001
            return ""
        if raw is None:
            payload = part.get_payload()
            return payload if isinstance(payload, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return raw.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return raw.decode("utf-8", errors="replace")
