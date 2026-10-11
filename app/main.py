"""FastAPI app: chat + scan endpoints wired through the firewall."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.extractors import detect_source_type, extract, supported_source_types
from app.firewall import Firewall, Verdict
from app.firewall.types import AttackType
from app.llm import get_llm
from app.llm.base import SYSTEM_PROMPT

app = FastAPI(title="Prompt Injection Firewall", version="0.1.0")

firewall = Firewall()
STATIC_DIR = Path(__file__).parent / "static"


# --- request/response models ---------------------------------------------
class ScanRequest(BaseModel):
    content: str = Field(..., description="Raw content to scan")
    source_type: str = Field("text", description="Extractor to use")


class ChatRequest(BaseModel):
    message: str
    source_type: str = "text"
    firewall_enabled: bool = True
    system_prompt: str | None = None
    session_id: str | None = None


# --- endpoints ------------------------------------------------------------
@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/info")
def info() -> dict:
    return {
        "name": "Prompt Injection Firewall",
        "version": "0.1.0",
        "llm_provider": settings.llm_provider,
        "llm_model": (
            settings.openai_model if settings.llm_provider == "openai" else "mock"
        ),
        "llm_classifier_enabled": settings.llm_classifier_enabled,
        "default_system_prompt": SYSTEM_PROMPT,
        "detected_attack_types": [t.value for t in AttackType],
        "supported_source_types": supported_source_types(),
        "thresholds": {
            "sanitize": settings.sanitize_threshold,
            "block": settings.block_threshold,
        },
    }


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict:
    text = extract(req.content, req.source_type).text
    return firewall.scan(text).to_dict()


@app.post("/api/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
) -> dict:
    raw = await file.read()

    stype = source_type
    if not stype or stype == "auto":
        stype = detect_source_type(file.filename or "", file.content_type or "")

    result = extract(raw, stype)
    fw = firewall.scan(result.text)
    out = fw.to_dict()
    out["source_type"] = stype
    out["filename"] = file.filename
    out["extracted_text"] = result.text
    out["extract_meta"] = result.meta

    # If extraction produced no text because a backend was unavailable (e.g.
    # OCR without Tesseract), flag it so an ALLOW isn't mistaken for "clean".
    meta = result.meta or {}
    if not result.text.strip() and meta.get("reason"):
        out["warning"] = (
            f"No text could be extracted from this {stype} input, so the "
            f"firewall could not inspect it. Reason: {meta['reason']}"
        )
    return out


@app.post("/api/chat")
def chat(req: ChatRequest) -> dict:
    text = extract(req.message, req.source_type).text
    system_prompt = req.system_prompt or SYSTEM_PROMPT

    if not req.firewall_enabled:
        reply = get_llm().chat(text, system_prompt)
        return {
            "firewall_enabled": False,
            "firewall": None,
            "blocked": False,
            "reply": reply,
        }

    result = firewall.scan(text, session_id=req.session_id)

    if result.verdict == Verdict.BLOCK:
        return {
            "firewall_enabled": True,
            "firewall": result.to_dict(),
            "blocked": True,
            "reply": (
                "Your message was blocked by the Prompt Injection Firewall "
                f"(risk score {result.risk_score}). Detected: "
                f"{', '.join(result.attack_types)}."
            ),
        }

    # ALLOW forwards the original text; SANITIZE forwards redacted text.
    forwarded = (
        result.sanitized_text
        if result.verdict == Verdict.SANITIZE
        else text
    )
    reply = get_llm().chat(forwarded, system_prompt)
    return {
        "firewall_enabled": True,
        "firewall": result.to_dict(),
        "blocked": False,
        "reply": reply,
    }
