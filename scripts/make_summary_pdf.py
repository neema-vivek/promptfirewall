"""Generate a 2-3 page summary PDF of the Prompt Injection Firewall.

Usage: python scripts/make_summary_pdf.py
Output: Prompt_Injection_Firewall_Summary.pdf  (project root)
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parents[1] / "Prompt_Injection_Firewall_Summary.pdf"

NAVY = colors.HexColor("#1f2a44")
BLUE = colors.HexColor("#2f6df6")
GREEN = colors.HexColor("#2e9e5b")
AMBER = colors.HexColor("#c9871f")
RED = colors.HexColor("#c0392b")
GREY = colors.HexColor("#5b6472")
LIGHT = colors.HexColor("#eef1f6")


def styles():
    # Custom style names are prefixed "pf" to avoid clashing with the
    # built-in names reportlab already defines (Title, Bullet, Code, ...).
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("pfTitle", parent=ss["Title"], fontSize=22,
                          textColor=NAVY, spaceAfter=2, leading=26))
    ss.add(ParagraphStyle("pfSub", parent=ss["Normal"], fontSize=10.5,
                          textColor=GREY, spaceAfter=10, leading=14))
    ss.add(ParagraphStyle("pfH2", parent=ss["Heading2"], fontSize=13,
                          textColor=BLUE, spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle("pfBody", parent=ss["Normal"], fontSize=9.6,
                          leading=13.5, spaceAfter=5, alignment=TA_LEFT))
    ss.add(ParagraphStyle("pfBullet", parent=ss["Normal"], fontSize=9.4,
                          leading=13, spaceAfter=1.5))
    ss.add(ParagraphStyle("pfMono", parent=ss["Code"], fontSize=8.4,
                          leading=11, textColor=NAVY, backColor=LIGHT,
                          borderPadding=6, spaceBefore=3, spaceAfter=6))
    ss.add(ParagraphStyle("pfSmall", parent=ss["Normal"], fontSize=8.3,
                          textColor=GREY, leading=11))
    return ss


def build():
    S = styles()
    story = []

    # ---- Header -----------------------------------------------------------
    story.append(Paragraph("🛡️ Prompt Injection Firewall", S["pfTitle"]))
    story.append(Paragraph(
        "A security layer that intercepts content before it reaches an AI/LLM, "
        "detecting and neutralizing prompt-injection attacks while letting "
        "legitimate content pass with minimal disruption.", S["pfSub"]))
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT))
    story.append(Spacer(1, 6))

    # ---- What it is -------------------------------------------------------
    story.append(Paragraph("What it is", S["pfH2"]))
    story.append(Paragraph(
        "AI agents, copilots, and chatbots increasingly read external content "
        "(web pages, PDFs, emails, API responses) and can call tools. That "
        "exposes them to <b>prompt injection</b> &mdash; hidden instructions "
        "that make the AI obey an attacker instead of the user. This firewall "
        "sits in front of the model and inspects every input first.", S["pfBody"]))
    story.append(Paragraph(
        "<font face='Courier'>incoming content &nbsp;&rarr;&nbsp; [ FIREWALL ] "
        "&nbsp;&rarr;&nbsp; ALLOW / SANITIZE / BLOCK &nbsp;&rarr;&nbsp; the AI"
        "</font>", S["pfMono"]))

    verdict_tbl = Table([
        [Paragraph("<b>ALLOW</b>", S["pfBullet"]),
         Paragraph("Looks safe &mdash; passes through unchanged.", S["pfBullet"])],
        [Paragraph("<b>SANITIZE</b>", S["pfBullet"]),
         Paragraph("Suspicious parts redacted; safe remainder forwarded.", S["pfBullet"])],
        [Paragraph("<b>BLOCK</b>", S["pfBullet"]),
         Paragraph("High-risk injection &mdash; nothing reaches the AI.", S["pfBullet"])],
    ], colWidths=[26 * mm, 142 * mm])
    verdict_tbl.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (0, 0), GREEN),
        ("TEXTCOLOR", (0, 1), (0, 1), AMBER),
        ("TEXTCOLOR", (0, 2), (0, 2), RED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(verdict_tbl)
    story.append(Spacer(1, 4))

    # ---- Coverage ---------------------------------------------------------
    story.append(Paragraph("What it detects &amp; reads", S["pfH2"]))
    cov = Table([
        [Paragraph("<b>9 attack types</b>", S["pfBullet"]),
         Paragraph("Instruction Override, Role Change, Secret Extraction, "
                   "Tool Abuse, Credential Theft, Context Poisoning, "
                   "Multi-Step Jailbreaks, Encoded Instructions, "
                   "Indirect Prompt Injection.", S["pfBullet"])],
        [Paragraph("<b>Input sources</b>", S["pfBullet"]),
         Paragraph("Plain text, HTML / web pages, PDF, Email (.eml), Word "
                   "(.docx), Markdown, source code, API / JSON, Images (OCR, "
                   "optional).", S["pfBullet"])],
    ], colWidths=[34 * mm, 134 * mm])
    cov.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, 0), 0.4, LIGHT),
    ]))
    story.append(cov)
    story.append(Spacer(1, 4))

    # ---- How it decides ---------------------------------------------------
    story.append(Paragraph("How it decides &mdash; four layers", S["pfH2"]))
    layers = ListFlowable([
        ListItem(Paragraph("<b>Rules</b> &mdash; ~30 pattern/heuristic rules over "
                 "<i>normalized</i> text (whitespace collapsed, zero-width "
                 "characters stripped, full-width folded), so line wraps and "
                 "typographic tricks don't evade detection.", S["pfBullet"])),
        ListItem(Paragraph("<b>Decoders</b> &mdash; base64/hex/rot13 payloads are "
                 "decoded and re-scanned, catching instructions hidden inside "
                 "encoded blobs.", S["pfBullet"])),
        ListItem(Paragraph("<b>LLM classifier (optional)</b> &mdash; a semantic "
                 "second opinion that judges <i>intent</i> to catch paraphrases "
                 "the rules miss; runs only on inconclusive inputs and degrades "
                 "safely if unavailable.", S["pfBullet"])),
        ListItem(Paragraph("<b>Session tracker</b> &mdash; spots multi-step "
                 "jailbreaks built gradually across conversation turns.", S["pfBullet"])),
    ], bulletType="1", leftIndent=14)
    story.append(layers)

    story.append(Paragraph(
        "<b>Scoring:</b> risk = max(matched severity) + 20&times;(extra attack "
        "types) + up to 15 for repetition. Risk &ge; 70 &rarr; BLOCK; &ge; 30 "
        "&rarr; SANITIZE; otherwise ALLOW (thresholds configurable). Severities "
        "are calibrated so an unambiguous attack blocks on its own while "
        "ambiguous phrasing needs corroboration.", S["pfBody"]))

    # ---- Honest performance ----------------------------------------------
    story.append(Paragraph("Measured reliability (honest numbers)", S["pfH2"]))
    story.append(Paragraph(
        "The benchmark counts BLOCKED, FORWARDED, and MISSED separately &mdash; a "
        "redacted-but-forwarded attack is not scored as a clean win. Two corpora "
        "are reported: one the rules were tuned on, and a held-out set they were "
        "not.", S["pfBody"]))
    perf = Table([
        ["Corpus", "Blocked", "Forwarded", "Missed", "False alarms"],
        ["corpus.json  (tuned on)", "54 / 54", "0", "0", "0 / 30"],
        ["holdout.json  (never tuned)", "7 / 17", "3", "7", "0 / 13"],
    ], colWidths=[58 * mm, 26 * mm, 26 * mm, 24 * mm, 34 * mm])
    perf.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.6),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.white),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(perf)
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "<b>Read the holdout row.</b> On novel phrasings the rule layer catches "
        "~59% with <b>0% false positives</b> (no benign message was ever "
        "flagged, including deliberate near-misses). The optional LLM classifier "
        "layer is the designed answer for the remaining novel and multilingual "
        "attacks.", S["pfSmall"]))

    # ---- Setup ------------------------------------------------------------
    story.append(Paragraph("Setup", S["pfH2"]))
    story.append(Paragraph(
        "Runs fully offline with no API key (rules only). Python 3.10+.", S["pfBody"]))
    story.append(Paragraph(
        "pip install -r requirements.txt<br/>"
        "uvicorn app.main:app --reload<br/>"
        "# open http://127.0.0.1:8000", S["pfMono"]))
    story.append(Paragraph(
        "<b>Enable the LLM layer (optional)</b> &mdash; create a <font "
        "face='Courier'>.env</font>:", S["pfBody"]))
    story.append(Paragraph(
        "OPENAI_API_KEY=your-key<br/>"
        "OPENAI_BASE_URL=https://YOUR-RESOURCE.openai.azure.com/openai/v1<br/>"
        "OPENAI_MODEL=your-deployment-name&nbsp;&nbsp;# Azure: deployment, not model<br/>"
        "FIREWALL_LLM_MODE=all", S["pfMono"]))

    # ---- Integration ------------------------------------------------------
    story.append(Paragraph("Integrating with an existing chatbot / app", S["pfH2"]))
    story.append(Paragraph(
        "<b>As a service (any language)</b> &mdash; POST to the firewall before "
        "calling your own LLM; block when the verdict is BLOCK, forward "
        "<font face='Courier'>sanitized_text</font> when it is SANITIZE:", S["pfBody"]))
    story.append(Paragraph(
        "r = httpx.post('http://127.0.0.1:8000/api/scan',<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;json={'content': user_text, 'source_type': 'text'})<br/>"
        "if r.json()['verdict'] == 'BLOCK': refuse()<br/>"
        "else: my_llm(user_text)", S["pfMono"]))
    story.append(Paragraph(
        "<b>In-process (Python)</b> &mdash; import the engine directly:", S["pfBody"]))
    story.append(Paragraph(
        "from app.firewall import Firewall, Verdict<br/>"
        "result = Firewall().scan(user_message, session_id=sid)<br/>"
        "if result.verdict == Verdict.BLOCK: refuse()<br/>"
        "else: my_llm(result.sanitized_text or user_message)", S["pfMono"]))
    story.append(Paragraph(
        "<b>Guard retrieved content (RAG / agents)</b> &mdash; the high-value case: "
        "run every web page, PDF, or email through the extractor + firewall "
        "<i>before</i> it enters the model's context. Indirect injection lives in "
        "retrieved content, which is the easiest path to forget.", S["pfBody"]))

    # ---- Limitations ------------------------------------------------------
    story.append(Paragraph("Scope &amp; known limitations", S["pfH2"]))
    story.append(Paragraph(
        "This is a hackathon prototype. Current gaps, documented honestly: "
        "the <font face='Courier'>firewall_enabled</font> / "
        "<font face='Courier'>system_prompt</font> request-body flags are "
        "unauthenticated and should be server-side in production; there is no "
        "output-side scanning yet (inputs only); email HTML alternatives and "
        "attachments, percent/entity encodings, and multi-layer base64 are not "
        "fully handled; non-English attacks rely on the LLM layer. The rule layer "
        "is strong on known attack families with zero false positives; the LLM "
        "layer covers novel and multilingual phrasings.", S["pfSmall"]))

    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.6, color=LIGHT))
    story.append(Paragraph(
        "Agentic Cybersecurity &mdash; Prompt Injection Firewall &nbsp;|&nbsp; "
        "full details in DOCUMENTATION.md &nbsp;|&nbsp; demo UI at "
        "http://127.0.0.1:8000", S["pfSmall"]))

    doc = SimpleDocTemplate(
        str(OUT), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=14 * mm,
        title="Prompt Injection Firewall - Summary",
    )
    doc.build(story)
    print("wrote", OUT)


if __name__ == "__main__":
    build()

