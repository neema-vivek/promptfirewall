# 🛡️ Prompt Injection Firewall
# 🛡️ Prompt Injection Firewall

A firewall that intercepts content **before** it reaches an LLM, detects and
neutralizes prompt-injection attacks, and lets legitimate content through with
minimal disruption. Ships as a chatbot demo so the firewall's value is visible.

> 📖 **Looking for the full write-up?** See **[DOCUMENTATION.md](DOCUMENTATION.md)**
> for a short overview plus in-depth coverage of how it works, setup, the HTTP
> API, and how to integrate the firewall into your own chatbot or application.

## Architecture

```
Input sources ─▶ [Extractor] ─▶ [Firewall Engine] ─▶ ALLOW / SANITIZE / BLOCK
 (text, HTML, PDF,                    │ Layer 1 rules
  email, docx, md,                    │ Layer 2 decode & re-scan
  code, API JSON)                     │ Layer 3 LLM classifier (optional)
                                      │ Layer 4 session tracker (multi-step)
                                      ▼
                               [LLM / AI agent]
```

- **Extractor layer** — normalizes every input source to text and surfaces the
  spots attackers hide in: HTML comments and `alt`/`title` attributes, `.docx`
  table cells, email headers, markdown link titles. Images are read via OCR
  (Tesseract), which degrades gracefully when the binary isn't installed.
- **Firewall engine** — four layers:
  1. **Rules** — ~25 regex/heuristic rules across the attack types.
  2. **Decode & re-scan** — base64/hex/rot13 payloads are decoded and re-scanned.
  3. **LLM classifier** *(optional)* — a semantic second opinion that catches
     paraphrases regex misses; only runs on inconclusive inputs.
  4. **Session tracker** — detects multi-step jailbreaks built across turns.
- **Verdict** — a 0–100 risk score maps to ALLOW / SANITIZE (redact malicious
  spans) / BLOCK (never reaches the AI). Thresholds are configurable.
- **LLM adapter** — `mock` (offline, no key) or OpenAI/Azure-compatible.

## Attack types detected (F3: all 9)

Instruction Override · Role Change · Secret Extraction · Tool Abuse ·
Credential Theft · Context Poisoning · Encoded Instructions ·
Indirect Prompt Injection · Multi-Step Jailbreaks

## Input sources supported

Plain text · HTML / web pages · PDF · Email (.eml) · Word (.docx) ·
Markdown · Source code · API / JSON responses · Images (OCR via Tesseract)

## Run it

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 — toggle the firewall on/off, try the sample attacks,
and upload a file (see `samples/files/`) to watch indirect injections get caught
inside documents.

### Optional: use a real LLM (OpenAI or Azure OpenAI)

Copy `.env.example` to `.env` and set `OPENAI_API_KEY` (the provider is
auto-detected). For Azure, set `OPENAI_BASE_URL` to your `/openai/v1` endpoint
and `OPENAI_MODEL` to your deployment name. Toggle the LLM classifier with
`FIREWALL_LLM_MODE=off|gray|all`.

## Demo files (indirect injection)

`samples/files/` contains clean and poisoned documents. The poisoned ones hide
an injection where a human wouldn't look:

- `poisoned_page.html` — in an HTML comment and an image `alt` attribute
- `poisoned_email.eml` — in the email body
- `poisoned_report.pdf` / `poisoned_report.docx` — the docx hides it in a table cell

Regenerate the binaries with `python samples/files/make_binary_samples.py`.

## Evaluate detection

```powershell
python scripts/evaluate.py                        # mixed samples
python scripts/evaluate.py instruction_override   # focused per-attack report
python scripts/evaluate.py all                    # every focused report
```

### Reliability benchmark (demonstrable reliability, D2)

The benchmark is deliberately strict about what counts as success. It reports
three outcomes separately, because a *sanitized-but-forwarded* attack still
reaches the model and should not be counted as a win:

| Outcome | Meaning |
|---|---|
| **BLOCKED** | attack neutralized, nothing reached the LLM |
| **FORWARDED** | attack noticed and redacted, but still sent onward |
| **MISSED** | attack not detected at all |

```powershell
python scripts/benchmark.py                              # tuned corpus
python scripts/benchmark.py --corpus samples/holdout.json  # held-out set
python scripts/benchmark.py --llm                        # + LLM classifier
```

**Two numbers, and the second is the honest one:**

- `samples/corpus.json` (84 samples, **rules were tuned against it**):
  54/54 attacks blocked, 0 forwarded, 0 missed, 0 false alarms.
- `samples/holdout.json` (30 samples, **never tuned against**):
  7/17 blocked, 3 forwarded, 7 missed, **0 false alarms**.

> Read the holdout number, not the corpus number. The corpus result shows the
> rules cover the attack families they were written for; the holdout shows what
> happens on novel phrasings — roughly 59% noticed, 41% missed, with precision
> holding at 100% (no benign message was ever flagged in either set).
>
> That gap is the honest case for the optional LLM classifier layer
> (`FIREWALL_LLM_MODE=gray|all`), which judges *intent* rather than phrasing and
> is designed to cover exactly the paraphrases the regex layer misses.

## API

- `POST /api/scan` — `{ "content": "...", "source_type": "text" }` → verdict
- `POST /api/scan-file` — multipart file upload → verdict + extracted text
- `POST /api/chat` — `{ "message": "...", "firewall_enabled": true, "session_id": "..." }`
  → reply + firewall report (session_id enables multi-step tracking)
- `GET /api/info` — config, supported attack types, and input sources

### Optional: OCR for images

Image scanning uses Tesseract. The app runs fine without it — image scans just
return a clear "OCR unavailable" note instead of crashing.

To enable real OCR:

```powershell
pip install pytesseract Pillow
# Then install the Tesseract binary:
#   Windows: https://github.com/UB-Mannheim/tesseract/wiki
#   macOS:   brew install tesseract
#   Linux:   apt-get install tesseract-ocr
# If tesseract isn't on PATH, set OCR_TESSERACT_CMD to its full path.
```

Once installed, upload a screenshot or scanned image in the UI (or POST it to
`/api/scan-file`) and the firewall scans the recognized text like any other
source — catching instructions hidden inside images.

## Roadmap

- Larger evaluation corpus and adversarial red-team set
- Streaming / output-side filtering (scan the AI's responses too)
- Cloud OCR option (Azure Document Intelligence / AWS Textract)
