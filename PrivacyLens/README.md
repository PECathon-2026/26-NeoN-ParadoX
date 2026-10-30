# PrivacyLens

PrivacyLens is a local privacy firewall for AI browser agents. It detects sensitive information in webpage/task context, sanitizes it while preserving interface meaning, and validates payloads before they leave the local boundary.

## Run the demo

Requires Python 3.10+ and no external packages:

```powershell
cd C:\Users\samar\Documents\PrivacyLens
python app.py
```

Open http://127.0.0.1:8765 for the privacy dashboard, or http://127.0.0.1:8765/agent.html for the end-to-end agent flow.

## Use the Chrome extension

PrivacyLens also includes a Manifest V3 browser extension in `extension/`.

1. Start the local server with `python app.py`.
2. Open `chrome://extensions` in Chrome and enable **Developer mode**.
3. Choose **Load unpacked** and select `C:\Users\samar\Documents\PrivacyLens\extension`.
4. Pin **PrivacyLens Local Guard**, open a webpage, and click **Scan active page**.
5. Review the detected patterns, sanitized context, and the action-safety decision.

The extension sends page text only to the local server at `127.0.0.1:8765`; it has no cloud model dependency.

Run tests with `python -m unittest discover -s tests -v` and evaluation scenarios with `python evaluate.py`.

## How it maps to the brief

- Detection: local pattern matching for major Indian identifiers including Aadhaar, PAN, passport, EPIC voter ID, driving licence, ration card, NREGA, vehicle registration, GSTIN, CIN, TAN, UAN, PF, ESIC, plus email, phone, cards, bank details, OTPs, passwords, API keys, and IP addresses. Patterns are flagged without registry lookups or checksum verification.
- Sanitization: values become typed placeholders such as `[REDACTED:CARD]`; useful context is preserved.
- AI boundary: only sanitized context is presented as the model-facing payload.
- Validation: outgoing payloads are scanned again and blocked if raw sensitive data remains.
- Security: fail-closed behavior, no network calls, no secret logging, and local-only binding to `127.0.0.1`.
- Evaluation: tests cover detection, redaction, preservation, and leakage blocking.
- Screenshot path: `privacylens/ocr.py` provides local OCR when Pillow and pytesseract are installed; the safety boundary is unchanged.
- Action safety: `privacylens/action_guard.py` allowlists actions, blocks prompt injection and secret-bearing values, and requires approval for payment/destructive actions.

## Demo script

1. Use the prefilled checkout example.
2. Show card, email, OTP, and IP detection.
3. Show typed placeholders in the sanitized context.
4. Validate the safe payload.
5. Replace it with a raw password and show that it is blocked.

## Hackathon package

The package includes the working dashboard, end-to-end agent guard, Chrome extension wrapper, architecture diagram, demo script, deterministic evaluation, and tests. See `submission/` and `extension/README.md` for the handoff materials.
