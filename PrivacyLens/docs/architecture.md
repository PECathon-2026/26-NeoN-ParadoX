# PrivacyLens architecture and data flow

```text
Browser page / screenshot
          |
          v
Local extractor (DOM text or optional OCR)
          |
          v
Local detector -----> findings + confidence
          |
          v
Sanitizer ----------> typed placeholders, useful context retained
          |
          v
AI planner receives sanitized context only
          |
          v
Action guard: allowlist + prompt-injection check + secret scan
          |
       +--+----------------+
       |                   |
   ALLOW low-risk     APPROVAL_REQUIRED / BLOCK
```

Privacy boundaries:

- Raw input is processed in the local process and is never sent to a model by this demo.
- Sanitized text is the only model-facing representation.
- Every proposed action is checked before execution.
- The demo binds only to `127.0.0.1` and does not write sensitive logs.

Production extension points are the DOM/screenshot adapter, a local LLM adapter, and a browser executor. The safety boundary stays between planning and execution.
