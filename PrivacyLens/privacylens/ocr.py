"""Optional local OCR adapter for screenshot-based interfaces.

The core product never uploads images. If Pillow and pytesseract are installed,
OCR runs locally; otherwise the demo reports the optional dependency clearly.
"""
from __future__ import annotations

def extract_local_text(image_path: str) -> dict:
    try:
        from PIL import Image
        import pytesseract
    except ImportError:
        return {"available": False, "text": "", "message": "Install Pillow and pytesseract for local screenshot OCR."}
    text = pytesseract.image_to_string(Image.open(image_path))
    return {"available": True, "text": text, "message": "OCR completed locally; no image was transmitted."}
