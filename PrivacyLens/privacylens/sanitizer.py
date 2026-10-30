"""Detect, redact, and validate sensitive information without network calls."""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Iterable

@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value_preview: str
    confidence: float
    def to_dict(self) -> dict:
        return asdict(self)

PATTERNS = (
    # Contact and identity
    ("EMAIL", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", .99),
    ("PHONE", r"(?<!\d)(?:\+?91[-. ]?)?[6-9]\d{4}[-. ]?\d{5}(?!\d)", .93),
    # Indian identity and government identifiers. These are intentionally
    # pattern-based: PrivacyLens flags a possible identifier locally and does
    # not attempt to verify it against a registry or checksum service.
    # A bare 12-digit run is deliberately not enough: it collides with
    # mobile numbers prefixed by +91 and ordinary order/reference numbers.
    # Unlabelled Aadhaar is accepted only in its common grouped form.
    ("AADHAAR", r"(?i)(?<!\d)(?:aadhaar|aadhar)\s*(?:number|no|id)?\s*[:#=-]?\s*\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)|(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)", .97),
    ("PAN", r"(?i)\b(?:pan(?: card)?(?: number| no| id)?\s*[:#=-]?\s*)?[A-Z]{5}\d{4}[A-Z]\b", .98),
    ("PASSPORT", r"(?i)\bpassport(?:\s+(?:number|no|id))?\s*[:#=-]?\s*[A-Z]{1,2}[0-9]{6,8}\b", .96),
    ("DRIVER_LICENSE", r"(?i)\b(?:driver'?s? license|driving license|driving licence|dl)\s*(?:number|no|id)?\s*[:#=-]?\s*[A-Z]{1,3}[- ]?\d{4,16}\b", .93),
    ("VOTER_ID", r"(?i)\b(?:voter(?:\s+id|\s+card)?|epic(?:\s+number|\s+id)?)\s*[:#=-]?\s*[A-Z]{2,3}\d{7,10}\b|\b[A-Z]{3}\d{7}\b", .93),
    ("RATION_CARD", r"(?i)\b(?:ration card|ration card number|food security card)\s*[:#=-]?\s*[A-Z0-9/-]{6,20}\b", .91),
    ("NREGA_ID", r"(?i)\b(?:nrega|mgnrega)(?: job)?\s*(?:card|id|number|no)?\s*[:#=-]?\s*[A-Z0-9/-]{8,25}\b", .90),
    ("VEHICLE_REGISTRATION", r"(?i)\b(?:vehicle|registration|car|bike|scooter)\s*(?:no|number|registration)?\s*[:#=-]?\s*[A-Z]{2}[- ]?\d{1,2}[- ]?[A-Z]{1,3}[- ]?\d{1,4}\b", .91),
    ("CIN", r"(?i)\b(?:cin|corporate identity number)\s*[:#=-]?\s*[A-Z]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b", .96),
    ("TAN", r"(?i)\b(?:tan|tax deduction account(?: number)?)\s*[:#=-]?\s*[A-Z]{4}\d{5}[A-Z]\b", .95),
    ("SSN", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", .98),
    ("DATE_OF_BIRTH", r"(?i)\b(?:date of birth|dob|birth date)\s*[:=-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", .95),
    ("CARD", r"(?i)\b(?:card|credit card|debit card|card number)\s*[:#=-]?\s*(?:\d[ -]?){13,19}\b|(?<!\d)(?:\d[ -]?){13,19}(?!\d)", .90),
    # Financial and payment data
    ("BANK_ACCOUNT", r"(?i)\b(?:bank account|account number|a/c no)\s*[:#=-]?\s*\d{9,18}\b", .94),
    ("IFSC", r"(?i)\b(?:ifsc(?: code)?)?\s*[:#=-]?\s*[A-Z]{4}0[A-Z0-9]{6}\b", .97),
    ("MICR", r"(?i)\b(?:micr(?: code)?)\s*[:#=-]?\s*\d{9}\b", .94),
    ("UAN", r"(?i)\b(?:uan|universal account number)\s*[:#=-]?\s*\d{12}\b", .95),
    ("PF_ACCOUNT", r"(?i)\b(?:pf|epf|provident fund)\s*(?:account|number|no|id)?\s*[:#=-]?\s*[A-Z]{2}/[A-Z]{2,5}/\d{4,10}/\d{1,7}\b", .92),
    ("ESIC", r"(?i)\b(?:esic|esi)(?: number| no| id)?\s*[:#=-]?\s*\d{10}\b", .93),
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", .97),
    ("SWIFT", r"(?i)\b(?:swift|bic)(?: code)?\s*[:#=-]?\s*[A-Z]{6}[A-Z0-9]{2,5}\b", .95),
    ("UPI_ID", r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b", .91),
    ("GSTIN", r"(?i)\b(?:gstin|gst(?:\s+number|\s+no|\s+id))?\s*[:#=-]?\s*\d{2}[A-Z]{5}\d{4}[A-Z]\d[Zz][A-Z0-9]\b", .98),
    # Authentication and software secrets
    # Verification codes are commonly numeric, but can also be longer or
    # alphanumeric. A label is required to avoid flagging ordinary numbers.
    ("OTP", r"(?i)\b(?:otp|one[- ]time password|verification code|security code|passcode)\s*(?::|=|#|\bis\b|-)\s*[A-Z0-9](?:[A-Z0-9 -]{2,15}[A-Z0-9])?\b", .96),
    ("PASSWORD", r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=-]\s*[^\s,;]+", .95),
    ("AUTH_TOKEN", r"(?i)\b(?:bearer|access token|refresh token|auth token|session token)\s*[:=-]\s*[A-Za-z0-9._~+/=-]{12,}", .97),
    ("API_KEY", r"\b(?:sk-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b", .98),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", .99),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", .99),
    # Location, health, and device identifiers
    ("ADDRESS", r"(?i)\b(?:home|residential|shipping|billing|street)\s+address\s*[:=-]\s*[^\n,;]+", .89),
    ("MEDICAL_RECORD", r"(?i)\b(?:medical|patient|health|hospital)\s*(?:record|file|id|number)\s*[:#=-]?\s*[A-Z0-9-]{4,20}\b", .92),
    ("INSURANCE_ID", r"(?i)\b(?:insurance|policy)\s*(?:id|number|no)\s*[:#=-]?\s*[A-Z0-9-]{5,25}\b", .92),
    ("GPS_COORDINATES", r"(?<!\d)-?\d{1,3}\.\d{3,}\s*,\s*-?\d{1,3}\.\d{3,}(?!\d)", .86),
    ("MAC_ADDRESS", r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", .96),
    # A raw UUID can be a harmless page/session identifier. Require a nearby
    # label so random UI IDs are not presented as a phone-related finding.
    ("UUID", r"(?i)\b(?:uuid|unique id|identifier)\s*[:#=-]?\s*[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", .86),
    ("IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", .82),
)

def detect(text: str) -> list[Finding]:
    found = []
    for kind, pattern, confidence in PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            found.append(Finding(kind, match.start(), match.end(), value[:3] + "***", confidence))
    found.sort(key=lambda x: (x.start, -(x.end - x.start)))
    chosen = []
    for item in found:
        if not chosen or item.start >= chosen[-1].end: chosen.append(item)
    return chosen

def sanitize(text: str, findings: Iterable[Finding] | None = None) -> str:
    items = list(findings if findings is not None else detect(text))
    for item in reversed(items):
        text = text[:item.start] + f"[REDACTED:{item.kind}]" + text[item.end:]
    return text

def validate_outgoing(text: str) -> dict:
    findings = detect(text)
    return {"allowed": not findings, "findings": [x.to_dict() for x in findings],
            "reason": "No sensitive values detected." if not findings else "Blocked: sensitive data detected before transmission."}

def analyze(text: str) -> dict:
    findings = detect(text)
    safe = sanitize(text, findings)
    return {"findings": [x.to_dict() for x in findings], "sanitized": safe,
            "outgoing_check": validate_outgoing(safe), "local_only": True}
