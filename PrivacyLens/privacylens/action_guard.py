"""Fail-closed validation for AI-proposed interface actions."""
from __future__ import annotations
import re
from .sanitizer import detect

ALLOWED_ACTIONS = {"click", "type", "navigate", "scroll", "submit"}
HIGH_RISK_WORDS = {"pay", "purchase", "transfer", "delete", "send", "submit", "confirm", "publish"}
INJECTION_PATTERNS = (r"ignore previous instructions", r"reveal (the )?password", r"disable security", r"bypass privacy")

def validate_action(action: dict, context: str = "") -> dict:
    name = str(action.get("type", "")).lower().strip()
    target = str(action.get("target", "")).strip()
    value = str(action.get("value", ""))
    reasons = []
    if name not in ALLOWED_ACTIONS: reasons.append("Action type is not allowlisted.")
    if not target: reasons.append("Action target is missing.")
    if any(re.search(pattern, context, re.I) for pattern in INJECTION_PATTERNS):
        reasons.append("Prompt-injection pattern detected in interface context.")
    payload_check = detect(value)
    if payload_check: reasons.append("Action value contains sensitive information.")
    risky = any(word in f"{name} {target}".lower() for word in HIGH_RISK_WORDS)
    if risky: reasons.append("Human approval required for a sensitive or irreversible action.")
    blocked = any("allowlisted" in r or "missing" in r or "injection" in r or "contains sensitive" in r for r in reasons)
    return {"allowed": not blocked and not risky, "requires_approval": risky and not blocked,
            "action": action, "reasons": reasons or ["Action is valid and low risk."],
            "decision": "BLOCK" if blocked else ("APPROVAL_REQUIRED" if risky else "ALLOW")}

def plan_action(task: str, context: str, action: dict) -> dict:
    safe_context = context
    return {"task": task, "context_was_sanitized": not bool(detect(context)),
            "validation": validate_action(action, safe_context)}
