"""Produce hackathon-ready evaluation metrics in Markdown and CSV."""
from __future__ import annotations
import csv
from pathlib import Path
from privacylens import analyze, validate_outgoing

CASES = [
    ("E-commerce checkout", "Card 4111 1111 1111 1111; shipping address: 12 MG Road", {"CARD", "ADDRESS"}),
    ("Authentication", "Email maya@example.com; password=hunter2; OTP: 482901", {"EMAIL", "PASSWORD", "OTP"}),
    ("Customer support", "Call +919876543210 about private medical message", {"PHONE"}),
    ("Video conferencing", "Participant email host@example.com at 19.0760, 72.8777", {"EMAIL", "GPS_COORDINATES"}),
    ("Developer settings", "API key AKIA1234567890ABCDEF and server 10.20.30.40", {"API_KEY", "IP_ADDRESS"}),
]

def main():
    rows = []
    for name, text, expected in CASES:
        result = analyze(text)
        found = {item["kind"] for item in result["findings"]}
        rows.append({"scenario": name, "expected": len(expected), "detected": len(found & expected),
                     "precision": round(len(found & expected) / len(found), 3) if found else 1.0,
                     "recall": round(len(found & expected) / len(expected), 3),
                     "sanitized_allowed": result["outgoing_check"]["allowed"],
                     "raw_blocked": not validate_outgoing(text)["allowed"]})
    out = Path(__file__).parent / "submission"
    out.mkdir(exist_ok=True)
    with (out / "evaluation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    recall = sum(r["recall"] for r in rows) / len(rows)
    precision = sum(r["precision"] for r in rows) / len(rows)
    blocked = sum(r["raw_blocked"] for r in rows)
    report = "# PrivacyLens evaluation\n\n| Scenario | Expected | Detected | Precision | Recall | Sanitized allowed | Raw blocked |\n|---|---:|---:|---:|---:|---:|---:|\n"
    report += "\n".join(f"| {r['scenario']} | {r['expected']} | {r['detected']} | {r['precision']:.0%} | {r['recall']:.0%} | {'Yes' if r['sanitized_allowed'] else 'No'} | {'Yes' if r['raw_blocked'] else 'No'} |" for r in rows)
    report += f"\n\n**Average precision:** {precision:.0%}  \n**Average recall:** {recall:.0%}  \n**Raw payloads blocked:** {blocked}/{len(rows)}\n\nThese are deterministic local-rule results on the included synthetic cases, not a claim of universal real-world accuracy."
    (out / "evaluation.md").write_text(report, encoding="utf-8")
    print(report)

if __name__ == "__main__": main()
