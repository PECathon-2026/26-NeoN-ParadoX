"""Run the four brief scenarios and print reproducible privacy metrics."""
from privacylens import analyze, validate_outgoing

SCENARIOS = {
    "e-commerce checkout": "Name Maya Shah; card 4111 1111 1111 1111; address 12 MG Road",
    "authentication": "Email maya@example.com; password=hunter2; OTP: 482901",
    "customer support": "Call +919876543210 about private medical message",
    "developer settings": "API key sk-abcdefghijklmnopqrstuvwxyz and server 10.20.30.40",
}

def main():
    total = detected = leaked = 0
    for name, text in SCENARIOS.items():
        result = analyze(text)
        count = len(result["findings"]); detected += count; total += count
        leaked += 0 if validate_outgoing(text)["allowed"] else 1
        print(f"{name}: detected={count}, outgoing={'ALLOWED' if result['outgoing_check']['allowed'] else 'BLOCKED'}")
        print(f"  sanitized: {result['sanitized']}")
    print(f"\nScenarios: {len(SCENARIOS)} | Sensitive items detected: {detected} | Unsafe payloads blocked: {leaked}/{len(SCENARIOS)}")

if __name__ == "__main__": main()
