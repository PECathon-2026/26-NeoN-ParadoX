# PrivacyLens evaluation

| Scenario | Expected | Detected | Precision | Recall | Sanitized allowed | Raw blocked |
|---|---:|---:|---:|---:|---:|---:|
| E-commerce checkout | 2 | 2 | 100% | 100% | Yes | Yes |
| Authentication | 3 | 3 | 100% | 100% | Yes | Yes |
| Customer support | 1 | 1 | 100% | 100% | Yes | Yes |
| Video conferencing | 2 | 2 | 100% | 100% | Yes | Yes |
| Developer settings | 2 | 2 | 100% | 100% | Yes | Yes |

**Average precision:** 100%  
**Average recall:** 100%  
**Raw payloads blocked:** 5/5

These are deterministic local-rule results on the included synthetic cases, not a claim of universal real-world accuracy.