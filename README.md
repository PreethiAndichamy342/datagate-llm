# datagate-llm

[![PyPI version](https://img.shields.io/pypi/v/datagate-llm.svg)](https://pypi.org/project/datagate-llm/)
[![Python versions](https://img.shields.io/pypi/pyversions/datagate-llm.svg)](https://pypi.org/project/datagate-llm/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/datagate-llm/datagate-llm/actions/workflows/test.yml/badge.svg)](https://github.com/datagate-llm/datagate-llm/actions/workflows/test.yml)

**The inference boundary layer between your data and outbound AI requests.**

Scan text for sensitive data — PII, secrets, credentials, and sector-specific identifiers — before it leaves your system and reaches an LLM API.

---

## The Problem

In 2023, Samsung engineers accidentally leaked proprietary source code and internal meeting notes by pasting them into ChatGPT. The data was retained and potentially used for training. This is not a hypothetical risk — it is the default behavior when you send unrestricted text to an external AI model.

datagate-llm is the layer you put in front of that API call. It checks what you are about to send, tells you what it found, and lets you decide: flag it, redact it, or block it.

---

## Install

```bash
pip install datagate-llm
```

Zero dependencies. Python 3.9+. Works offline.

---

## Quickstart

```python
from datagate_llm import scan

# Basic scan
result = scan("Contact Alice at alice@company.com or call 415-555-0192")
print(result["safe"])        # False
print(result["risk_score"])  # 0.8 (or similar)
print(result["findings"])    # list of matched spans

# Redact mode — replace PII before sending to an LLM
result = scan(
    "My SSN is 123-45-6789 and card number 4111111111111111",
    mode="redact"
)
print(result["redacted_text"])
# "My SSN is [REDACTED:universal/ssn] and card number [REDACTED:universal/credit_card]"

# Block mode — hard stop on high-risk content
result = scan("AKIAIOSFODNN7EXAMPLEKEY", sectors=["technology"], mode="block")
if result["action"] == "block":
    raise ValueError("Refusing to send credentials to LLM")

# Multi-sector scan
result = scan(
    "Patient MRN: AB12345, account 123456789012",
    sectors=["healthcare", "finance"]
)
for finding in result["findings"]:
    print(finding["rule_id"], finding["severity"], finding["confidence"])
```

---

## What It Detects

| Category | Rule ID | Severity |
|----------|---------|----------|
| Email address | `universal/email` | high |
| US phone number | `universal/phone_us` | medium |
| Social Security Number | `universal/ssn` | critical |
| Credit card number | `universal/credit_card` | critical |
| IP address | `universal/ip_address` | low |
| AWS access key | `technology/aws_access_key` | critical |
| OpenAI API key | `technology/openai_key` | critical |
| Anthropic API key | `technology/anthropic_key` | critical |
| GitHub token | `technology/github_token` | critical |
| Stripe key | `technology/stripe_key` | critical |
| JWT token | `technology/jwt_token` | high |
| Private key (PEM) | `technology/private_key` | critical |
| Database connection string | `technology/connection_string` | critical |
| NPI number | `healthcare/npi_number` | high |
| ICD-10 diagnosis code | `healthcare/icd10_code` | medium |
| Insurance member ID | `healthcare/insurance_member_id` | high |
| Medical record number | `healthcare/medical_record_number` | critical |
| DEA number | `healthcare/dea_number` | critical |
| IBAN | `finance/iban` | high |
| SWIFT/BIC code | `finance/swift_bic` | medium |
| ABA routing number | `finance/routing_number` | high |
| Bank account number | `finance/bank_account` | high |
| Tax ID / EIN | `finance/tax_id_ein` | critical |
| Bitcoin address | `finance/crypto_btc` | medium |
| Ethereum address | `finance/crypto_eth` | medium |

---

## How It Works

```
text input
    │
    ▼
tokenize()          ← NFKC normalization, zero-width char removal
    │
    ▼
match()             ← regex scan against compiled rule set
    │
    ▼
score()             ← context-aware confidence (boost / suppress words)
    │
    ▼
resolve()           ← remove overlapping spans, keep highest confidence
    │
    ▼
aggregate()         ← single risk_score in [0.0, 1.0]
    │
    ▼
build_result()      ← assemble final dict with action, findings, fingerprint
```

Every step is a pure function. No network calls. No disk writes. No global state except the in-process rule cache.

---

## Scan Modes

| Mode | When risk > 0 | Use case |
|------|---------------|----------|
| `flag` (default) | `action = "flag"` | Log and review before sending |
| `redact` | `action = "flag"`, spans replaced in `redacted_text` | Strip PII, send cleaned text |
| `block` | `action = "block"` | Hard stop — raise an error upstream |

---

## Honest Limits

- **Regex-only**: datagate-llm uses deterministic pattern matching. It will not catch PII embedded in obfuscated prose, paraphrased content, or novel formats it has never seen.
- **English-centric**: Phone and ID patterns currently target US formats. International variants may be missed.
- **No semantic understanding**: "The patient's temperature was 98.6" will not be flagged as health data because there is no pattern for it. Semantic scanning requires the optional `onnxruntime` layer (not yet released).
- **False positives are possible**: Short patterns like SWIFT codes can match arbitrary uppercase strings. Use `context.suppress` words in your rule JSON to reduce noise.
- **Not a compliance tool**: Passing a scan does not mean a document is HIPAA, GDPR, or PCI-DSS compliant. Use this as one layer of defense, not the only one.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: add rules in JSON, add tests, open a PR.

---

## License

MIT. See [LICENSE](LICENSE).
