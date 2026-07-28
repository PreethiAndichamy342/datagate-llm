# Changelog

All notable changes to datagate-llm are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- add_rule() — register custom patterns at runtime
- clear_rules() — clear runtime rules and cache
- custom_rules param in scan() for file-based rules
- detect_hardcoded() — entropy, token anomaly,
  structural pattern detection without rules
- scan_hardcoded param in scan() (default True)
- protect() — auto-scan all LLM client calls
- unprotect() — restore original client method
- gate() — decorator for function-level protection
- Supports openai and anthropic clients
- flag, redact, block modes throughout
- All files under 100 lines

## [0.1.0] - 2026-06-04

### Added

- Layer 1 deterministic scanning engine
- Universal rules: email, phone (US), SSN, credit card, IP address
- Technology rules: AWS access keys, OpenAI keys, Anthropic keys,
  GitHub tokens, Stripe keys, JWT tokens, private keys, connection strings
- Healthcare rules: NPI numbers, ICD-10 codes, insurance member IDs,
  medical record numbers, DEA numbers
- Finance rules: IBAN, SWIFT/BIC, routing numbers, bank account numbers,
  tax ID / EIN, Bitcoin addresses, Ethereum addresses
- Three scan modes: flag, redact, block
- Context-aware scoring with boost and suppress word lists
- Deterministic fingerprinting via SHA-256
- Full decision trace on every scan result
- In-process rule cache keyed by (sectors, rules_dir)
- Zero external dependencies for core engine
- Optional onnxruntime extra for future semantic layer
