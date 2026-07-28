"""
datagate-llm: The inference boundary layer between your data and outbound AI requests.

Public API
----------
scan(text, sectors=None, mode="flag", rules_dir=_RULES_DIR) -> dict

Args:
    text (str): Input text to analyse.
    sectors (list[str] | None): Domain rule sets to load in addition to
        universal rules. Supported: "technology", "healthcare", "finance".
    mode (str): One of "flag", "redact", or "block".
    rules_dir (str): Path to directory containing JSON rule files.

Returns a dict with keys:
    safe (bool)          - True when risk_score == 0.0
    risk_score (float)   - 0.0-1.0 aggregate risk
    action (str)         - "allow", "flag", or "block"
    findings (list)      - matched spans with metadata
    redacted_text (str)  - text with spans replaced (mode=redact)
    fingerprint (str)    - first 16 hex chars of sha256(text+rule_version)
    rule_version (str)   - hash of loaded rule set for audit
    trace (list[str])    - human-readable decision log
"""

from __future__ import annotations

import os

from .engine import (
    tokenize, match, score,
    resolve, aggregate, build_result,
    detect_hardcoded,
)
from .loader import load_rules, add_rule, clear_rules
from .builder import build_rule, add_pattern

__version__ = "0.1.0"
__all__ = [
    "scan", "add_rule", "clear_rules",
    "detect_hardcoded", "protect", "unprotect", "gate",
    "build_rule", "add_pattern",
]

_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def scan(
    text: str,
    sectors: list | None = None,
    mode: str = "flag",
    rules_dir: str = _RULES_DIR,
    custom_rules: str | None = None,
    scan_hardcoded: bool = True,
) -> dict:
    """Run the full detection pipeline on *text*."""
    sectors = sectors or []
    trace = []

    rules = load_rules(sectors, rules_dir, custom_rules)
    trace.append(f"loaded {len(rules)} rules for sectors={['universal'] + sectors}")

    cleaned = tokenize(text)
    trace.append("tokenized input")

    rule_spans = match(cleaned, rules)
    if scan_hardcoded:
        rule_spans = rule_spans + detect_hardcoded(cleaned)
    trace.append(f"matched {len(rule_spans)} raw spans")

    scored = [{**s, "confidence": score(s, cleaned)} for s in rule_spans]
    clean_spans = resolve(scored)
    trace.append(f"resolved to {len(clean_spans)} non-overlapping spans")

    risk = aggregate(clean_spans)
    trace.append(f"risk_score={risk:.3f}")

    rule_version = rules[0].get("rule_version", "unknown") if rules else "unknown"
    result = build_result(cleaned, clean_spans, risk, mode, rule_version)
    result["trace"] = trace
    return result


from .protector import protect, unprotect  # noqa: E402
from .gate import gate  # noqa: E402
