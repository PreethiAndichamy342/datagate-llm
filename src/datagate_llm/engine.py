"""
Pure-function detection engine. No side effects. No I/O. stdlib only.
"""

import hashlib
import re
import unicodedata
from math import log1p

_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff\u00ad]")

_SEVERITY_BASE = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
}
_WINDOW = 30
_BOOST = 0.15
_SUPPRESS = 0.25
_LOG_SCALE = 0.05


def tokenize(text):
    """Normalise *text* to NFKC and strip zero-width characters."""
    normalised = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH.sub("", normalised)


def match(text, rules):
    """Return every span matched by *rules* against *text*."""
    spans = []
    for rule in rules:
        compiled = rule.get("compiled")
        if compiled is None:
            continue
        for m in compiled.finditer(text):
            spans.append({
                "start": m.start(),
                "end": m.end(),
                "text": m.group(),
                "rule_id": rule["id"],
                "sector": rule.get("sector", "universal"),
                "severity": rule.get("severity", "medium"),
                "context": rule.get("context", {}),
            })
    return spans


def score(span, text):
    """Return a confidence float in [0.0, 1.0] for *span* inside *text*."""
    base = _SEVERITY_BASE.get(span.get("severity", "medium"), 0.5)
    start = max(0, span["start"] - _WINDOW)
    end = min(len(text), span["end"] + _WINDOW)
    window = text[start:end].lower()

    ctx = span.get("context", {})
    boost_words = ctx.get("boost", [])
    suppress_words = ctx.get("suppress", [])

    if any(w in window for w in boost_words):
        base = min(1.0, base + _BOOST)
    if any(w in window for w in suppress_words):
        base = max(0.0, base - _SUPPRESS)
    return round(base, 4)


def resolve(spans):
    """Remove overlapping spans, keeping highest-confidence ones."""
    sorted_spans = sorted(
        spans,
        key=lambda s: (s["start"], -s.get("confidence", 0), s["rule_id"])
    )
    result = []
    last_end = -1
    for span in sorted_spans:
        if span["start"] >= last_end:
            result.append(span)
            last_end = span["end"]
    return result


def aggregate(spans):
    """Compute aggregate risk in [0.0, 1.0] from resolved *spans*."""
    if not spans:
        return 0.0
    max_score = max(s.get("confidence", 0.0) for s in spans)
    raw = max_score * (1 + _LOG_SCALE * log1p(len(spans)))
    return round(min(1.0, raw), 4)


def build_result(text, spans, risk, mode, rule_version):
    """Assemble the final result dict. Never raises."""
    findings = [
        {k: v for k, v in s.items() if k not in ("compiled", "context")}
        for s in spans
    ]

    redacted = text
    if mode == "redact":
        for span in reversed(spans):
            placeholder = f"[REDACTED:{span['rule_id']}]"
            redacted = redacted[: span["start"]] + placeholder + redacted[span["end"]:]

    action = _resolve_action(risk, mode)
    fp_raw = hashlib.sha256(f"{text}{rule_version}".encode()).hexdigest()

    return {
        "safe": risk == 0.0,
        "risk_score": risk,
        "action": action,
        "findings": findings,
        "redacted_text": redacted,
        "fingerprint": fp_raw[:16],
        "rule_version": rule_version,
        "trace": [],
    }


def _resolve_action(risk, mode):
    if risk == 0.0:
        return "allow"
    if mode == "block":
        return "block"
    if mode == "flag":
        return "flag"
    return "allow"
