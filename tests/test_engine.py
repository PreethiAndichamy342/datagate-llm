"""Tests for pure engine functions."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import re
from datagate_llm.engine import (
    tokenize,
    match,
    score,
    resolve,
    aggregate,
    build_result,
)

_EMAIL_RULE = {
    "id": "universal/email",
    "sector": "universal",
    "severity": "high",
    "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "compiled": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "context": {"boost": ["email", "contact"], "suppress": ["example", "test"]},
}


def test_tokenize_removes_zero_width():
    dirty = "hel\u200blo"
    assert "\u200b" not in tokenize(dirty)
    assert "hello" in tokenize(dirty)


def test_match_finds_email():
    spans = match("Contact: user@example.com today", [_EMAIL_RULE])
    assert len(spans) == 1
    assert spans[0]["text"] == "user@example.com"


def test_score_boosts_with_context():
    span_no_ctx = {
        "start": 9, "end": 25, "text": "x",
        "severity": "high", "context": {},
    }
    span_boost = {
        "start": 11, "end": 27, "text": "x",
        "severity": "high",
        "context": {"boost": ["email"], "suppress": []},
    }
    base = score(span_no_ctx, "no context here user@example.com")
    boosted = score(span_boost, "send email user@example.com to team")
    assert boosted > base


def test_resolve_removes_overlap():
    spans = [
        {"start": 0, "end": 10, "rule_id": "a", "confidence": 0.8},
        {"start": 5, "end": 15, "rule_id": "b", "confidence": 0.6},
    ]
    result = resolve(spans)
    assert len(result) == 1
    assert result[0]["rule_id"] == "a"


def test_aggregate_empty_returns_zero():
    assert aggregate([]) == 0.0


def test_aggregate_caps_at_one():
    spans = [{"confidence": 1.0}] * 100
    assert aggregate(spans) <= 1.0


def test_build_result_redact_mode():
    spans = [{"start": 0, "end": 4, "rule_id": "x/id", "confidence": 0.8, "severity": "high"}]
    r = build_result("test text", spans, 0.8, "redact", "v1")
    assert "[REDACTED:x/id]" in r["redacted_text"]
    assert r["action"] == "allow"


def test_fingerprint_is_deterministic():
    r1 = build_result("hello", [], 0.0, "flag", "v1")
    r2 = build_result("hello", [], 0.0, "flag", "v1")
    assert r1["fingerprint"] == r2["fingerprint"]
    assert len(r1["fingerprint"]) == 16
