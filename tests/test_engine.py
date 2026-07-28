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


from datagate_llm.engine import _entropy, _token_anomaly, detect_hardcoded


def test_entropy_empty():
    assert _entropy("") == 0.0


def test_entropy_high_random():
    assert _entropy("xK9#mP2$vL8nQ5rT!") > 4.0


def test_entropy_low_natural():
    assert _entropy("hello world") < 4.0


def test_token_anomaly_camelcase():
    assert _token_anomaly("mySecretPassword") > 0.3


def test_token_anomaly_key_value():
    assert _token_anomaly("DATABASE_URL=postgres") > 0.5


def test_token_anomaly_clean():
    assert _token_anomaly("hello") < 0.3


def test_detect_uuid():
    r = detect_hardcoded(
        "session 3f2a9c1b-4d5e-4f6a-8b9c-1d2e3f4a5b6c"
    )
    assert len(r) > 0
    assert r[0]["rule_id"] == "hardcoded/detected"


def test_detect_prefix_num():
    r = detect_hardcoded("user EMP-123456 logged in")
    assert len(r) > 0


def test_detect_key_value():
    r = detect_hardcoded(
        "DATABASE_URL=postgres://user:pass@host/db"
    )
    assert len(r) > 0


def test_detect_clean_sentence():
    r = detect_hardcoded(
        "the quick brown fox jumps over the lazy dog"
    )
    assert r == []


def test_detect_long_hex():
    r = detect_hardcoded(
        "hash 8f14e45fceea167a5a36dedd4bea2543"
    )
    assert len(r) > 0
