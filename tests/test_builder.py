"""Tests for build_rule() and add_pattern()."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from datagate_llm.builder import build_rule, _TEMPLATES
from datagate_llm import add_pattern, clear_rules, scan


def teardown_function():
    clear_rules()


# --- build_rule: pattern correctness ---

def test_prefix_digits():
    r = build_rule("patient_id", "prefix_digits", "high", prefix="PT", n=8)
    assert r["pattern"] == r"PT\d{8}"


def test_prefix_dash_digits():
    r = build_rule("order", "prefix_dash_digits", "medium", prefix="ORD", n=6)
    assert r["pattern"] == r"ORD-\d{6}"


def test_prefix_dash_alphanum():
    r = build_rule("internal", "prefix_dash_alphanum", "high", prefix="INT", n=6)
    assert r["pattern"] == r"INT-[A-Z0-9]{6}"


def test_digits_only():
    r = build_rule("pin", "digits_only", "low", n=4)
    assert r["pattern"] == r"\d{4}"


def test_alphanum_fixed():
    r = build_rule("code", "alphanum_fixed", "low", n=9)
    assert r["pattern"] == r"[A-Z0-9]{9}"


def test_key_value():
    r = build_rule("mykey", "key_value", "critical", prefix="MYKEY", n=1)
    assert r["pattern"] == r"MYKEY=\S{1,}"


# --- build_rule: metadata ---

def test_rule_id_format():
    r = build_rule("emp", "prefix_digits", "high", prefix="EMP", n=5)
    assert r["id"] == "custom/emp"


def test_rule_sector_default():
    r = build_rule("emp", "prefix_digits", "high", prefix="EMP", n=5)
    assert r["sector"] == "custom"


def test_rule_sector_custom():
    r = build_rule("emp", "prefix_digits", "high", prefix="EMP", n=5, sector="hr")
    assert r["sector"] == "hr"


def test_boost_suppress_passthrough():
    r = build_rule("emp", "prefix_digits", "high",
                   prefix="EMP", n=5,
                   boost=["employee"], suppress=["example"])
    assert r["context"]["boost"] == ["employee"]
    assert r["context"]["suppress"] == ["example"]


# --- build_rule: validation errors ---

def test_unknown_template_raises():
    with pytest.raises(ValueError, match="Unknown template"):
        build_rule("x", "nonexistent", "high")


def test_invalid_severity_raises():
    with pytest.raises(ValueError, match="Invalid severity"):
        build_rule("x", "prefix_digits", "extreme", prefix="X", n=4)


# --- add_pattern: scan integration ---

def test_add_pattern_detected_in_scan():
    add_pattern("patient_id", "prefix_digits", "high", prefix="PT", n=8)
    result = scan("Patient: PT12345678 admitted")
    ids = [f["rule_id"] for f in result["findings"]]
    assert "custom/patient_id" in ids


def test_add_pattern_does_not_match_wrong_format():
    add_pattern("order", "prefix_dash_digits", "medium", prefix="ORD", n=6)
    result = scan("reference ORD12345")
    ids = [f["rule_id"] for f in result["findings"]]
    assert "custom/order" not in ids
