"""Tests for the rule loader."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import json
import re
import tempfile
import pytest
import datagate_llm.loader as loader_mod
from datagate_llm import scan, add_rule, clear_rules

_RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "src", "datagate_llm", "rules"
)


def _fresh_load(sectors):
    loader_mod._cache.clear()
    return loader_mod.load_rules(sectors, _RULES_DIR)


def test_load_universal_always_included():
    rules = _fresh_load([])
    ids = [r["id"] for r in rules]
    assert any(i.startswith("universal/") for i in ids)


def test_load_missing_sector_safe():
    rules = _fresh_load(["nonexistent_sector"])
    assert isinstance(rules, list)


def test_cache_hit_on_second_call():
    _fresh_load(["technology"])
    key = (("technology",), _RULES_DIR)
    assert key in loader_mod._cache
    first = loader_mod._cache[key]
    loader_mod.load_rules(["technology"], _RULES_DIR)
    assert loader_mod._cache[key] is first


def test_compile_adds_compiled_key():
    rules = _fresh_load([])
    assert all("compiled" in r for r in rules)


def test_critical_rules_sorted_first():
    rules = _fresh_load(["technology"])
    severities = [r.get("severity") for r in rules]
    first_critical = next((i for i, s in enumerate(severities) if s == "critical"), None)
    first_medium = next((i for i, s in enumerate(severities) if s == "medium"), None)
    if first_critical is not None and first_medium is not None:
        assert first_critical < first_medium


# ── runtime-rule tests ────────────────────────────────────────────────────────

@pytest.fixture
def _cleanup_runtime():
    yield
    clear_rules()


def test_add_rule_detected_in_scan(_cleanup_runtime):
    add_rule("custom/emp_id", r"EMP-\d{6}", "high", "custom")
    result = scan("Employee EMP-123456 accessed system", sectors=["custom"])
    assert not result["safe"]
    assert any(f["rule_id"] == "custom/emp_id" for f in result["findings"])


def test_add_rule_duplicate_raises(_cleanup_runtime):
    add_rule("custom/dup_test", r"DUP-\d+", "low")
    with pytest.raises(ValueError, match="already registered"):
        add_rule("custom/dup_test", r"DUP-\d+", "low")


def test_add_rule_invalid_severity_raises():
    with pytest.raises(ValueError, match="severity"):
        add_rule("custom/bad_sev", r"BAD-\d+", "extreme")


def test_add_rule_invalid_regex_raises():
    with pytest.raises(re.error):
        add_rule("custom/bad_regex", r"[invalid", "low")


def test_clear_rules_removes_registered():
    add_rule("custom/temp_rule", r"TEMP-\d{4}", "medium")
    clear_rules()
    result = scan("value TEMP-1234 found")
    assert not any(f["rule_id"] == "custom/temp_rule" for f in result["findings"])


def test_custom_rules_file_loaded():
    rules = [{
        "id": "custom/order_id",
        "pattern": r"ORD-\d{4}-\d{6}",
        "severity": "medium",
        "context": {"boost": ["order"], "suppress": []},
    }]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(rules, f)
        path = f.name
    try:
        result = scan("order ORD-2024-001234 placed", custom_rules=path)
        assert not result["safe"]
        assert any(f["rule_id"] == "custom/order_id" for f in result["findings"])
    finally:
        os.unlink(path)


def test_custom_rules_file_missing_silent():
    result = scan("hello world", custom_rules="./nonexistent_file.json")
    assert result["safe"]
