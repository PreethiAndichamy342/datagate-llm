"""Tests for the rule loader."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import datagate_llm.loader as loader_mod

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
