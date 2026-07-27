"""
Rule loader with in-process cache. stdlib only.
"""

import json
import os
import re
import sys

_cache = {}
_RUNTIME_RULES: list = []

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_rules(
    sectors: list,
    rules_dir: str,
    custom_rules: str | None = None
) -> list:
    """Return compiled rules for *sectors* (universal always included)."""
    key = (tuple(sorted(sectors)), rules_dir) + ((custom_rules,) if custom_rules is not None else ())
    if key in _cache:
        return _cache[key] + _RUNTIME_RULES

    raw = _read(os.path.join(rules_dir, "universal.json"))
    for sector in sectors:
        path = os.path.join(rules_dir, f"{sector}.json")
        raw.extend(_read(path))

    if custom_rules is not None:
        if os.path.isfile(custom_rules):
            raw += _read(custom_rules)
        else:
            print(f"Warning: custom_rules file not found: {custom_rules}", file=sys.stderr)

    compiled = _compile(raw)
    _cache[key] = compiled
    return compiled + _RUNTIME_RULES


def add_rule(
    id: str,
    pattern: str,
    severity: str,
    sector: str = "custom",
    context: dict | None = None
) -> None:
    """
    Register a custom rule at runtime.

    Args:
        id:       unique rule id e.g. "custom/employee_id"
        pattern:  raw regex string
        severity: "low" | "medium" | "high" | "critical"
        sector:   defaults to "custom"
        context:  optional boost/suppress dict

    Raises:
        ValueError: if id duplicate, severity invalid
        re.error:   if pattern is invalid regex
    """
    _VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")
    re.compile(pattern)  # raises re.error if invalid
    if any(r["id"] == id for r in _RUNTIME_RULES):
        raise ValueError(f"Rule id already registered: {id}")
    _RUNTIME_RULES.append({
        "id": id,
        "pattern": pattern,
        "severity": severity,
        "sector": sector,
        "context": context or {"boost": [], "suppress": []},
        "compiled": re.compile(pattern),
    })


def clear_rules() -> None:
    """Clear runtime rules and cache. For testing."""
    _RUNTIME_RULES.clear()
    _cache.clear()


def _read(path):
    """Load JSON rule list from *path*; return [] on any error."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.loads(fh.read())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _compile(rules):
    """Add *compiled* regex key to each rule and sort by severity."""
    out = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        out.append({**rule, "compiled": compiled})

    out.sort(key=lambda r: _SEVERITY_ORDER.get(r.get("severity", "medium"), 2))
    return out
