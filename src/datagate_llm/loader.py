"""
Rule loader with in-process cache. stdlib only.
"""

import json
import os
import re

_cache = {}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_rules(sectors, rules_dir):
    """Return compiled rules for *sectors* (universal always included)."""
    key = (tuple(sorted(sectors)), rules_dir)
    if key in _cache:
        return _cache[key]

    raw = _read(os.path.join(rules_dir, "universal.json"))
    for sector in sectors:
        path = os.path.join(rules_dir, f"{sector}.json")
        raw.extend(_read(path))

    compiled = _compile(raw)
    _cache[key] = compiled
    return compiled


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
        entry = dict(rule)
        entry["compiled"] = compiled
        out.append(entry)

    out.sort(key=lambda r: _SEVERITY_ORDER.get(r.get("severity", "medium"), 2))
    return out
