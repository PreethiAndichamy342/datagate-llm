"""Template-based pattern builder. No regex knowledge required."""
from __future__ import annotations

import re
from datagate_llm.loader import add_rule

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_TEMPLATES: dict[str, str] = {
    "prefix_digits": r"{prefix}\d{{{n}}}",
    "prefix_dash_digits": r"{prefix}-\d{{{n}}}",
    "prefix_dash_alphanum": r"{prefix}-[A-Z0-9]{{{n}}}",
    "digits_only": r"\d{{{n}}}",
    "alphanum_fixed": r"[A-Z0-9]{{{n}}}",
    "key_value": r"{prefix}=\S{{{n},}}",
}


def build_rule(
    name: str,
    template: str,
    severity: str,
    prefix: str = "",
    n: int = 0,
    sector: str = "custom",
    boost: list | None = None,
    suppress: list | None = None,
) -> dict:
    """Return a rule dict built from a named template."""
    if template not in _TEMPLATES:
        raise ValueError(
            f"Unknown template '{template}'. "
            f"Choose from: {sorted(_TEMPLATES)}"
        )
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Choose from: {sorted(_VALID_SEVERITIES)}"
        )
    pattern = _TEMPLATES[template].format(prefix=prefix, n=n)
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Generated pattern is invalid: {exc}") from exc
    return {
        "id": f"custom/{name}",
        "pattern": pattern,
        "severity": severity,
        "sector": sector,
        "context": {
            "boost": boost or [],
            "suppress": suppress or [],
        },
    }


def add_pattern(
    name: str,
    template: str,
    severity: str,
    prefix: str = "",
    n: int = 0,
    sector: str = "custom",
    boost: list | None = None,
    suppress: list | None = None,
) -> None:
    """Build a rule from a template and register it at runtime."""
    rule = build_rule(
        name, template, severity,
        prefix=prefix, n=n, sector=sector,
        boost=boost, suppress=suppress,
    )
    add_rule(
        id=rule["id"],
        pattern=rule["pattern"],
        severity=rule["severity"],
        sector=rule["sector"],
        context=rule["context"],
    )
