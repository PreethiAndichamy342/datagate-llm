"""
gate() decorator for function-level LLM protection.
"""
from __future__ import annotations
import functools


def gate(
    sectors=None,
    mode="flag",
    custom_rules=None,
    scan_hardcoded=True,
):
    """Decorator — scan first string arg before
    function executes."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            text = _first_string(args, kwargs)
            if text is None:
                return fn(*args, **kwargs)
            from datagate_llm import scan
            result = scan(
                text,
                sectors=sectors,
                mode=mode,
                custom_rules=custom_rules,
                scan_hardcoded=scan_hardcoded,
            )
            if mode == "block" and not result["safe"]:
                raise ValueError(
                    f"datagate-llm blocked: "
                    f"{result['findings'][0]['rule_id']}"
                )
            if mode == "redact":
                args, kwargs = _replace_first_string(
                    args, kwargs,
                    result["redacted_text"] or text
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _first_string(args, kwargs):
    """Return first string in args or kwargs."""
    for a in args:
        if isinstance(a, str):
            return a
    for v in kwargs.values():
        if isinstance(v, str):
            return v
    return None


def _replace_first_string(args, kwargs, replacement):
    """Replace first string in args or kwargs."""
    args = list(args)
    for i, a in enumerate(args):
        if isinstance(a, str):
            args[i] = replacement
            return tuple(args), kwargs
    for k, v in kwargs.items():
        if isinstance(v, str):
            kwargs[k] = replacement
            return tuple(args), kwargs
    return tuple(args), kwargs
