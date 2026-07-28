# Contributing to datagate-llm

Thank you for your interest in contributing. This document explains how the project works and what we accept.

## How to Add Rules (JSON Only, No Python)

All detection patterns live in JSON files under `src/datagate_llm/rules/`. To add a new rule:

1. Open the appropriate sector file (`universal.json`, `technology.json`, `healthcare.json`, or `finance.json`).
2. Add a new JSON object to the array following the schema below.
3. Add a test in `tests/test_scan.py` that exercises the new rule.
4. Open a pull request.

No Python changes are needed to add a rule. Pattern logic stays in JSON.

## Rule Schema Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique rule identifier in the form `sector/name` (e.g. `universal/email`) |
| `sector` | string | yes | One of `universal`, `technology`, `healthcare`, `finance` |
| `pattern` | string | yes | Python `re`-compatible regex. Escape backslashes as `\\` in JSON. |
| `severity` | string | yes | One of `critical`, `high`, `medium`, `low` |
| `context` | object | yes | Object with two keys: `boost` (list of strings) and `suppress` (list of strings) |
| `context.boost` | list[str] | yes | Words near the match that raise confidence |
| `context.suppress` | list[str] | yes | Words near the match that lower confidence |

## Test Requirements

Every pull request must include tests. The rule: **if you add or modify a rule, add a test that catches a real-world example of that pattern.**

- Tests live in `tests/`.
- Each test function must be independent (no shared mutable state).
- Tests must pass on Python 3.9, 3.10, 3.11, and 3.12.

## What Will Be Rejected

Pull requests that add any of the following will be closed without review:

- **Proxies, API gateways, or middleware layers** — this library is a pure function, not a service.
- **Dashboards, UIs, or web servers** — out of scope.
- **Enterprise platform integrations** — keep it zero-dependency.
- **External dependencies** for the core engine — stdlib only (`re`, `json`, `os`, `hashlib`, `unicodedata`, `functools`).
- **Classes** where plain functions suffice.
- **Hardcoded values** in Python files — all patterns belong in JSON.
- **Files over 100 lines** or functions over 20 lines.

## How to Add New Templates

Templates live in `src/datagate_llm/builder.py`
in the `_TEMPLATES` dict.

Each template is a Python format string:

```python
_TEMPLATES = {
    "your_template_name": r"{prefix}\d{{{n}}}",
}
```

Format string variables available:
- `{prefix}` — fixed string prefix
- `{n}` — digit or character count

### Rules for new templates:
1. Name must be lowercase with underscores
2. Must be expressible with `{prefix}` and `{n}` only
3. Must have a test in `tests/test_builder.py`
4. Must be added to the README.md template table
5. Must be documented with an example match

### What belongs in templates vs rules:

| Use a template when… | Use `add_rule()` when… |
|----------------------|------------------------|
| Pattern is `PREFIX + fixed-length digits/alphanum` | Length is variable (`\d{6,10}`) |
| Format never changes between organisations | Pattern has optional parts (`-?`) |
| No regex knowledge is available | Pattern requires OR conditions (`A|B`) |
| You want validation on prefix and length | You need character classes or lookaheads |

If you are unsure, use `add_rule()` — it accepts any valid Python regex.

### Example PR for new template:
```python
# 1. Add to _TEMPLATES in builder.py
"prefix_slash_digits": r"{prefix}/\d{{{n}}}",

# 2. Add test in test_builder.py
def test_prefix_slash_digits():
    r = build_rule("x", "prefix_slash_digits",
                   "high", prefix="INV", n=6)
    assert r["pattern"] == r"INV/\d{6}"

# 3. Add to README.md table
# | `prefix_slash_digits` | `INV/123456` | ... |
```

## How to Run Tests Locally

```bash
# 1. Install the package in editable mode
pip install -e .

# 2. Install pytest
pip install pytest

# 3. Run the full test suite
pytest tests/ -v
```

All tests should pass with zero warnings before you open a pull request.
