"""
Client protection via monkey-patching.
Wraps LLM client methods to auto-scan before
every API call. Zero dependencies.
"""
from __future__ import annotations

_PROTECTED: dict = {}  # tracks patched clients


def protect(
    client,
    sectors=None,
    mode="flag",
    custom_rules=None,
    scan_hardcoded=True,
):
    """Wrap openai/anthropic client to auto-scan every request."""
    name = _client_name(client)
    if name in _PROTECTED:
        raise ValueError(f"{name} already protected")
    original = _get_method(client, name)
    if original is None:
        raise ValueError(
            f"Unsupported client: {name}. "
            f"Supported: openai, anthropic"
        )

    def patched(**kwargs):
        _scan_messages(
            kwargs, sectors=sectors, mode=mode,
            custom_rules=custom_rules, scan_hardcoded=scan_hardcoded,
        )
        return original(**kwargs)

    _set_method(client, name, patched)
    _PROTECTED[name] = original


def unprotect(client) -> None:
    """Remove protection and restore original method."""
    name = _client_name(client)
    if name not in _PROTECTED:
        raise ValueError(f"{name} is not protected")
    _set_method(client, name, _PROTECTED.pop(name))


def _client_name(client) -> str:
    """Identify client by module or class name."""
    name = getattr(client, "__name__", None)
    if name:
        return name
    return type(client).__module__.split(".")[0]


def _get_method(client, name):
    """Return create method for known clients, else None."""
    try:
        if name == "openai":
            return client.chat.completions.create
        if name == "anthropic":
            return client.messages.create
    except AttributeError:
        pass
    return None


def _set_method(client, name, fn) -> None:
    """Patch the create method on the client."""
    if name == "openai":
        client.chat.completions.create = fn
    elif name == "anthropic":
        client.messages.create = fn


def _scan_messages(kwargs, sectors, mode, custom_rules, scan_hardcoded):
    """Scan messages; mutate for redact; raise for block."""
    from datagate_llm import scan

    messages = kwargs.get("messages", [])
    if not messages:
        prompt = kwargs.get("prompt", [])
        messages = [{"role": "user", "content": prompt}] if isinstance(prompt, str) else prompt

    for msg in messages:
        content = msg.get("content", "")
        if not isinstance(content, str):
            continue
        result = scan(content, sectors=sectors, mode=mode,
                      custom_rules=custom_rules, scan_hardcoded=scan_hardcoded)
        if mode == "redact":
            msg["content"] = result["redacted_text"]
        elif mode == "block" and not result["safe"]:
            raise ValueError(
                f"blocked: unsafe content detected "
                f"(risk_score={result['risk_score']})"
            )
