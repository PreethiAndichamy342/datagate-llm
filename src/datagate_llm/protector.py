"""
Client protection via monkey-patching.
Wraps LLM client methods to auto-scan before
every API call. Zero dependencies.
"""
from __future__ import annotations

_PROTECTED: dict = {}  # tracks patched clients


def protect(
    client: object,
    sectors: list | None = None,
    mode: str = "flag",
    custom_rules: str | None = None,
    scan_hardcoded: bool = True,
) -> None:
    """
    Wrap an LLM client to auto-scan every request.

    Supports openai and anthropic clients.
    Call once at app startup.

    Raises:
        ValueError: if client already protected or unsupported
    """
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


def unprotect(client: object) -> None:
    """
    Remove protection from a client.
    Restores original method. Useful for testing.

    Raises:
        ValueError: if client not protected
    """
    name = _client_name(client)
    if name not in _PROTECTED:
        raise ValueError(f"{name} is not protected")
    _set_method(client, name, _PROTECTED.pop(name))


def _client_name(client: object) -> str:
    """Identify client by module or class name."""
    name = getattr(client, "__name__", None)
    if name:
        return name
    return type(client).__module__.split(".")[0]


def _get_method(client: object, name: str):
    """Return the create method for known clients, else None."""
    try:
        if name == "openai":
            return client.chat.completions.create
        if name == "anthropic":
            return client.messages.create
    except AttributeError:
        pass
    return None


def _set_method(client: object, name: str, fn) -> None:
    """Patch the create method on the client."""
    if name == "openai":
        client.chat.completions.create = fn
    elif name == "anthropic":
        client.messages.create = fn


def _scan_messages(
    kwargs: dict,
    sectors: list | None,
    mode: str,
    custom_rules: str | None,
    scan_hardcoded: bool,
) -> None:
    """
    Scan all message content before sending.
    Mutates kwargs in place for redact mode.
    Raises ValueError in block mode if unsafe.
    """
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
