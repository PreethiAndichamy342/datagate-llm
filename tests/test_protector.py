"""Tests for protect() / unprotect() client wrapping."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import MagicMock
from datagate_llm import protect, unprotect
from datagate_llm.protector import _PROTECTED


def _make_openai():
    client = MagicMock()
    client.__name__ = "openai"
    client.chat.completions.create = MagicMock(
        return_value={"choices": []}
    )
    return client


def _make_anthropic():
    client = MagicMock()
    client.__name__ = "anthropic"
    client.messages.create = MagicMock(
        return_value={"content": []}
    )
    return client


def teardown_function():
    _PROTECTED.clear()


def test_protect_flag_safe_passes():
    client = _make_openai()
    protect(client, mode="flag")
    result = client.chat.completions.create(
        messages=[{"role": "user", "content": "hello world"}]
    )
    assert result == {"choices": []}


def test_protect_block_raises_on_unsafe():
    client = _make_openai()
    protect(client, mode="block", sectors=["technology"])
    with pytest.raises(ValueError, match="blocked"):
        client.chat.completions.create(
            messages=[{
                "role": "user",
                "content": "key AKIAIOSFODNN7EXAMPLE",
            }]
        )


def test_protect_redact_removes_pii():
    client = _make_openai()
    protect(client, mode="redact")
    messages = [{"role": "user", "content": "email me at john@company.com"}]
    client.chat.completions.create(messages=messages)
    assert "john@company.com" not in messages[0]["content"]


def test_protect_duplicate_raises():
    client = _make_openai()
    protect(client, mode="flag")
    with pytest.raises(ValueError, match="already protected"):
        protect(client, mode="flag")


def test_unprotect_restores_original():
    client = _make_openai()
    original = client.chat.completions.create
    protect(client, mode="flag")
    unprotect(client)
    assert client.chat.completions.create == original


def test_unprotect_not_protected_raises():
    client = _make_openai()
    with pytest.raises(ValueError, match="not protected"):
        unprotect(client)


def test_protect_anthropic_passes():
    client = _make_anthropic()
    protect(client, mode="flag")
    client.messages.create(
        messages=[{"role": "user", "content": "hello world"}]
    )


def test_protect_clean_reaches_original():
    client = _make_openai()
    protect(client, mode="block")
    result = client.chat.completions.create(
        messages=[{"role": "user", "content": "how do I sort a list"}]
    )
    assert result == {"choices": []}
