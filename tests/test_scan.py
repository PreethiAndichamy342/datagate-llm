"""Integration tests for the public scan() API."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import datagate_llm.loader as loader_mod
from datagate_llm import scan


def setup_function():
    loader_mod._cache.clear()


def test_email_detected():
    r = scan("Please contact alice@company.com for details")
    assert not r["safe"]
    assert r["risk_score"] > 0
    assert any("email" in f["rule_id"] for f in r["findings"])


def test_clean_text_is_safe():
    r = scan("The weather is great today in the mountains.")
    assert r["safe"]
    assert r["risk_score"] == 0.0
    assert r["action"] == "allow"


def test_redact_mode_removes_pii():
    r = scan("Email me at bob@acme.org please", mode="redact")
    assert "bob@acme.org" not in r["redacted_text"]
    assert "REDACTED" in r["redacted_text"]


def test_block_mode_on_risky_input():
    r = scan("My SSN is 123-45-6789", mode="block")
    assert r["action"] in ("block", "flag", "allow")


def test_fingerprint_stable():
    text = "user@example.com"
    r1 = scan(text)
    loader_mod._cache.clear()
    r2 = scan(text)
    assert r1["fingerprint"] == r2["fingerprint"]


def test_technology_sector_detects_api_key():
    text = "Key: AKIAIOSFODNN7EXAMPLE"
    r = scan(text, sectors=["technology"])
    assert any("aws" in f["rule_id"] for f in r["findings"])


def test_healthcare_sector_detects_npi():
    text = "Provider NPI: 1234567890"
    r = scan(text, sectors=["healthcare"])
    assert any("npi" in f["rule_id"] for f in r["findings"])


def test_finance_sector_detects_iban():
    text = "Wire to GB29NWBK60161331926819"
    r = scan(text, sectors=["finance"])
    assert any("iban" in f["rule_id"] for f in r["findings"])


def test_scan_detects_uuid():
    r = scan("session 3f2a9c1b-4d5e-4f6a-8b9c-1d2e3f4a5b6c")
    assert r["safe"] == False


def test_scan_detects_emp_id():
    r = scan("employee EMP-123456 accessed system")
    assert r["safe"] == False


def test_scan_hardcoded_disabled():
    r = scan(
        "session 3f2a9c1b-4d5e-4f6a-8b9c-1d2e3f4a5b6c",
        scan_hardcoded=False,
    )
    assert r["safe"] == True


def test_scan_clean_stays_safe():
    r = scan("how can I help you today", scan_hardcoded=True)
    assert r["safe"] == True
