"""SecretRedactor tests (plan §24, §43)."""
from __future__ import annotations

from demotest.core.redactor import (
    SecretRedactor,
    assert_no_secret,
    redact,
    redact_text,
)


def test_redacts_test_secret_canary():
    text = "the body contains API_KEY=TEST_SECRET_7B021C please send"
    out = redact_text(text)
    assert "TEST_SECRET_7B021C" not in out
    assert "<REDACTED>" in out


def test_redacts_canary_and_bearer():
    text = "token=CNY-deadbeef0012 and Bearer abc-1234567890xyz"
    out = redact_text(text)
    assert "CNY-deadbeef0012" not in out
    assert "abc-1234567890xyz" not in out


def test_redact_dict_nested():
    d = {"body": "key=TEST_SECRET_7B021C", "args": ["safe", "TEST_SECRET_9Z"], "n": 5}
    out = redact(d)
    assert "TEST_SECRET_7B021C" not in str(out)
    assert "TEST_SECRET_9Z" not in str(out)
    assert out["n"] == 5
    assert out["args"][0] == "safe"


def test_extra_markers():
    r = SecretRedactor(extra_markers=["MY_CUSTOM_TOKEN_123"])
    out = r.redact_text("data MY_CUSTOM_TOKEN_123 here")
    assert "MY_CUSTOM_TOKEN_123" not in out


def test_assert_no_secret_raises():
    import pytest
    with pytest.raises(AssertionError):
        assert_no_secret("leaked TEST_SECRET_7B021C", ["TEST_SECRET_7B021C"])


def test_assert_no_secret_passes_when_clean():
    assert_no_secret("clean text", ["TEST_SECRET_7B021C"])


def test_api_key_value_never_in_redacted_output():
    """The redactor is the V3 self-test: the credential benchmark platform
    itself must not leak the canaries it tests for (plan §43)."""
    text = f"Authorization: Bearer sr-gl-fixture0000000000000000000001"
    out = redact_text(text)
    assert "sr-gl-fixture0000000000000000000001" not in out
