import pytest
from layer5.dlp import DataLossPreventer


@pytest.fixture
def dlp():
    return DataLossPreventer()


def test_clean_text(dlp):
    res = dlp.scan("This is a public statement about security architecture.")
    assert res.has_leak is False
    assert res.risk == "LOW"
    assert len(res.findings) == 0


def test_openai_key_leak(dlp):
    leaked = "Here is the key: sk-abcdef1234567890abcdef1234567890 to access model."
    res = dlp.scan(leaked)
    assert res.has_leak is True
    assert res.risk == "CRITICAL"
    assert res.findings[0].finding_type == "OPENAI_KEY"
    assert "[REDACTED_SECRET:OPENAI_KEY]" in res.redacted_text


def test_aws_key_leak(dlp):
    leaked = "Export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE now."
    res = dlp.scan(leaked)
    assert res.has_leak is True
    assert res.findings[0].finding_type == "AWS_ACCESS_KEY"


def test_private_key_leak(dlp):
    leaked = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----"""
    res = dlp.scan(leaked)
    assert res.has_leak is True
    assert res.findings[0].finding_type == "PRIVATE_KEY_BLOCK"


def test_ssn_and_email_leak(dlp):
    leaked = "Contact user at alice@example.com with SSN 123-45-6789."
    res = dlp.scan(leaked)
    assert res.has_leak is True
    types = [f.finding_type for f in res.findings]
    assert "SSN" in types
    assert "EMAIL" in types
    redacted = dlp.redact(leaked)
    assert "alice@example.com" not in redacted
    assert "123-45-6789" not in redacted
