"""Layer 5 — AI Firewall: Data Loss Prevention (DLP) and Model Output Redaction."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DLPFinding:
    category: str      # SECRET or PII
    finding_type: str  # OPENAI_KEY, AWS_KEY, PRIVATE_KEY, CREDIT_CARD, SSN, EMAIL
    match_preview: str # Partial redacted preview
    severity: str      # HIGH or CRITICAL


@dataclass(frozen=True)
class DLPResult:
    has_leak: bool
    risk: str          # LOW, MEDIUM, HIGH, CRITICAL
    findings: list[DLPFinding] = field(default_factory=list)
    redacted_text: str = ""


class DataLossPreventer:
    """Detects and redacts credentials, secrets, and personally identifiable information (PII)."""

    SECRET_PATTERNS = {
        "OPENAI_KEY": r"\bsk-[a-zA-Z0-9_-]{20,}\b",
        "GITHUB_PAT": r"\bghp_[a-zA-Z0-9]{36}\b",
        "AWS_ACCESS_KEY": r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        "PRIVATE_KEY_BLOCK": r"-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+([A-Z\s]+)?PRIVATE\s+KEY-----",
        "JWT_TOKEN": r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
    }

    PII_PATTERNS = {
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    }

    def __init__(self) -> None:
        self._compiled_secrets = {k: re.compile(p) for k, p in self.SECRET_PATTERNS.items()}
        self._compiled_pii = {k: re.compile(p) for k, p in self.PII_PATTERNS.items()}

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """Validates credit card checksum via Luhn algorithm."""
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += digit
        return total % 10 == 0

    def scan(self, text: str) -> DLPResult:
        if not text:
            return DLPResult(has_leak=False, risk="LOW", findings=[], redacted_text="")

        findings: list[DLPFinding] = []
        redacted = text

        # 1. Scan for Secrets
        for sec_type, regex in self._compiled_secrets.items():
            for match in regex.finditer(text):
                val = match.group(0)
                preview = val[:4] + "..." + val[-3:] if len(val) > 7 else "***"
                findings.append(DLPFinding(
                    category="SECRET",
                    finding_type=sec_type,
                    match_preview=preview,
                    severity="CRITICAL"
                ))
            redacted = regex.sub(f"[REDACTED_SECRET:{sec_type}]", redacted)

        # 2. Scan for PII
        for pii_type, regex in self._compiled_pii.items():
            for match in regex.finditer(text):
                val = match.group(0)
                # Verify Credit Card numbers with Luhn check to prevent false positives
                if pii_type == "CREDIT_CARD" and not self._luhn_check(val):
                    continue

                preview = val[:2] + "..." + val[-2:] if len(val) > 4 else "***"
                findings.append(DLPFinding(
                    category="PII",
                    finding_type=pii_type,
                    match_preview=preview,
                    severity="HIGH"
                ))
                redacted = redacted.replace(val, f"[REDACTED_PII:{pii_type}]")

        has_leak = len(findings) > 0
        risk = "CRITICAL" if any(f.severity == "CRITICAL" for f in findings) else ("HIGH" if has_leak else "LOW")

        return DLPResult(
            has_leak=has_leak,
            risk=risk,
            findings=findings,
            redacted_text=redacted
        )

    def redact(self, text: str) -> str:
        return self.scan(text).redacted_text
