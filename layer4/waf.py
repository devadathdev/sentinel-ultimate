"""Layer 4 — Application Fortress: WAF and HTTP Request Inspection Engine."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum


class ViolationType(str, Enum):
    METHOD_NOT_ALLOWED = "method_not_allowed"
    PATH_TRAVERSAL = "path_traversal"
    SENSITIVE_PROBE = "sensitive_probe_attempt"
    SQL_INJECTION = "sql_injection_detected"
    XSS_ATTACK = "xss_detected"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    INVALID_CONTENT_TYPE = "invalid_content_type"
    MALFORMED_ENCODING = "malformed_encoding"


@dataclass(frozen=True)
class WAFResult:
    allowed: bool
    action: str  # ALLOW, BLOCK, MONITOR
    reason: str
    risk: str    # LOW, MEDIUM, HIGH, CRITICAL
    violations: list[str] = field(default_factory=list)


class WAFEngine:
    """Inspects HTTP requests for injection, path anomalies, and protocol violations."""

    ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
    
    # Probing for common vulnerable endpoints
    PROBE_PATTERNS = (
        r"/\.env", r"/\.git", r"/wp-admin", r"/wp-login", r"/phpmyadmin",
        r"/actuator", r"/console", r"/swagger-ui", r"/debug/pprof",
        r"/aws/credentials", r"/\.aws", r"/id_rsa", r"/id_ed25519",
        r"/etc/passwd", r"/etc/shadow", r"/proc/self"
    )

    # SQL Injection Heuristics
    SQLI_PATTERNS = (
        r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b[\s\S]*?\b(FROM|INTO|TABLE|WHERE|ALL)\b)",
        r"(\bOR\b\s+['\"]?[0-9a-zA-Z_]+['\"]?\s*=\s*['\"]?[0-9a-zA-Z_]+['\"]?)",
        r"(\bAND\b\s+['\"]?[0-9a-zA-Z_]+['\"]?\s*=\s*['\"]?[0-9a-zA-Z_]+['\"]?)",
        r"(--|/\*|\*/|;\s*DROP\b|;\s*DELETE\b|;\s*SHUTDOWN\b)",
        r"(WAITFOR\s+DELAY\s+'[0-9:]+')",
        r"(pg_sleep\s*\(\s*[0-9]+\s*\))",
        r"(SLEEP\s*\(\s*[0-9]+\s*\))",
        r"(BENCHMARK\s*\(\s*[0-9]+)"
    )

    # Cross-Site Scripting (XSS) Patterns
    XSS_PATTERNS = (
        r"<script[\s\S]*?>[\s\S]*?</script>",
        r"<script\b[^>]*>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:\s*text/html",
        r"on(load|error|click|mouseover|focus|blur|submit)\s*=",
        r"eval\s*\([^\)]*\)",
        r"document\.(cookie|location|write)",
        r"<iframe[\s\S]*?>",
        r"<object[\s\S]*?>",
        r"<embed[\s\S]*?>"
    )

    def __init__(
        self,
        *,
        max_body_bytes: int = 1048576,
        block_probes: bool = True,
        enforce_methods: bool = True
    ) -> None:
        self.max_body_bytes = max_body_bytes
        self.block_probes = block_probes
        self.enforce_methods = enforce_methods
        self._compiled_sqli = [re.compile(p, re.IGNORECASE) for p in self.SQLI_PATTERNS]
        self._compiled_xss = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self._compiled_probes = [re.compile(p, re.IGNORECASE) for p in self.PROBE_PATTERNS]

    def inspect_request(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        content_type: str | None = None
    ) -> WAFResult:
        violations: list[str] = []
        method = method.upper()

        # 1. Method Check
        if self.enforce_methods and method not in self.ALLOWED_METHODS:
            return WAFResult(
                allowed=False,
                action="BLOCK",
                reason=ViolationType.METHOD_NOT_ALLOWED.value,
                risk="HIGH",
                violations=[f"method_{method}_disallowed"]
            )

        # 2. Path Normalization & Canonicalization
        try:
            # Double decode to catch obfuscated traversal (%252e%252e%252f)
            decoded_path = urllib.parse.unquote(urllib.parse.unquote(path))
        except Exception:
            return WAFResult(
                allowed=False,
                action="BLOCK",
                reason=ViolationType.MALFORMED_ENCODING.value,
                risk="HIGH",
                violations=["malformed_url_encoding"]
            )

        # Null byte check
        if "\x00" in decoded_path or "%00" in path:
            return WAFResult(
                allowed=False,
                action="BLOCK",
                reason=ViolationType.PATH_TRAVERSAL.value,
                risk="CRITICAL",
                violations=["null_byte_injection"]
            )

        # Path traversal check
        if "../" in decoded_path or "..\\" in decoded_path or "/.." in decoded_path:
            return WAFResult(
                allowed=False,
                action="BLOCK",
                reason=ViolationType.PATH_TRAVERSAL.value,
                risk="CRITICAL",
                violations=["directory_traversal_sequence"]
            )

        # 3. Known Vulnerability Probing Check
        if self.block_probes:
            for probe in self._compiled_probes:
                if probe.search(decoded_path):
                    return WAFResult(
                        allowed=False,
                        action="BLOCK",
                        reason=ViolationType.SENSITIVE_PROBE.value,
                        risk="HIGH",
                        violations=[f"probe:{probe.pattern}"]
                    )

        # 4. Body Size Check
        body_len = len(body) if body is not None else 0
        if body_len > self.max_body_bytes:
            return WAFResult(
                allowed=False,
                action="BLOCK",
                reason=ViolationType.PAYLOAD_TOO_LARGE.value,
                risk="MEDIUM",
                violations=[f"size_{body_len}_exceeds_{self.max_body_bytes}"]
            )

        # Convert body to string for content inspection
        body_str = ""
        if isinstance(body, bytes):
            try:
                body_str = body.decode("utf-8", errors="ignore")
            except Exception:
                body_str = ""
        elif isinstance(body, str):
            body_str = body

        inspect_target = f"{decoded_path} {body_str}"

        # 5. SQL Injection Inspection
        for sqli in self._compiled_sqli:
            if sqli.search(inspect_target):
                violations.append("sql_injection_signature")
                return WAFResult(
                    allowed=False,
                    action="BLOCK",
                    reason=ViolationType.SQL_INJECTION.value,
                    risk="CRITICAL",
                    violations=violations
                )

        # 6. Cross-Site Scripting (XSS) Inspection
        for xss in self._compiled_xss:
            if xss.search(inspect_target):
                violations.append("xss_signature")
                return WAFResult(
                    allowed=False,
                    action="BLOCK",
                    reason=ViolationType.XSS_ATTACK.value,
                    risk="HIGH",
                    violations=violations
                )

        # 7. Content-Type Validation for Mutations
        if method in {"POST", "PUT", "PATCH"} and body_len > 0:
            ctype = content_type or (headers.get("content-type") if headers else "") or ""
            allowed_ctypes = ("application/json", "text/plain", "multipart/form-data", "application/x-www-form-urlencoded")
            if not ctype or not any(v in ctype.lower() for v in allowed_ctypes):
                violations.append("unsupported_media_type")
                return WAFResult(
                    allowed=False,
                    action="BLOCK",
                    reason=ViolationType.INVALID_CONTENT_TYPE.value,
                    risk="MEDIUM",
                    violations=violations
                )

        return WAFResult(
            allowed=True,
            action="ALLOW",
            reason="waf_validation_pass",
            risk="LOW",
            violations=[]
        )
