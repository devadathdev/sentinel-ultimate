"""Layer 7 — Execution Sandbox: Policy Engine and Attested Execution Ticket Generator."""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass, field
from .command_parser import SafeCommandParser, CommandAnalysisResult


@dataclass(frozen=True)
class ExecutionTicket:
    ticket_id: str
    command: str
    identity: str
    role: str
    created_at: int
    expires_at: int
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    timeout_seconds: int = 30
    signature: str = ""


@dataclass(frozen=True)
class ExecutionDecision:
    allow: bool
    action: str  # ALLOW, REQUIRE_APPROVAL, BLOCK
    reason: str
    risk: str    # LOW, MEDIUM, HIGH, CRITICAL
    ticket: ExecutionTicket | None = None
    violations: list[str] = field(default_factory=list)


class SandboxPolicyEngine:
    """Enforces deny-by-default execution boundaries and issues cryptographic execution tickets."""

    def __init__(self, signing_secret: str = "sentinel-sandbox-secret-default") -> None:
        self.signing_secret = signing_secret.encode()
        self.parser = SafeCommandParser()

    def _sign_ticket(self, ticket_id: str, command: str, identity: str, expires_at: int) -> str:
        data = f"{ticket_id}:{command}:{identity}:{expires_at}".encode()
        return hmac.new(self.signing_secret, data, hashlib.sha256).hexdigest()

    def verify_ticket(self, ticket: ExecutionTicket) -> bool:
        if not ticket or not ticket.signature:
            return False
        if time.time() > ticket.expires_at:
            return False
        expected = self._sign_ticket(ticket.ticket_id, ticket.command, ticket.identity, ticket.expires_at)
        return hmac.compare_digest(expected, ticket.signature)

    def authorize(
        self,
        *,
        identity: str,
        role: str,
        command: str,
        sandbox: bool = False,
        timeout_seconds: int = 30
    ) -> ExecutionDecision:
        if not identity:
            return ExecutionDecision(
                allow=False, action="BLOCK", reason="missing_identity",
                risk="HIGH", violations=["no_caller_identity"]
            )

        if not sandbox:
            return ExecutionDecision(
                allow=False, action="BLOCK", reason="execution_requires_sandbox",
                risk="CRITICAL", violations=["unsandboxed_execution_forbidden"]
            )

        if role not in {"developer", "admin"}:
            return ExecutionDecision(
                allow=False, action="BLOCK", reason="role_cannot_execute",
                risk="HIGH", violations=[f"role_{role}_forbidden_from_execution"]
            )

        # Parse command with lexical anti-evasion parser
        analysis: CommandAnalysisResult = self.parser.analyze(command)
        if not analysis.is_safe:
            raw_reason = analysis.reasons[0] if analysis.reasons else "command_not_allowed"
            reason = raw_reason[7:] if raw_reason.startswith("threat:") else raw_reason
            return ExecutionDecision(
                allow=False,
                action="BLOCK" if analysis.risk in {"CRITICAL", "HIGH"} else "REQUIRE_APPROVAL",
                reason=reason,
                risk=analysis.risk,
                violations=analysis.reasons
            )

        # Issue cryptographically signed execution ticket
        now = int(time.time())
        exp = now + timeout_seconds
        tid = str(uuid.uuid4())
        sig = self._sign_ticket(tid, analysis.canonical_command, identity, exp)

        ticket = ExecutionTicket(
            ticket_id=tid,
            command=analysis.canonical_command,
            identity=identity,
            role=role,
            created_at=now,
            expires_at=exp,
            timeout_seconds=timeout_seconds,
            signature=sig
        )

        return ExecutionDecision(
            allow=True,
            action="ALLOW",
            reason="sandboxed_allowlisted_command",
            risk="MEDIUM",
            ticket=ticket
        )
