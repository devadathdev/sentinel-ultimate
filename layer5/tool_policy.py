"""Layer 5 — AI Firewall: Tool Governance and Multi-Stage Approval Policy Engine."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum


class ToolRiskTier(IntEnum):
    SAFE = 0       # Pure informational / search
    LOW = 1        # Read local project file
    MEDIUM = 2     # File create/edit, non-destructive state update
    HIGH = 3       # System shell, deploy, database write, credential access
    CRITICAL = 4   # Drop tables, force push, cluster wipe, host shutdown


@dataclass(frozen=True)
class ToolDecision:
    allow: bool
    action: str  # ALLOW, REQUIRE_APPROVAL, REQUIRE_MFA, BLOCK
    reason: str
    risk: str    # LOW, MEDIUM, HIGH, CRITICAL
    tier: ToolRiskTier
    violations: list[str] = field(default_factory=list)


class AIToolPolicyEngine:
    """Evaluates agent tool invocations against risk tiers, caller identity, and deep argument inspection."""

    TOOL_TIERS: dict[str, ToolRiskTier] = {
        # Tier 0 (Safe)
        "web_search": ToolRiskTier.SAFE,
        "read_project": ToolRiskTier.SAFE,
        "calculator": ToolRiskTier.SAFE,
        "get_weather": ToolRiskTier.SAFE,

        # Tier 1 (Low)
        "read_file": ToolRiskTier.LOW,
        "list_directory": ToolRiskTier.LOW,
        "git_status": ToolRiskTier.LOW,

        # Tier 2 (Medium)
        "create_code": ToolRiskTier.MEDIUM,
        "edit_file": ToolRiskTier.MEDIUM,
        "run_query": ToolRiskTier.MEDIUM,

        # Tier 3 (High)
        "shell": ToolRiskTier.HIGH,
        "deploy": ToolRiskTier.HIGH,
        "database_write": ToolRiskTier.HIGH,
        "secrets": ToolRiskTier.HIGH,
        "network_admin": ToolRiskTier.HIGH,

        # Tier 4 (Critical)
        "force_push": ToolRiskTier.CRITICAL,
        "delete_database": ToolRiskTier.CRITICAL,
        "shutdown_host": ToolRiskTier.CRITICAL,
    }

    DANGEROUS_ARG_PATTERNS = (
        "../", r"..\\", "%2e%2e",
        "/etc/shadow", "/etc/passwd", "/proc/",
        "169.254.169.254", "metadata.google.internal",
        "rm -rf", "format c:", "del /f", "mkfs", ":(){ :|:& };:",
        "drop table", "truncate table", "drop database"
    )

    def evaluate(
        self,
        *,
        identity: str,
        role: str,
        tool: str,
        args: dict | None = None,
        approved: bool = False,
        mfa_verified: bool = False,
        approvers: list[str] | None = None
    ) -> ToolDecision:
        if not identity:
            return ToolDecision(
                allow=False, action="BLOCK", reason="missing_identity",
                risk="HIGH", tier=ToolRiskTier.HIGH, violations=["no_caller_identity"]
            )

        tier = self.TOOL_TIERS.get(tool)
        if tier is None:
            # Unknown tool: default-deny
            return ToolDecision(
                allow=False, action="BLOCK", reason="unknown_tool_denied_by_default",
                risk="HIGH", tier=ToolRiskTier.HIGH, violations=[f"unknown_tool_{tool}"]
            )

        # Deep argument inspection
        violations: list[str] = []
        if args:
            args_str = json.dumps(args).lower()
            for pattern in self.DANGEROUS_ARG_PATTERNS:
                if pattern in args_str:
                    violations.append(f"malicious_signature:{pattern}")
                    return ToolDecision(
                        allow=False,
                        action="BLOCK",
                        reason="threat_signature_detected_in_tool_args",
                        risk="CRITICAL",
                        tier=tier,
                        violations=violations
                    )

        # Policy by Tier
        if tier == ToolRiskTier.SAFE:
            return ToolDecision(allow=True, action="ALLOW", reason="safe_tool", risk="LOW", tier=tier)

        if tier == ToolRiskTier.LOW:
            if role in {"viewer", "user", "developer", "operator", "admin"}:
                return ToolDecision(allow=True, action="ALLOW", reason="low_risk_role_authorized", risk="LOW", tier=tier)
            return ToolDecision(allow=False, action="BLOCK", reason="role_cannot_read_files", risk="MEDIUM", tier=tier)

        if tier == ToolRiskTier.MEDIUM:
            if role in {"developer", "operator", "admin"}:
                return ToolDecision(allow=True, action="ALLOW", reason="medium_risk_role_authorized", risk="MEDIUM", tier=tier)
            return ToolDecision(allow=False, action="REQUIRE_APPROVAL", reason="medium_risk_requires_approval", risk="MEDIUM", tier=tier)

        if tier == ToolRiskTier.HIGH:
            if role == "admin" and approved:
                return ToolDecision(allow=True, action="ALLOW", reason="explicit_high_risk_approval", risk="HIGH", tier=tier)
            return ToolDecision(allow=False, action="REQUIRE_APPROVAL", reason="high_risk_tool_requires_explicit_approval", risk="HIGH", tier=tier)

        if tier == ToolRiskTier.CRITICAL:
            # Critical actions require two distinct administrative approvers and MFA verification
            approvers_list = approvers or []
            if len(set(approvers_list)) >= 2 and mfa_verified:
                return ToolDecision(allow=True, action="ALLOW", reason="dual_control_mfa_authorized", risk="CRITICAL", tier=tier)
            return ToolDecision(
                allow=False,
                action="BLOCK",
                reason="critical_action_requires_dual_approval_and_mfa",
                risk="CRITICAL",
                tier=tier,
                violations=["dual_control_not_satisfied"]
            )

        return ToolDecision(allow=False, action="BLOCK", reason="deny_by_default", risk="HIGH", tier=tier)
