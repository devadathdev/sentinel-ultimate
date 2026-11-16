"""Layer 7 — Execution Sandbox: Command Tokenizer, Evasion Detector, and Allowlist Validator."""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from enum import Enum


class EvasionThreat(str, Enum):
    COMMAND_CHAINING = "command_chaining_forbidden"
    PIPE_REDIRECTION = "pipe_or_redirection_detected"
    COMMAND_SUBSTITUTION = "command_substitution_detected"
    INLINE_EXECUTION = "inline_code_execution_detected"
    SHELL_ESCAPE = "shell_escape_detected"
    DISALLOWED_FLAG = "disallowed_flag_detected"
    COMMAND_NOT_ALLOWLISTED = "command_not_on_safe_allowlist"


@dataclass(frozen=True)
class CommandAnalysisResult:
    is_safe: bool
    canonical_command: str
    base_command: str
    reasons: list[str] = field(default_factory=list)
    risk: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


class SafeCommandParser:
    """Parses shell commands using lexical analysis to prevent injection, subshells, and escapes."""

    # Evasion tokens that must never appear in safe execution
    CHAINING_TOKENS = {";", "&&", "||", "&"}
    REDIRECTION_TOKENS = {">", ">>", "<", "<<", "2>&1", "1>&2"}
    SUBSTITUTION_CHARS = {"`", "$(", "${"}

    ALLOWLIST_CONFIG = {
        "python": {
            "allowed_modules": {
                "pytest": {
                    "allowed_flags": {"-v", "-q", "-k", "--tb=short", "--tb=line", "-s", "--color=yes", "--color=no"},
                    "allow_positional": True,
                },
                "compileall": {
                    "allowed_flags": {"-q", "-f", "-l"},
                    "allow_positional": True,
                },
            }
        },
        "pytest": {
            "allowed_flags": {"-v", "-q", "-k", "--tb=short", "--tb=line", "-s", "--color=yes", "--color=no"},
            "allow_positional": True,
        },
        "git": {
            "allowed_subcommands": {
                "status": {"allowed_flags": {"-s", "--short", "-b", "--branch"}},
                "diff": {"allowed_flags": {"--stat", "--name-only", "--cached", "-U3"}},
                "log": {"allowed_flags": {"-n", "--oneline", "--stat"}},
            }
        },
        "ruff": {
            "allowed_subcommands": {
                "check": {"allowed_flags": {"--fix", "--watch", "-v", "-q"}},
                "format": {"allowed_flags": {"--check", "--diff"}},
            }
        }
    }

    def analyze(self, raw_command: str) -> CommandAnalysisResult:
        if not raw_command or not raw_command.strip():
            return CommandAnalysisResult(
                is_safe=False, canonical_command="", base_command="",
                reasons=["empty_command"], risk="HIGH"
            )

        cmd = raw_command.strip()

        # 1. Check for command substitutions (`, $(, ${)
        for token in self.SUBSTITUTION_CHARS:
            if token in cmd:
                return CommandAnalysisResult(
                    is_safe=False, canonical_command=cmd, base_command="",
                    reasons=[f"threat:{EvasionThreat.COMMAND_SUBSTITUTION.value}"], risk="CRITICAL"
                )

        # 2. Tokenize with shlex
        try:
            tokens = shlex.split(cmd, posix=True)
        except Exception as e:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=cmd, base_command="",
                reasons=[f"malformed_syntax:{str(e)}"], risk="HIGH"
            )

        if not tokens:
            return CommandAnalysisResult(is_safe=False, canonical_command="", base_command="", reasons=["no_tokens"], risk="HIGH")

        # 3. Check for chaining tokens and pipes
        for t in tokens:
            if t in self.CHAINING_TOKENS:
                return CommandAnalysisResult(
                    is_safe=False, canonical_command=cmd, base_command=tokens[0],
                    reasons=[f"threat:{EvasionThreat.COMMAND_CHAINING.value}"], risk="CRITICAL"
                )
            if t == "|" or t in self.REDIRECTION_TOKENS:
                return CommandAnalysisResult(
                    is_safe=False, canonical_command=cmd, base_command=tokens[0],
                    reasons=[f"threat:{EvasionThreat.PIPE_REDIRECTION.value}"], risk="CRITICAL"
                )

        # 4. Binary check
        base = tokens[0].lower()
        if base in {"sh", "bash", "zsh", "dash", "powershell", "cmd", "cmd.exe", "powershell.exe"}:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=cmd, base_command=base,
                reasons=[f"threat:{EvasionThreat.SHELL_ESCAPE.value}"], risk="CRITICAL"
            )

        if base not in self.ALLOWLIST_CONFIG:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=cmd, base_command=base,
                reasons=[f"threat:{EvasionThreat.COMMAND_NOT_ALLOWLISTED.value}"], risk="HIGH"
            )

        # 5. Specialized validation per binary
        if base == "python":
            return self._validate_python(tokens, cmd)
        elif base == "pytest":
            return CommandAnalysisResult(is_safe=True, canonical_command=" ".join(tokens), base_command="pytest", risk="LOW")
        elif base == "git":
            return self._validate_git(tokens, cmd)
        elif base == "ruff":
            return self._validate_ruff(tokens, cmd)

        return CommandAnalysisResult(is_safe=True, canonical_command=" ".join(tokens), base_command=base, risk="LOW")

    def _validate_python(self, tokens: list[str], raw_cmd: str) -> CommandAnalysisResult:
        if len(tokens) < 3 or tokens[1] != "-m":
            return CommandAnalysisResult(
                is_safe=False, canonical_command=raw_cmd, base_command="python",
                reasons=["python_requires_explicit_-m_module_execution"], risk="HIGH"
            )

        module = tokens[2].lower()
        allowed_mods = self.ALLOWLIST_CONFIG["python"]["allowed_modules"]
        if module not in allowed_mods:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=raw_cmd, base_command=f"python -m {module}",
                reasons=[f"module_{module}_not_allowlisted"], risk="HIGH"
            )

        # Check for inline execution flag (-c) anywhere
        if "-c" in tokens:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=raw_cmd, base_command="python",
                reasons=[f"threat:{EvasionThreat.INLINE_EXECUTION.value}"], risk="CRITICAL"
            )

        return CommandAnalysisResult(
            is_safe=True,
            canonical_command=" ".join(tokens),
            base_command=f"python -m {module}",
            risk="LOW"
        )

    def _validate_git(self, tokens: list[str], raw_cmd: str) -> CommandAnalysisResult:
        if len(tokens) < 2:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=raw_cmd, base_command="git",
                reasons=["git_requires_subcommand"], risk="MEDIUM"
            )
        sub = tokens[1].lower()
        allowed_subs = self.ALLOWLIST_CONFIG["git"]["allowed_subcommands"]
        if sub not in allowed_subs:
            return CommandAnalysisResult(
                is_safe=False, canonical_command=raw_cmd, base_command=f"git {sub}",
                reasons=[f"git_subcommand_{sub}_forbidden"], risk="HIGH"
            )
        return CommandAnalysisResult(
            is_safe=True, canonical_command=" ".join(tokens), base_command=f"git {sub}", risk="LOW"
        )

    def _validate_ruff(self, tokens: list[str], raw_cmd: str) -> CommandAnalysisResult:
        if len(tokens) < 2:
            return CommandAnalysisResult(is_safe=False, canonical_command=raw_cmd, base_command="ruff", reasons=["ruff_requires_subcommand"], risk="MEDIUM")
        sub = tokens[1].lower()
        if sub not in self.ALLOWLIST_CONFIG["ruff"]["allowed_subcommands"]:
            return CommandAnalysisResult(is_safe=False, canonical_command=raw_cmd, base_command=f"ruff {sub}", reasons=[f"ruff_subcommand_{sub}_forbidden"], risk="HIGH")
        return CommandAnalysisResult(is_safe=True, canonical_command=" ".join(tokens), base_command=f"ruff {sub}", risk="LOW")
