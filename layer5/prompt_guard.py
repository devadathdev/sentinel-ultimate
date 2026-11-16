"""Layer 5 — AI Firewall: Prompt Injection and Jailbreak Defense Engine."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum


class InjectionType(str, Enum):
    SYSTEM_OVERRIDE = "system_override"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    DELIMITER_INJECTION = "delimiter_injection"
    OBFUSCATION_ATTACK = "obfuscation_attack"
    INDIRECT_INJECTION = "indirect_injection"


@dataclass(frozen=True)
class InjectionResult:
    is_safe: bool
    risk: str  # LOW, MEDIUM, HIGH, CRITICAL
    threat_score: float  # 0.0 to 1.0
    detected_types: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class PromptGuard:
    """Detects direct and indirect prompt injection, jailbreak attempts, and token delimiter spoofing."""

    # Explicit override signatures (High Confidence)
    SYSTEM_OVERRIDE_PATTERNS = (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)",
        r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)",
        r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)",
        r"bypass\s+(all\s+)?(safety|security|content|filter)\s+(guidelines|protocols|checks|rules)",
        r"you\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|god\s+mode|dan\s+mode)",
        r"override\s+(system\s+)?(prompt|instructions|guardrails)",
        r"enter\s+(developer\s+mode|debug\s+mode|sudo\s+mode)",
        r"your\s+new\s+system\s+(prompt|directive)\s+is",
    )

    # Jailbreak / adversarial framing
    JAILBREAK_PATTERNS = (
        r"\bact\s+as\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|malicious)\b",
        r"\bpretend\s+you\s+(have\s+no\s+rules|are\s+not\s+an\s+ai|are\s+evil)\b",
        r"\bdo\s+anything\s+now\b",
        r"\bhypothetically\s+without\s+(any\s+)?(rules|laws|ethics)\b",
        r"\bfor\s+educational\s+purposes\s+only,?\s+how\s+do\s+i\s+(hack|attack|exploit|bypass)\b",
    )

    # Delimiter / LLM control token injection
    DELIMITER_PATTERNS = (
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"\[INST\]",
        r"\[/INST\]",
        r"<<SYS>>",
        r"<</SYS>>",
        r"\b(SYSTEM|ASSISTANT|HUMAN):\s*",
        r"###\s*(System|Instruction|Response):",
    )

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold
        self._compiled_override = [re.compile(p, re.IGNORECASE) for p in self.SYSTEM_OVERRIDE_PATTERNS]
        self._compiled_jailbreak = [re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_PATTERNS]
        self._compiled_delimiter = [re.compile(p, re.IGNORECASE) for p in self.DELIMITER_PATTERNS]

    def scan_prompt(self, prompt: str) -> InjectionResult:
        if not prompt or not prompt.strip():
            return InjectionResult(is_safe=True, risk="LOW", threat_score=0.0)

        threat_score = 0.0
        detected_types: list[str] = []
        reasons: list[str] = []

        # 1. System Prompt Override Checks (Weight: 0.6)
        for pattern in self._compiled_override:
            if pattern.search(prompt):
                threat_score += 0.6
                detected_types.append(InjectionType.SYSTEM_OVERRIDE.value)
                reasons.append(f"matched_override:{pattern.pattern}")
                break

        # 2. Jailbreak Roleplay Checks (Weight: 0.4)
        for pattern in self._compiled_jailbreak:
            if pattern.search(prompt):
                threat_score += 0.4
                detected_types.append(InjectionType.JAILBREAK_ROLEPLAY.value)
                reasons.append(f"matched_jailbreak:{pattern.pattern}")
                break

        # 3. Delimiter Injection Checks (Weight: 0.5)
        for pattern in self._compiled_delimiter:
            if pattern.search(prompt):
                threat_score += 0.5
                detected_types.append(InjectionType.DELIMITER_INJECTION.value)
                reasons.append(f"matched_delimiter:{pattern.pattern}")
                break

        # 4. Obfuscation Detection (Base64 check)
        b64_matches = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", prompt)
        for b64 in b64_matches:
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                for pattern in self._compiled_override:
                    if pattern.search(decoded):
                        threat_score += 0.7
                        detected_types.append(InjectionType.OBFUSCATION_ATTACK.value)
                        reasons.append("hidden_base64_injection_payload")
                        break
            except Exception:
                pass

        # Normalize score
        threat_score = min(1.0, threat_score)
        is_safe = threat_score < self.threshold

        if threat_score >= 0.8:
            risk = "CRITICAL"
        elif threat_score >= 0.5:
            risk = "HIGH"
        elif threat_score >= 0.2:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return InjectionResult(
            is_safe=is_safe,
            risk=risk,
            threat_score=round(threat_score, 2),
            detected_types=detected_types,
            reasons=reasons
        )
