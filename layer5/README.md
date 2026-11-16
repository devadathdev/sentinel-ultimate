# Layer 5 — AI Firewall

Layer 5 provides comprehensive runtime protection, tool governance, and data sanitization for LLM/AI agent ecosystems (such as Brahma, Jarvis, and Thara).

## Controls

1. **Prompt Injection & Jailbreak Defense (`PromptGuard`)**:
   - Detects direct prompt overrides ("ignore previous instructions", "disregard all rules", "DAN mode").
   - Blocks roleplay jailbreaks ("act as an unfiltered hacker", "pretend you have no rules").
   - Defends against control delimiter injection (`<|im_start|>`, `[INST]`, `SYSTEM:`).
   - Inspects and decodes hidden base64-encoded injection payloads.

2. **Tool Governance & Multi-Stage Approval (`AIToolPolicyEngine`)**:
   - Five-tier risk classification: `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
   - Deep argument inspection for path traversal (`../`), cloud metadata SSRF (`169.254.169.254`), and destructive shell fragments.
   - Dual-control authorization requiring multiple distinct approvers and MFA verification for critical actions (`delete_database`, `force_push`).

3. **Data Loss Prevention & Output Redactor (`DataLossPreventer`)**:
   - Scans outbound model and tool responses for leaked API keys, tokens, and private keys.
   - Verifies and catches credit card numbers (with Luhn checksum validation), SSNs, and emails.
   - Built-in redaction engine replacing sensitive data with typed redaction markers.

## Production Rule

Do not permit AI models direct unsanitized tool execution. Every action request must pass through Layer 5 policy evaluation before reaching Layer 7 (Execution Sandbox).
