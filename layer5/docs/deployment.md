# Layer 5 Deployment and Operational Guide

## Pipeline Integration

Layer 5 operates in two stages:
1. **Pre-Execution (Inbound Guard)**:
   - When an agent prompt or tool call is received, invoke `PromptGuard.scan_prompt()` and `AIToolPolicyEngine.evaluate()`.
   - If `allow=False` or `action="REQUIRE_APPROVAL"`, halt autonomous execution and route to the approval queue.
2. **Post-Execution (Outbound Guard)**:
   - Before model completions or tool outputs are returned to the user or external network, pass through `DataLossPreventer.scan()`.
   - If leaks are found, redact using `DataLossPreventer.redact()`.

## Multi-Agent Swarm Governance

When multiple agents collaborate across message boards or subagents:
- Enforce caller identity tagging (`identity="brahma-agent-1"`, `role="developer"`).
- Never allow an untrusted subagent to inherit administrative execution rights without explicit human approval.
