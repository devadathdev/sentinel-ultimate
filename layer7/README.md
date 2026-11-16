# Layer 7 — Execution Sandbox

Layer 7 enforces deny-by-default execution boundaries, lexical command sanitization, and containerized sandbox attestation for all agent and workflow execution requests.

## Controls

1. **Lexical Anti-Evasion Command Parser (`SafeCommandParser`)**:
   - Parses tokens with `shlex` and verifies commands against a strict binary and argument allowlist.
   - Detects and categorically blocks command chaining (`;`, `&&`, `||`, `&`), pipelines (`|`), subshell executions (`sh`, `bash`, `powershell`), command substitutions (`` ` ``, `$()`), and I/O redirections (`>`, `<`).
   - Disallows arbitrary code evaluation flags (`-c`, `--override-ini`).

2. **Sandbox Boundary Enforcement**:
   - Unsandboxed execution requests (`sandbox=False`) are rejected immediately as `CRITICAL` violations.
   - Only caller roles `developer` and `admin` may request execution authorization.

3. **Cryptographically Attested Execution Tickets (`ExecutionTicket`)**:
   - Authorized execution requests receive an HMAC-SHA256 signed ticket with bounded lifespan (default 30 seconds) and container cgroup quotas (1.0 CPU, 512MB RAM).

4. **Hardened Seccomp & Container Profiles**:
   - Includes standard Linux seccomp profile (`layer7/seccomp/sentinel-default.json`) blocking dangerous syscalls (`ptrace`, `bpf`, `mount`, `chroot`, `reboot`, `keyctl`).
