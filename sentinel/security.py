from __future__ import annotations
import base64, json, os, time, hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import settings

class EncryptedEventStore:
    def __init__(self, path=None):
        key_b64 = settings.master_key
        if not key_b64:
            self.key = None
        else:
            self.key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
            if len(self.key) != 32:
                raise ValueError("SENTINEL_MASTER_KEY must decode to exactly 32 bytes")
        self.path = path or settings.event_store_path

    def append(self, event: dict):
        if not self.key:
            # Safe development fallback: do not pretend this is encrypted.
            with open(self.path.replace('.enc', '.jsonl'), 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
            return
        aes = AESGCM(self.key)
        nonce = os.urandom(12)
        plaintext = json.dumps(event, separators=(",", ":")).encode()
        ciphertext = aes.encrypt(nonce, plaintext, None)
        with open(self.path, 'ab') as f:
            f.write(base64.b64encode(nonce + ciphertext) + b"\n")

class RateLimiter:
    def __init__(self, limit: int):
        self.limit = limit
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

@dataclass(frozen=True)
class Decision:
    allow: bool
    action: str
    reason: str
    risk: str

class PolicyEngine:
    HIGH_RISK_TOOLS = {"shell", "deploy", "force_push", "delete", "secrets", "network_admin"}
    SAFE_TOOLS = {"web_search", "read_file", "read_project", "create_code"}

    def authorize(self, *, identity: str, role: str, method: str, path: str, body_size: int, zone: str) -> Decision:
        if not identity:
            return Decision(False, "BLOCK", "missing_identity", "HIGH")
        if body_size > settings.max_body_bytes:
            return Decision(False, "BLOCK", "request_too_large", "MEDIUM")
        if zone not in {"user", "ai", "server", "iot", "management"}:
            return Decision(False, "BLOCK", "unknown_zone", "HIGH")
        if zone == "management" and role != "admin":
            return Decision(False, "BLOCK", "management_requires_admin", "CRITICAL")
        if method.upper() not in {"GET", "POST"}:
            return Decision(False, "BLOCK", "method_not_allowed", "MEDIUM")
        return Decision(True, "ALLOW", "policy_pass", "LOW")

    def authorize_tool(self, *, identity: str, role: str, tool: str, approved: bool) -> Decision:
        if not identity:
            return Decision(False, "BLOCK", "missing_identity", "HIGH")
        if tool in self.SAFE_TOOLS:
            return Decision(True, "ALLOW", "safe_tool", "LOW")
        if tool in self.HIGH_RISK_TOOLS:
            if role == "admin" and approved:
                return Decision(True, "ALLOW", "explicit_high_risk_approval", "HIGH")
            return Decision(False, "REQUIRE_APPROVAL", "high_risk_tool_requires_explicit_approval", "HIGH")
        return Decision(False, "BLOCK", "unknown_tool_denied_by_default", "HIGH")

    def authorize_execution(self, *, identity: str, role: str, command: str, sandbox: bool) -> Decision:
        if not sandbox:
            return Decision(False, "BLOCK", "execution_requires_sandbox", "CRITICAL")
        if role not in {"developer", "admin"}:
            return Decision(False, "BLOCK", "role_cannot_execute", "HIGH")
        allowed_prefixes = ("python -m pytest", "python -m compileall", "git status", "git diff")
        if not command.startswith(allowed_prefixes):
            return Decision(False, "REQUIRE_APPROVAL", "command_not_on_safe_allowlist", "HIGH")
        return Decision(True, "ALLOW", "sandboxed_allowlisted_command", "MEDIUM")

def event_id(event: dict) -> str:
    raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()
