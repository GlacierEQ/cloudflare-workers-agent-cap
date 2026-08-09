
"""Workers agent capability tokens — no mid-request escalation."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CapVerdict(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CapToken:
    request_id: str
    capabilities: frozenset[str]
    not_after: float
    mac: str

    def fingerprint(self) -> str:
        return digest({"rid": self.request_id, "caps": sorted(self.capabilities), "na": self.not_after, "mac": self.mac})


class CapMint:
    def __init__(self, secret: bytes):
        self._secret = secret

    def mint(self, request_id: str, capabilities: set[str], not_after: float) -> CapToken:
        caps = frozenset(capabilities)
        body = f"{request_id}|{'|'.join(sorted(caps))}|{not_after}"
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return CapToken(request_id, caps, not_after, mac)

    def verify(self, token: CapToken) -> bool:
        body = f"{token.request_id}|{'|'.join(sorted(token.capabilities))}|{token.not_after}"
        exp = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(exp, token.mac)


class AgentCapRuntime:
    def __init__(self, mint: CapMint):
        self._mint = mint

    def invoke(self, token: CapToken, capability: str, now: float) -> tuple[CapVerdict, str | None]:
        if not self._mint.verify(token):
            return CapVerdict.REFUSE, "BAD_MAC"
        if now > token.not_after:
            return CapVerdict.REFUSE, "EXPIRED"
        if capability not in token.capabilities:
            return CapVerdict.REFUSE, "CAPABILITY_NOT_GRANTED"
        return CapVerdict.ALLOW, None

    def escalate(self, token: CapToken, new_cap: str) -> None:
        """Explicitly unsupported — mid-request escalation is forbidden."""
        raise RuntimeError("ESCALATION_FORBIDDEN: mint a new token for a new request scope")
