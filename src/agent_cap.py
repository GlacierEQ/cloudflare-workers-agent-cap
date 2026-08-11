"""Workers agent capability tokens — attenuating authority without in-place escalation."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


TOKEN_VERSION = 2


def canonical_json(obj: object) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(obj: object) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _token(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(name)
    return value


def _finite(name: str, value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
        raise ValueError(name)
    return float(value)


def _capabilities(values: Iterable[str]) -> frozenset[str]:
    try:
        caps = frozenset(values)
    except TypeError as exc:
        raise ValueError("capabilities") from exc
    if not caps:
        raise ValueError("capabilities")
    for cap in caps:
        _token("capability", cap)
    return caps


class CapVerdict(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class CapToken:
    request_id: str
    capabilities: frozenset[str]
    not_after: float
    mac: str
    not_before: float = 0.0
    issuer_id: str = "local-authority"
    parent_fingerprint: str = ""
    delegation_depth: int = 0
    version: int = TOKEN_VERSION

    def __post_init__(self) -> None:
        _token("request_id", self.request_id)
        object.__setattr__(self, "capabilities", _capabilities(self.capabilities))
        nb = _finite("not_before", self.not_before)
        na = _finite("not_after", self.not_after)
        if na <= nb:
            raise ValueError("validity_window")
        object.__setattr__(self, "not_before", nb)
        object.__setattr__(self, "not_after", na)
        _token("issuer_id", self.issuer_id)
        if not isinstance(self.delegation_depth, int) or isinstance(self.delegation_depth, bool) or self.delegation_depth < 0:
            raise ValueError("delegation_depth")
        if self.parent_fingerprint:
            if len(self.parent_fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in self.parent_fingerprint):
                raise ValueError("parent_fingerprint")
        elif self.delegation_depth != 0:
            raise ValueError("delegation_without_parent")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version != TOKEN_VERSION:
            raise ValueError("token_version")
        if not isinstance(self.mac, str) or len(self.mac) != 64 or any(ch not in "0123456789abcdef" for ch in self.mac):
            raise ValueError("mac")

    def unsigned_body(self) -> dict[str, object]:
        return {
            "version": self.version,
            "request_id": self.request_id,
            "capabilities": sorted(self.capabilities),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "issuer_id": self.issuer_id,
            "parent_fingerprint": self.parent_fingerprint,
            "delegation_depth": self.delegation_depth,
        }

    def fingerprint(self) -> str:
        return digest({**self.unsigned_body(), "mac": self.mac})


@dataclass(frozen=True)
class DelegationReceipt:
    parent_fingerprint: str
    child_fingerprint: str
    issuer_id: str
    child_request_id: str
    removed_capabilities: tuple[str, ...]
    parent_not_before: float
    child_not_before: float
    parent_not_after: float
    child_not_after: float
    parent_depth: int
    child_depth: int
    fingerprint: str


class CapMint:
    def __init__(self, secret: bytes, issuer_id: str = "local-authority"):
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret")
        self._secret = secret
        self.issuer_id = _token("issuer_id", issuer_id)

    def _mac(self, body: dict[str, object]) -> str:
        return hmac.new(
            self._secret,
            canonical_json(body).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _build(
        self,
        request_id: str,
        capabilities: Iterable[str],
        *,
        not_before: float,
        not_after: float,
        parent_fingerprint: str,
        delegation_depth: int,
    ) -> CapToken:
        rid = _token("request_id", request_id)
        caps = _capabilities(capabilities)
        nb = _finite("not_before", not_before)
        na = _finite("not_after", not_after)
        if na <= nb:
            raise ValueError("validity_window")
        body: dict[str, object] = {
            "version": TOKEN_VERSION,
            "request_id": rid,
            "capabilities": sorted(caps),
            "not_before": nb,
            "not_after": na,
            "issuer_id": self.issuer_id,
            "parent_fingerprint": parent_fingerprint,
            "delegation_depth": delegation_depth,
        }
        return CapToken(
            request_id=rid,
            capabilities=caps,
            not_after=na,
            mac=self._mac(body),
            not_before=nb,
            issuer_id=self.issuer_id,
            parent_fingerprint=parent_fingerprint,
            delegation_depth=delegation_depth,
        )

    def mint(
        self,
        request_id: str,
        capabilities: Iterable[str],
        not_after: float,
        not_before: float = 0.0,
    ) -> CapToken:
        return self._build(
            request_id,
            capabilities,
            not_before=not_before,
            not_after=not_after,
            parent_fingerprint="",
            delegation_depth=0,
        )

    def verify(self, token: CapToken) -> bool:
        if not isinstance(token, CapToken):
            return False
        if token.issuer_id != self.issuer_id:
            return False
        try:
            expected = self._mac(token.unsigned_body())
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, token.mac)

    def issue_subcap(
        self,
        parent: CapToken,
        request_id: str,
        capabilities: Iterable[str],
        not_after: float,
        not_before: float | None = None,
    ) -> tuple[CapToken, DelegationReceipt]:
        if not self.verify(parent):
            raise PermissionError("PARENT_TOKEN_INVALID")
        rid = _token("request_id", request_id)
        if rid == parent.request_id:
            raise ValueError("CHILD_REQUEST_ID_MUST_DIFFER")
        child_caps = _capabilities(capabilities)
        if not child_caps.issubset(parent.capabilities):
            raise PermissionError("CAPABILITY_ESCALATION")
        child_nb = parent.not_before if not_before is None else _finite("not_before", not_before)
        child_na = _finite("not_after", not_after)
        if child_nb < parent.not_before or child_na > parent.not_after or child_na <= child_nb:
            raise PermissionError("TIME_ESCALATION")

        child = self._build(
            rid,
            child_caps,
            not_before=child_nb,
            not_after=child_na,
            parent_fingerprint=parent.fingerprint(),
            delegation_depth=parent.delegation_depth + 1,
        )
        receipt = self.delegation_receipt(parent, child)
        return child, receipt

    def verify_delegation(self, parent: CapToken, child: CapToken) -> bool:
        if not self.verify(parent) or not self.verify(child):
            return False
        if child.parent_fingerprint != parent.fingerprint():
            return False
        if child.issuer_id != parent.issuer_id:
            return False
        if child.delegation_depth != parent.delegation_depth + 1:
            return False
        if not child.capabilities.issubset(parent.capabilities):
            return False
        if child.not_before < parent.not_before or child.not_after > parent.not_after:
            return False
        return True

    def delegation_receipt(self, parent: CapToken, child: CapToken) -> DelegationReceipt:
        if not self.verify_delegation(parent, child):
            raise PermissionError("DELEGATION_INVALID")
        removed = tuple(sorted(parent.capabilities - child.capabilities))
        body = {
            "parent_fingerprint": parent.fingerprint(),
            "child_fingerprint": child.fingerprint(),
            "issuer_id": child.issuer_id,
            "child_request_id": child.request_id,
            "removed_capabilities": list(removed),
            "parent_not_before": parent.not_before,
            "child_not_before": child.not_before,
            "parent_not_after": parent.not_after,
            "child_not_after": child.not_after,
            "parent_depth": parent.delegation_depth,
            "child_depth": child.delegation_depth,
        }
        return DelegationReceipt(
            parent_fingerprint=body["parent_fingerprint"],
            child_fingerprint=body["child_fingerprint"],
            issuer_id=child.issuer_id,
            child_request_id=child.request_id,
            removed_capabilities=removed,
            parent_not_before=parent.not_before,
            child_not_before=child.not_before,
            parent_not_after=parent.not_after,
            child_not_after=child.not_after,
            parent_depth=parent.delegation_depth,
            child_depth=child.delegation_depth,
            fingerprint=digest(body),
        )


class AgentCapRuntime:
    def __init__(self, mint: CapMint):
        self._mint = mint

    def invoke(self, token: CapToken, capability: str, now: float) -> tuple[CapVerdict, str | None]:
        if not self._mint.verify(token):
            return CapVerdict.REFUSE, "BAD_MAC"
        try:
            current = _finite("now", now)
            requested = _token("capability", capability)
        except ValueError:
            return CapVerdict.REFUSE, "INVALID_INVOCATION"
        if current < token.not_before:
            return CapVerdict.REFUSE, "NOT_YET_VALID"
        if current > token.not_after:
            return CapVerdict.REFUSE, "EXPIRED"
        if requested not in token.capabilities:
            return CapVerdict.REFUSE, "CAPABILITY_NOT_GRANTED"
        return CapVerdict.ALLOW, None

    def escalate(self, token: CapToken, new_cap: str) -> None:
        """Explicitly unsupported — authority must be issued as a new attenuated subcap."""
        raise RuntimeError("ESCALATION_FORBIDDEN: use issue_subcap with a verified parent")
