"""Indicator: the common currency every detection tier reports into the score.

MODULE_CONTRACT.md §4. Indicator IDs are deterministic FNV-1a hashes of a stable
key so that replaying the same capture through the same modules yields identical
IDs (idempotent replay, §6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# FNV-1a (64-bit) constants.
_FNV64_OFFSET = 0xCBF29CE484222325
_FNV64_PRIME = 0x100000001B3
_MASK64 = (1 << 64) - 1


def fnv1a_64(data: str) -> int:
    """64-bit FNV-1a over the UTF-8 bytes of ``data``."""
    h = _FNV64_OFFSET
    for b in data.encode("utf-8"):
        h ^= b
        h = (h * _FNV64_PRIME) & _MASK64
    return h


def indicator_id(*parts: object) -> str:
    """Deterministic indicator ID from a stable key.

    The caller passes the fields that make the finding unique (module, name,
    path, matched rule, ...). Same key -> same ID across runs, which is what
    makes replay idempotent. The 0-byte separator cannot appear in the string
    parts, so joins are unambiguous.
    """
    key = "\x00".join("" if p is None else str(p) for p in parts)
    return f"{fnv1a_64(key):016x}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MALICIOUS = "malicious"


class Tier(str, Enum):
    STATIC = "static"
    BEHAVIORAL = "behavioral"
    EMULATION = "emulation"
    DISPATCH = "dispatch"


@dataclass
class Indicator:
    id: str  # deterministic FNV-1a of a stable key
    name: str
    severity: Severity
    tier: Tier
    module: str  # which module produced it
    description: str
    attack: list[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    evidence: dict = field(default_factory=dict)  # event refs, matched rule, entitlement, ...

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "tier": self.tier.value,
            "module": self.module,
            "attack": list(self.attack),
            "description": self.description,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Indicator":
        return cls(
            id=d["id"],
            name=d["name"],
            severity=Severity(d["severity"]),
            tier=Tier(d["tier"]),
            module=d["module"],
            attack=list(d.get("attack", [])),
            description=d.get("description", ""),
            evidence=d.get("evidence", {}),
        )
