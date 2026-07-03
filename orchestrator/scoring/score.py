"""Detection Score aggregation (MODULE_CONTRACT.md §5).

Adapted from LitterBox's detection-score model (https://github.com/BlackSnufkin/LitterBox,
credited in the README): weight each indicator, sum, saturate to a 0-100 score, and
map to a verdict. What changes from LitterBox is the *inputs* — the macOS signals are
code-identity, XProtect/Gatekeeper emulation, and ESF behavior rather than Windows AV
and sandbox telemetry — not the shape.

The score is deliberately a thin, tunable function of the `Indicator`s the tiers emit:

  points(indicator) = SEVERITY_WEIGHT[severity] * TIER_WEIGHT[tier]
  raw   = sum(points)
  score = min(100, raw)                       # a couple of strong hits saturate
  verdict = threshold(score), floored to `malicious` by any malicious-severity hit

The operator-facing payload is not the number but the **triggering-indicators
breakdown**: every contributing indicator with its tier, module, severity, ATT&CK
techniques, evidence, and the points it added, plus roll-ups by tier, module, and
ATT&CK technique. `report.py` renders it.

Weighting posture follows §5: emulation (Apple/Elastic mirror production detection)
and dispatch (real agents) weigh heaviest; static code-identity failures weigh heavy
(they gate whether the thing runs); behavioral heuristics corroborate. Every weight is
a plain dict argument so a caller can retune without touching the aggregation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..contracts.indicator import Indicator, Severity, Tier

# Per-severity base weight. INFO carries no weight (it is context, not a finding).
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 8.0,
    Severity.MALICIOUS: 20.0,
}

# Per-tier multiplier (§5 posture). Emulation and dispatch mirror production
# detection; static gates execution; behavioral corroborates.
TIER_WEIGHT: dict[Tier, float] = {
    Tier.STATIC: 1.0,
    Tier.BEHAVIORAL: 0.75,
    Tier.EMULATION: 1.5,
    Tier.DISPATCH: 2.0,
}

# Score thresholds -> verdict. A malicious-severity indicator floors the verdict at
# `malicious` regardless of the numeric score (a single Apple XProtect hit is a
# conviction, not a corroborating point).
# A single HIGH emulation hit (e.g. a Gatekeeper block: 8 * 1.5 = 12) reaches
# `suspicious`; a lone HIGH static finding (8, e.g. merely unsigned) stays `low`.
_MALICIOUS_AT = 60.0
_SUSPICIOUS_AT = 12.0
_LOW_AT = 3.0


@dataclass
class Contribution:
    """One indicator's contribution to the score: the finding plus the points it
    added. Ordered highest-points-first in the result so the report leads with what
    moved the needle."""

    indicator: Indicator
    points: float

    def to_dict(self) -> dict:
        return {"points": round(self.points, 2), "indicator": self.indicator.to_dict()}


@dataclass
class DetectionScore:
    """The aggregate verdict over a run's indicators, with the triggering breakdown."""

    score: float                                   # 0-100, saturating
    verdict: str                                   # clean | low | suspicious | malicious
    contributions: list[Contribution] = field(default_factory=list)
    by_tier: dict[str, float] = field(default_factory=dict)
    by_module: dict[str, float] = field(default_factory=dict)
    by_attack: dict[str, float] = field(default_factory=dict)

    @property
    def triggering(self) -> list[Contribution]:
        """Indicators that actually added points (drops INFO/zero-weight context)."""
        return [c for c in self.contributions if c.points > 0]

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "verdict": self.verdict,
            "counts": {
                "indicators": len(self.contributions),
                "triggering": len(self.triggering),
            },
            "by_tier": {k: round(v, 2) for k, v in self.by_tier.items()},
            "by_module": {k: round(v, 2) for k, v in self.by_module.items()},
            "by_attack": {k: round(v, 2) for k, v in self.by_attack.items()},
            "contributions": [c.to_dict() for c in self.contributions],
        }


def _verdict(score: float, indicators: list[Indicator]) -> str:
    if any(i.severity == Severity.MALICIOUS for i in indicators):
        return "malicious"
    if score >= _MALICIOUS_AT:
        return "malicious"
    if score >= _SUSPICIOUS_AT:
        return "suspicious"
    if score >= _LOW_AT:
        return "low"
    return "clean"


def score_indicators(
    indicators: "list[Indicator] | tuple[Indicator, ...]",
    *,
    severity_weight: dict[Severity, float] | None = None,
    tier_weight: dict[Tier, float] | None = None,
) -> DetectionScore:
    """Aggregate indicators into a `DetectionScore` (MODULE_CONTRACT.md §5).

    Deterministic: identical indicators (same deterministic IDs on replay) always
    produce the same score and ordering, so a report is reproducible. Weight tables
    are injectable for retuning without forking the aggregation."""
    sev_w = severity_weight or SEVERITY_WEIGHT
    tier_w = tier_weight or TIER_WEIGHT

    contribs: list[Contribution] = []
    by_tier: dict[str, float] = defaultdict(float)
    by_module: dict[str, float] = defaultdict(float)
    by_attack: dict[str, float] = defaultdict(float)

    for ind in indicators:
        points = sev_w.get(ind.severity, 0.0) * tier_w.get(ind.tier, 1.0)
        contribs.append(Contribution(indicator=ind, points=points))
        by_tier[ind.tier.value] += points
        by_module[ind.module] += points
        for technique in ind.attack:
            by_attack[technique] += points

    # Lead with the biggest movers; break ties deterministically by indicator id.
    contribs.sort(key=lambda c: (-c.points, c.indicator.id))

    raw = sum(c.points for c in contribs)
    score = min(100.0, raw)
    verdict = _verdict(score, list(indicators))

    return DetectionScore(
        score=score,
        verdict=verdict,
        contributions=contribs,
        by_tier=dict(by_tier),
        by_module=dict(by_module),
        by_attack={k: v for k, v in by_attack.items() if v > 0},
    )
