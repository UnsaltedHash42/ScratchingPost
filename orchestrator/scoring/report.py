"""Minimal Detection Score report (MODULE_CONTRACT.md §5).

Renders a `DetectionScore` as operator-facing text: the verdict and number up top,
then the triggering-indicators breakdown (tier / module / severity / ATT&CK /
evidence) that §5 calls "the operator-facing payload of the whole tool", then the
tier / module / ATT&CK roll-ups. The structured form is `DetectionScore.to_dict()`
(JSON); this is the human view of the same data, no extra computation.
"""

from __future__ import annotations

import json

from ..contracts.sample import Sample
from .score import DetectionScore

_VERDICT_LABEL = {
    "clean": "CLEAN",
    "low": "LOW",
    "suspicious": "SUSPICIOUS",
    "malicious": "MALICIOUS",
}


def _evidence_summary(evidence: dict) -> str:
    """One-line evidence digest — the fields that identify why the indicator fired,
    not a full dump (that lives in the JSON)."""
    if not evidence:
        return ""
    keys = ("rule", "signature_type", "entitlement", "dylib", "spctl_source", "trigger_range")
    parts = [f"{k}={evidence[k]}" for k in keys if k in evidence]
    if not parts:  # fall back to the first couple of fields, whatever they are
        parts = [f"{k}={v}" for k, v in list(evidence.items())[:2]]
    return ", ".join(parts)


def render_report(result: DetectionScore, sample: Sample | None = None, title: str = "ScratchingPost Detection Report") -> str:
    lines: list[str] = []
    lines.append(title)
    lines.append("=" * len(title))
    if sample is not None:
        lines.append(f"sample : {sample.path}")
        lines.append(f"sha256 : {sample.sha256}")
        lines.append(f"size   : {sample.size} bytes")
    verdict = _VERDICT_LABEL.get(result.verdict, result.verdict.upper())
    lines.append(f"verdict: {verdict}   score: {result.score:.0f}/100"
                 f"   ({len(result.triggering)} triggering / {len(result.contributions)} indicators)")
    lines.append("")

    triggering = result.triggering
    if triggering:
        lines.append("Triggering indicators (highest weight first):")
        for c in triggering:
            ind = c.indicator
            attack = " ".join(ind.attack) if ind.attack else "-"
            lines.append(
                f"  [{c.points:5.1f}] {ind.severity.value:<9} {ind.tier.value:<10} "
                f"{ind.module:<16} {ind.name}"
            )
            lines.append(f"          ATT&CK {attack}  |  {ind.description}")
            ev = _evidence_summary(ind.evidence)
            if ev:
                lines.append(f"          evidence: {ev}")
    else:
        lines.append("No triggering indicators (only informational context).")
    lines.append("")

    if result.by_tier:
        lines.append("By tier   : " + ", ".join(
            f"{k}={v:.1f}" for k, v in sorted(result.by_tier.items(), key=lambda kv: -kv[1]) if v > 0))
    if result.by_module:
        lines.append("By module : " + ", ".join(
            f"{k}={v:.1f}" for k, v in sorted(result.by_module.items(), key=lambda kv: -kv[1]) if v > 0))
    if result.by_attack:
        lines.append("By ATT&CK : " + ", ".join(
            f"{k}={v:.1f}" for k, v in sorted(result.by_attack.items(), key=lambda kv: -kv[1])))

    return "\n".join(lines)


def render_json(result: DetectionScore, sample: Sample | None = None, indent: int | None = 2) -> str:
    payload = result.to_dict()
    if sample is not None:
        payload = {"sample": {"path": sample.path, "sha256": sample.sha256, "size": sample.size}, **payload}
    return json.dumps(payload, indent=indent)
