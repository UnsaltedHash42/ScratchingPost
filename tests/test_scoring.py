"""Detection Score aggregation + report (MODULE_CONTRACT.md §5)."""

from orchestrator.contracts.indicator import Indicator, Severity, Tier, indicator_id
from orchestrator.scoring import (
    SEVERITY_WEIGHT,
    TIER_WEIGHT,
    DetectionScore,
    render_json,
    render_report,
    score_indicators,
)


def _ind(name, severity, tier, module="m", attack=None, evidence=None):
    return Indicator(
        id=indicator_id(module, name, severity.value, tier.value),
        name=name,
        severity=severity,
        tier=tier,
        module=module,
        description=f"{name} fired",
        attack=attack or [],
        evidence=evidence or {},
    )


def test_empty_is_clean_zero():
    s = score_indicators([])
    assert s.score == 0.0
    assert s.verdict == "clean"
    assert s.triggering == []


def test_info_does_not_contribute():
    s = score_indicators([_ind("apple-platform-binary", Severity.INFO, Tier.STATIC)])
    assert s.score == 0.0
    assert s.verdict == "clean"
    assert s.triggering == []  # zero-weight context is filtered from the breakdown
    assert len(s.contributions) == 1  # but still recorded


def test_malicious_severity_floors_verdict():
    # A single XProtect emulation hit: 20 * 1.5 = 30 points, below the malicious
    # score threshold, but a malicious-severity indicator convicts regardless.
    s = score_indicators([_ind("xprotect", Severity.MALICIOUS, Tier.EMULATION, "emulation.apple")])
    assert s.score == SEVERITY_WEIGHT[Severity.MALICIOUS] * TIER_WEIGHT[Tier.EMULATION]  # 30
    assert s.verdict == "malicious"


def test_emulation_weighs_more_than_static_for_same_severity():
    stat = score_indicators([_ind("gk", Severity.HIGH, Tier.STATIC)]).score
    emu = score_indicators([_ind("gk", Severity.HIGH, Tier.EMULATION)]).score
    assert emu > stat
    assert emu == 8.0 * TIER_WEIGHT[Tier.EMULATION]


def test_thresholds_map_to_verdicts():
    assert score_indicators([_ind("a", Severity.LOW, Tier.STATIC)]).verdict == "clean"      # 1 -> clean
    assert score_indicators([_ind("a", Severity.MEDIUM, Tier.STATIC)]).verdict == "low"     # 3 -> low
    assert score_indicators([_ind("a", Severity.HIGH, Tier.EMULATION)]).verdict == "suspicious"  # 12
    # High-density stack of static highs saturates to a malicious score.
    many = [_ind(f"h{i}", Severity.HIGH, Tier.STATIC) for i in range(10)]
    assert score_indicators(many).verdict == "malicious"  # 80 -> >= 60


def test_score_saturates_at_100():
    many = [_ind(f"m{i}", Severity.MALICIOUS, Tier.DISPATCH) for i in range(20)]
    assert score_indicators(many).score == 100.0


def test_breakdowns_sum_by_tier_module_attack():
    inds = [
        _ind("unsigned", Severity.HIGH, Tier.STATIC, "static.macho", ["T1553.001"]),
        _ind("adhoc", Severity.MEDIUM, Tier.STATIC, "static.macho", ["T1553.001"]),
        _ind("xprotect", Severity.MALICIOUS, Tier.EMULATION, "emulation.apple"),
    ]
    s = score_indicators(inds)
    assert s.by_tier["static"] == 8.0 + 3.0
    assert s.by_tier["emulation"] == 30.0
    assert s.by_module["static.macho"] == 11.0
    assert s.by_attack["T1553.001"] == 11.0  # both static hits carry the technique


def test_contributions_sorted_by_points_desc():
    inds = [
        _ind("low", Severity.LOW, Tier.STATIC),
        _ind("mal", Severity.MALICIOUS, Tier.EMULATION),
        _ind("med", Severity.MEDIUM, Tier.STATIC),
    ]
    pts = [c.points for c in score_indicators(inds).contributions]
    assert pts == sorted(pts, reverse=True)
    assert pts[0] == 30.0


def test_deterministic_score_and_order():
    inds = [
        _ind("a", Severity.HIGH, Tier.STATIC),
        _ind("b", Severity.MEDIUM, Tier.EMULATION),
    ]
    a = score_indicators(inds)
    b = score_indicators(list(reversed(inds)))
    assert a.score == b.score
    assert [c.indicator.id for c in a.contributions] == [c.indicator.id for c in b.contributions]


def test_custom_weights_retune_without_forking():
    ind = [_ind("x", Severity.HIGH, Tier.BEHAVIORAL)]
    louder = score_indicators(ind, tier_weight={**TIER_WEIGHT, Tier.BEHAVIORAL: 5.0})
    assert louder.score == 8.0 * 5.0


def test_report_leads_with_verdict_and_lists_triggers():
    inds = [
        _ind("unsigned-binary", Severity.HIGH, Tier.STATIC, "static.macho", ["T1553.001"],
             {"signature_type": "unsigned"}),
        _ind("xprotect-signature-match", Severity.MALICIOUS, Tier.EMULATION, "emulation.apple",
             evidence={"rule": "MACOS.EICAR"}),
        _ind("apple-platform-binary", Severity.INFO, Tier.STATIC),
    ]
    text = render_report(score_indicators(inds))
    assert "MALICIOUS" in text
    assert "xprotect-signature-match" in text
    assert "T1553.001" in text
    assert "rule=MACOS.EICAR" in text
    # INFO context is not a triggering line.
    assert "apple-platform-binary" not in text


def test_render_json_round_trips_with_sample():
    from orchestrator.contracts.sample import Sample

    sample = Sample(path="/tmp/x", sha256="ab" * 32, size=10)
    s = score_indicators([_ind("x", Severity.HIGH, Tier.EMULATION)])
    import json
    payload = json.loads(render_json(s, sample=sample))
    assert payload["sample"]["sha256"] == "ab" * 32
    assert payload["verdict"] == s.verdict
    assert payload["score"] == round(s.score, 2)
    assert isinstance(payload["contributions"], list)
