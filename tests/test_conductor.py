"""End-to-end conductor integration (orchestrator/conductor.py).

Drives the whole Phase-1 chain in one `analyze()` call over a real fixture Mach-O
plus a real eslogger capture: static + Apple-builtin emulation on the sample
bytes, the detonation seam for telemetry (replay-backed), the behavioral pipeline,
aggregation into one Detection Score, and the rendered report. Every external
boundary is injected, so it runs on any host — no VM, no libyara, no macOS tools.

Where the per-tier tests use synthetic indicators, this asserts the tiers actually
compose: real bytes through static+emulation, a real ESF capture through the
behavioral pipeline, into one verdict.
"""

from pathlib import Path

import pytest

from modules.emulation.apple_builtin import YaraMatch, YaraStringHit
from orchestrator import analyze
from orchestrator.contracts.indicator import Tier
from orchestrator.contracts.sample import Sample
from orchestrator.detonation import LocalAppliance, capture_dir_resolver
from orchestrator.pipeline import write_capture
from sensors.eslogger.parser import parse_stream

from tests.support import ExecWatchModule
from tests.test_code_identity import ADHOC_DV, make_runner

FIX = Path(__file__).parent / "fixtures"
MACHO = FIX / "macho"
ESLOGGER = FIX / "eslogger"


def _adhoc_runner():
    """adhoc signature + spctl block -> adhoc-signed (static) + gatekeeper-block
    (emulation)."""
    return make_runner(ADHOC_DV, spctl=("rejected", 3, "source=no usable signature"))


def _xprotect_matcher(needle: bytes = b"__TEXT", rule: str = "XProtect_MACOS_Fixture"):
    """Fake XProtect matcher: fires `rule` on any Mach-O (every Mach-O carries a
    __TEXT segment name), so the emulation tier's YARA path is exercised offline."""

    def match(buf: bytes):
        idx = buf.find(needle)
        if idx < 0:
            return []
        return [YaraMatch(rule=rule, strings=[YaraStringHit(offset=idx, identifier="$s")])]

    return match


def _eslogger_backed_appliance(tmp_path, raw_fixture: Path) -> LocalAppliance:
    """Convert a real *raw* eslogger capture to the uniform schema (what the live
    seam does host-side) and serve it from the replay-backed appliance."""
    uniform = tmp_path / "apple.jsonl"
    write_capture(uniform, parse_stream(raw_fixture.read_text().splitlines()))
    return LocalAppliance(capture_resolver=capture_dir_resolver({"apple": str(uniform)}))


def test_analyze_runs_full_phase1_chain(tmp_path):
    sample = Sample.from_path(str(MACHO / "hijackable_arm64"))
    env = _eslogger_backed_appliance(tmp_path, ESLOGGER / "sample_capture.jsonl")

    result = analyze(
        sample,
        "apple",
        env,
        behavioral_modules=[ExecWatchModule()],
        runner=_adhoc_runner(),
        matcher=_xprotect_matcher(),
        timeout=2.0,
    )

    names = {i.name for i in result.indicators}
    tiers = {i.tier for i in result.indicators}

    # Static tier fired on the real Mach-O bytes.
    assert "adhoc-signed" in names
    assert "weak-dylib-load" in names
    assert Tier.STATIC in tiers

    # The Gatekeeper verdict now comes ONLY from the emulation tier (no static
    # double-count); emulation also produced the XProtect hit.
    assert "gatekeeper-rejected" not in names
    assert "gatekeeper-block" in names
    assert "xprotect-signature-match" in names
    assert Tier.EMULATION in tiers

    # Behavioral tier consumed the ESF telemetry: the capture's exec carries
    # DYLD_INSERT_LIBRARIES, which ExecWatchModule flags.
    assert "exec-observed" in names
    assert Tier.BEHAVIORAL in tiers

    # Telemetry was actually collected through the seam.
    assert result.events
    assert any(e.event_type.value == "exec" for e in result.events)

    # One aggregate verdict: a malicious-severity XProtect hit convicts.
    assert result.verdict == "malicious"
    assert result.score.score > 0

    # The report leads with the verdict and lists a triggering indicator.
    report = result.report()
    assert "MALICIOUS" in report
    assert "xprotect-signature-match" in report


def test_analyze_reverts_env(tmp_path):
    # After analyze the run's bookkeeping is gone (revert ran) — lab left clean.
    sample = Sample.from_path(str(MACHO / "thin_arm64"))
    env = _eslogger_backed_appliance(tmp_path, ESLOGGER / "sample_capture.jsonl")
    result = analyze(
        sample, "apple", env, runner=_adhoc_runner(), matcher=_xprotect_matcher(), timeout=1.0
    )
    with pytest.raises(KeyError):
        env.collect(result.run_id)


def test_analyze_shares_one_code_identity_assessment(tmp_path):
    # The two default static modules must not each shell codesign/spctl. With the
    # conductor assessing identity once and injecting it, the tool boundary is hit
    # exactly 4 times (codesign, entitlements, spctl, xattr), not 8.
    sample = Sample.from_path(str(MACHO / "hijackable_arm64"))
    env = _eslogger_backed_appliance(tmp_path, ESLOGGER / "sample_capture.jsonl")

    calls: list[list[str]] = []
    base = _adhoc_runner()

    def counting_runner(argv):
        calls.append(list(argv))
        return base(argv)

    analyze(
        sample, "apple", env, runner=counting_runner, matcher=_xprotect_matcher(), timeout=1.0
    )
    tools = [c[0] for c in calls]
    assert tools == ["codesign", "codesign", "spctl", "xattr"]


def test_analyze_no_behavioral_modules_still_scores(tmp_path):
    # Static + emulation only (no behavioral modules) still produces a verdict.
    sample = Sample.from_path(str(MACHO / "hijackable_arm64"))
    env = _eslogger_backed_appliance(tmp_path, ESLOGGER / "sample_capture.jsonl")
    result = analyze(
        sample, "apple", env, runner=_adhoc_runner(), matcher=_xprotect_matcher(), timeout=1.0
    )
    assert result.verdict == "malicious"
    assert not any(i.tier == Tier.BEHAVIORAL for i in result.indicators)


def test_analyze_wires_dispatch_module_own_profile(tmp_path):
    # A dispatch module detonates its OWN profile (wazuh) via its OWN seam, separate
    # from the conductor's apple behavioral detonation, and its agent alerts land in
    # the one aggregate score as dispatch-tier indicators.
    from modules.dispatch import WazuhAlert, WazuhModule

    sample = Sample.from_path(str(MACHO / "thin_arm64"))
    env = _eslogger_backed_appliance(tmp_path, ESLOGGER / "sample_capture.jsonl")

    class DispatchEnv:
        def __init__(self):
            self.profiles = []

        def detonate(self, sample, profile, timeout):
            self.profiles.append(profile)
            return "drun"

        def revert(self, profile):
            self.profiles.append(("revert", profile))

    denv = DispatchEnv()
    alert = WazuhAlert(rule_id="100002", level=12, description="ptrace attach",
                       mitre=["T1055.008"], agent="wazuh-guest")

    class Backend:
        def alerts_since(self, since, *, agent=None):
            return [alert]

    wazuh = WazuhModule(denv, Backend(), agent="wazuh-guest")

    result = analyze(
        sample, "apple", env,
        dispatch_modules=[wazuh],
        runner=_adhoc_runner(), matcher=_xprotect_matcher(), timeout=1.0,
    )

    # The dispatch module ran its own profile, not the apple behavioral one.
    assert denv.profiles[0] == "wazuh"
    dispatch = [i for i in result.indicators if i.tier is Tier.DISPATCH]
    assert dispatch and dispatch[0].module == "dispatch.wazuh"
    assert dispatch[0].attack == ["T1055.008"]
