"""Apple built-in emulation module (modules/emulation/apple_builtin.py).

The YARA matcher and the spctl runner are both injected, so these run on any host
with no libyara and no macOS tools."""

from orchestrator.contracts.indicator import Tier
from orchestrator.contracts.sample import Sample
from modules.emulation.apple_builtin import (
    AppleBuiltinModule,
    YaraMatch,
    YaraStringHit,
    bisect_trigger,
)

from tests.test_code_identity import make_runner, PLATFORM_DV, DEVID_DV


def _sample(tmp_path, data: bytes) -> Sample:
    p = tmp_path / "payload.bin"
    p.write_bytes(data)
    return Sample.from_path(str(p))


# -- bisect_trigger ----------------------------------------------------------
def _substr_matcher(needle: bytes, rule: str) -> "callable":
    """Fake matcher: fires `rule` iff `needle` survives intact in the buffer."""
    def match(buf: bytes):
        idx = buf.find(needle)
        if idx < 0:
            return []
        return [YaraMatch(rule=rule, strings=[YaraStringHit(offset=idx, identifier="$s")])]
    return match


def test_bisect_narrows_to_exact_trigger_span():
    data = b"\x00" * 40 + b"EVILSIG" + b"\x00" * 40
    matcher = _substr_matcher(b"EVILSIG", "R")
    window = bisect_trigger(data, "R", matcher)
    assert window == (40, 47)  # exactly the needle span; zeroing either end breaks it


def test_bisect_returns_none_when_no_match():
    matcher = _substr_matcher(b"EVILSIG", "R")
    assert bisect_trigger(b"harmless", "R", matcher) is None


def test_bisect_preserves_offset_gated_rule():
    # Condition-only rule that needs byte0==0xCA AND a marker later; zeroing must
    # keep offset 0 intact, so the window spans from 0 through the marker.
    data = b"\xca" + b"\x00" * 20 + b"MARK" + b"\x00" * 10

    def matcher(buf):
        if buf[:1] == b"\xca" and b"MARK" in buf:
            return [YaraMatch(rule="COND")]  # no strings -> forces bisect fallback
        return []

    window = bisect_trigger(data, "COND", matcher)
    assert window is not None
    lo, hi = window
    assert lo == 0 and hi == 25  # 0..(offset of MARK end)


# -- module: XProtect signature ---------------------------------------------
def test_xprotect_match_emits_malicious_emulation_indicator(tmp_path):
    data = b"MZ junk EVILSIG more junk"
    sample = _sample(tmp_path, data)
    matcher = _substr_matcher(b"EVILSIG", "XProtect_MACOS_Test")
    # spctl accepts (irrelevant to the XProtect hit); platform-style output.
    mod = AppleBuiltinModule(matcher=matcher, runner=make_runner(DEVID_DV))
    inds = list(mod.scan_static(sample))

    xp = [i for i in inds if i.name == "xprotect-signature-match"]
    assert len(xp) == 1
    ind = xp[0]
    assert ind.severity.value == "malicious"
    assert ind.tier == Tier.EMULATION
    assert ind.evidence["rule"] == "XProtect_MACOS_Test"
    assert ind.evidence["trigger_range"] == [data.index(b"EVILSIG"), data.index(b"EVILSIG")]


def test_clean_sample_no_xprotect_indicator(tmp_path):
    sample = _sample(tmp_path, b"totally benign bytes")
    matcher = _substr_matcher(b"EVILSIG", "X")
    mod = AppleBuiltinModule(matcher=matcher, runner=make_runner(DEVID_DV))
    inds = list(mod.scan_static(sample))
    assert not any(i.name == "xprotect-signature-match" for i in inds)


# -- module: Gatekeeper verdict ---------------------------------------------
def test_gatekeeper_block_indicator(tmp_path):
    sample = _sample(tmp_path, b"benign")
    matcher = _substr_matcher(b"EVILSIG", "X")  # no XProtect hit
    runner = make_runner(
        (1, "/tmp/x: code object is not signed at all"),
        spctl=("rejected", 3, "source=no usable signature"),
    )
    mod = AppleBuiltinModule(matcher=matcher, runner=runner)
    inds = list(mod.scan_static(sample))
    block = [i for i in inds if i.name == "gatekeeper-block"]
    assert len(block) == 1
    assert block[0].severity.value == "high"
    assert block[0].tier == Tier.EMULATION


def test_gatekeeper_accept_indicator(tmp_path):
    sample = _sample(tmp_path, b"benign")
    matcher = _substr_matcher(b"EVILSIG", "X")
    mod = AppleBuiltinModule(
        matcher=matcher,
        runner=make_runner(DEVID_DV, spctl=("accepted", 0, "source=Notarized Developer ID")),
    )
    inds = list(mod.scan_static(sample))
    assert any(i.name == "gatekeeper-accept" and i.severity.value == "info" for i in inds)


def test_platform_binary_not_flagged_by_gatekeeper(tmp_path):
    # spctl declines a bare platform binary ("not an app"); not a block.
    sample = _sample(tmp_path, b"benign")
    matcher = _substr_matcher(b"EVILSIG", "X")
    mod = AppleBuiltinModule(
        matcher=matcher,
        runner=make_runner(
            PLATFORM_DV,
            spctl=("rejected (the code is valid but does not seem to be an app)", 3,
                   "origin=Software Signing"),
        ),
    )
    inds = list(mod.scan_static(sample))
    assert not any(i.name.startswith("gatekeeper-") for i in inds)


def test_indicator_ids_are_deterministic(tmp_path):
    data = b"x EVILSIG y"
    sample = _sample(tmp_path, data)
    matcher = _substr_matcher(b"EVILSIG", "R")
    a = list(AppleBuiltinModule(matcher=matcher, runner=make_runner(DEVID_DV)).scan_static(sample))
    b = list(AppleBuiltinModule(matcher=matcher, runner=make_runner(DEVID_DV)).scan_static(sample))
    assert [i.id for i in a] == [i.id for i in b]


# -- live path (real libyara + real on-disk XProtect); self-skips otherwise ----
def test_live_xprotect_detects_eicar(tmp_path):
    import pytest
    yara = pytest.importorskip("yara")  # noqa: F841
    from pathlib import Path
    from modules.emulation.apple_builtin import XPROTECT_YARA, xprotect_matcher

    if not Path(XPROTECT_YARA).exists():
        pytest.skip("on-disk XProtect.yara not present (non-macOS host)")

    matcher = xprotect_matcher()  # compiles Apple's real rules
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert matcher(b"harmless bytes, no signature") == []
    hits = matcher(eicar)
    assert any(h.rule == "EICAR" for h in hits), "Apple XProtect ships an EICAR rule"

    sample = _sample(tmp_path, eicar)
    inds = list(AppleBuiltinModule().scan_static(sample))
    xp = [i for i in inds if i.name == "xprotect-signature-match"]
    assert xp and xp[0].evidence["rule"] == "EICAR"
    assert xp[0].severity.value == "malicious"
