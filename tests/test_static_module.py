"""Static module end-to-end: a real Mach-O fixture through scan_static, with the
code-identity subprocess boundary faked so it runs anywhere."""

from pathlib import Path

from orchestrator.contracts.module import ModuleCaps
from orchestrator.contracts.sample import Sample
from modules.static import StaticMachOModule

from tests.test_code_identity import ADHOC_DV, PLATFORM_DV, make_runner

FIX = Path(__file__).parent / "fixtures" / "macho"


def _adhoc_runner():
    return make_runner(ADHOC_DV, spctl=("rejected", 3, "source=no usable signature"))


def _platform_runner():
    return make_runner(
        PLATFORM_DV,
        spctl=("rejected (the code is valid but does not seem to be an app)", 3, "origin=Software Signing"),
    )


def test_capabilities_is_static_only():
    m = StaticMachOModule()
    assert m.capabilities() is ModuleCaps.STATIC


def test_scan_hijackable_produces_expected_indicators():
    sample = Sample.from_path(str(FIX / "hijackable_arm64"))
    mod = StaticMachOModule(runner=_adhoc_runner())
    inds = list(mod.scan_static(sample))
    names = {i.name for i in inds}

    assert "adhoc-signed" in names
    # The Gatekeeper/spctl verdict is emitted only by the Apple emulation tier now
    # (see the Gatekeeper decision note in modules/static/module.py); the static
    # tier reports signing posture, not the runtime verdict.
    assert "gatekeeper-rejected" not in names
    assert "weak-dylib-load" in names      # weak CoreFoundation
    # dylib-hijack indicators carry the ATT&CK tag
    hijack = [i for i in inds if i.name == "weak-dylib-load"]
    assert hijack and hijack[0].attack == ["T1574.004"]


def test_indicator_ids_stable_across_scans():
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    ids1 = sorted(i.id for i in StaticMachOModule(runner=_adhoc_runner()).scan_static(sample))
    ids2 = sorted(i.id for i in StaticMachOModule(runner=_adhoc_runner()).scan_static(sample))
    assert ids1 == ids2


def test_platform_binary_scores_clean():
    # A platform binary must not produce posture false-positives (no
    # gatekeeper-rejected / adhoc / no-hardened-runtime); just an info note.
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    inds = list(StaticMachOModule(runner=_platform_runner()).scan_static(sample))
    ident_names = {i.name for i in inds if i.name != "weak-dylib-load" and i.name != "rpath-dylib-load"}
    assert ident_names == {"apple-platform-binary"}
    assert all(i.severity.value == "info" for i in inds if i.name == "apple-platform-binary")
    assert "gatekeeper-rejected" not in {i.name for i in inds}


def test_non_macho_yields_nothing(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("just text")
    sample = Sample.from_path(str(p))
    assert list(StaticMachOModule(runner=_adhoc_runner()).scan_static(sample)) == []
