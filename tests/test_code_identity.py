"""Code-identity assessor tests. The subprocess boundary is injected, so these
run on any host with canned codesign/spctl/xattr output (no real Mac tools)."""

from modules.static.code_identity import assess_code_identity


def make_runner(codesign_dv, entitlements_xml="", spctl=("accepted", 0, "source=Notarized Developer ID"),
                quarantine=None):
    """Build a fake Runner. `codesign_dv` = (rc, stderr). `spctl` = (verdict,
    rc, source_line). `quarantine` = xattr stdout or None (absent)."""

    def runner(argv):
        tool = argv[0]
        if tool == "codesign" and "--entitlements" in argv:
            return (0 if entitlements_xml else 1, entitlements_xml, "")
        if tool == "codesign":
            rc, stderr = codesign_dv
            return (rc, "", stderr)
        if tool == "spctl":
            verdict, rc, source = spctl
            return (rc, "", f"/tmp/x: {verdict}\n{source}")
        if tool == "xattr":
            return (0, quarantine, "") if quarantine else (1, "", "No such xattr")
        raise AssertionError(f"unexpected argv {argv}")

    return runner


ADHOC_DV = (0, "\n".join([
    "Identifier=hello",
    "CodeDirectory v=20400 size=260 flags=0x20002(adhoc,linker-signed) hashes=5+0",
    "CDHash=d194a628f3feac16e1da1ca2c3a524c3d09f6722",
    "Signature=adhoc",
    "TeamIdentifier=not set",
]))

DEVID_DV = (0, "\n".join([
    "Identifier=com.example.app",
    "TeamIdentifier=ABCDE12345",
    "CDHash=1111222233334444",
    "CodeDirectory v=20500 size=999 flags=0x10000(runtime) hashes=9+0",
    "Authority=Developer ID Application: Example Corp (ABCDE12345)",
    "Authority=Developer ID Certification Authority",
    "Authority=Apple Root CA",
]))

PLATFORM_DV = (0, "\n".join([
    "Identifier=com.apple.ls",
    "CodeDirectory v=20400 size=741 flags=0x0(none) hashes=18+2",
    "Platform identifier=26",
    "Authority=Software Signing",
    "Authority=Apple Code Signing Certification Authority",
    "Authority=Apple Root CA",
    "TeamIdentifier=not set",
]))

ENTITLEMENTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.get-task-allow</key><true/>
  <key>com.apple.security.app-sandbox</key><true/>
</dict></plist>"""


def test_unsigned():
    runner = make_runner((1, "/tmp/x: code object is not signed at all"),
                         spctl=("rejected", 3, "source=no usable signature"))
    ident = assess_code_identity("/tmp/x", runner=runner)
    assert ident.signature_type == "unsigned"
    assert ident.spctl_accepted is False
    assert ident.hardened_runtime is False


def test_adhoc():
    runner = make_runner(ADHOC_DV, spctl=("rejected", 3, "source=no usable signature"))
    ident = assess_code_identity("/tmp/x", runner=runner)
    assert ident.signature_type == "adhoc"
    assert ident.team_id is None
    assert ident.cdhash == "d194a628f3feac16e1da1ca2c3a524c3d09f6722"
    assert ident.spctl_accepted is False


def test_developer_id_notarized_with_entitlement_and_quarantine():
    runner = make_runner(
        DEVID_DV,
        entitlements_xml=ENTITLEMENTS_XML,
        spctl=("accepted", 0, "source=Notarized Developer ID"),
        quarantine="0081;deadbeef;Safari;",
    )
    ident = assess_code_identity("/tmp/x", runner=runner)
    assert ident.signature_type == "developer_id"
    assert ident.team_id == "ABCDE12345"
    assert ident.hardened_runtime is True
    assert ident.is_notarized is True
    assert ident.spctl_accepted is True
    assert "com.apple.security.get-task-allow" in ident.dangerous_entitlements()
    assert ident.quarantine is True


def test_platform_binary_not_assessable_by_spctl():
    # /bin/ls-style: platform-signed, spctl declines ("not an app") — not a block.
    runner = make_runner(
        PLATFORM_DV,
        spctl=("rejected (the code is valid but does not seem to be an app)", 3, "origin=Software Signing"),
    )
    ident = assess_code_identity("/bin/ls", runner=runner)
    assert ident.signature_type == "platform"
    assert ident.is_platform_binary is True
    assert ident.spctl_accepted is None      # not a rejection
    assert ident.spctl_assessable is False


def test_tools_missing_degrades_gracefully(monkeypatch):
    # No runner injected + no codesign on PATH -> returns, does not raise.
    import modules.static.code_identity as ci
    monkeypatch.setattr(ci.shutil, "which", lambda _name: None)
    ident = assess_code_identity("/tmp/x")
    assert ident.tools_available is False
    assert ident.signature_type == "unsigned"
