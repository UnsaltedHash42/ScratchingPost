"""Code-identity assessor (ROADMAP.md Phase 1 static tier).

Shells out to codesign / spctl / xattr and collapses signing, notarization,
hardened runtime, entitlements, and quarantine into one CodeIdentity verdict:
"would a stock Mac run this, and would it flag it."

The subprocess boundary is injectable (a `Runner` callable) so the parsing logic
is unit-testable on any host against canned tool output; the live path is guarded
and only touched when a real Runner runs. On a host without these tools, an
assessment still returns — with `tools_available=False` — rather than raising.

Reconciled against real macOS 26.5.2 (Tahoe, build 25F84) output on 2026-07-01:
`/bin/ls` (platform: `Authority=Software Signing`, `Platform identifier=26`, spctl
`rejected (the code is valid but does not seem to be an app)` + `origin=Software
Signing`), Google Chrome (developer_id + notarized: `Authority=Developer ID
Application`, `flags=...(runtime)`, spctl `accepted` + `source=Notarized Developer
ID`), and an adhoc fixture (`flags=0x20002(adhoc,linker-signed)`, bare `rejected`).
The string-matching below matches all three. Re-confirm only if the target guest is
a materially different macOS build.
"""

from __future__ import annotations

import plistlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from orchestrator.contracts.process import DANGEROUS_ENTITLEMENTS

# `Runner(argv) -> (returncode, stdout, stderr)`. Injected in tests.
Runner = Callable[[list[str]], "tuple[int, str, str]"]


def subprocess_runner(argv: list[str]) -> tuple[int, str, str]:
    """Default live Runner. Never invoked at import time."""
    p = subprocess.run(argv, capture_output=True, text=True, check=False)
    return p.returncode, p.stdout, p.stderr


@dataclass
class CodeIdentity:
    signature_type: str = "unsigned"  # unsigned|adhoc|developer_id|app_store|platform|unknown
    team_id: str | None = None
    signing_id: str | None = None
    cdhash: str = ""
    is_platform_binary: bool = False
    hardened_runtime: bool = False
    is_notarized: bool = False
    entitlements: dict = field(default_factory=dict)
    quarantine: bool = False
    spctl_accepted: bool | None = None  # True=accepted, False=blocked, None=not assessable
    spctl_source: str | None = None
    spctl_assessable: bool = True  # False when spctl declines (e.g. "not an app")
    authorities: list[str] = field(default_factory=list)
    tools_available: bool = True
    notes: list[str] = field(default_factory=list)

    def dangerous_entitlements(self) -> list[str]:
        return [k for k in self.entitlements if k in DANGEROUS_ENTITLEMENTS]


# -- codesign -----------------------------------------------------------------
def _parse_codesign_dv(stderr: str) -> dict:
    """Parse `codesign -dvvv`. Fields land on stderr, one `Key=Value` per line.
    Line spellings confirmed on macOS 26.5.2 (see module docstring)."""
    out: dict = {
        "signing_id": None,
        "team_id": None,
        "cdhash": "",
        "hardened_runtime": False,
        "adhoc": False,
        "authorities": [],
        "signature": None,
        "platform": False,
    }
    for raw in stderr.splitlines():
        line = raw.strip()
        if line.startswith("Identifier="):
            out["signing_id"] = line.split("=", 1)[1] or None
        elif line.startswith("TeamIdentifier="):
            v = line.split("=", 1)[1]
            out["team_id"] = None if v in ("", "not set") else v
        elif line.startswith("CDHash="):
            out["cdhash"] = line.split("=", 1)[1]
        elif line.startswith("Signature="):
            out["signature"] = line.split("=", 1)[1]  # e.g. "adhoc"
        elif line.startswith("Platform identifier="):
            # Present on Apple platform binaries (/bin, /usr/bin, ...).
            out["platform"] = True
        elif line.startswith("Authority="):
            auth = line.split("=", 1)[1]
            out["authorities"].append(auth)
            # "Software Signing" is Apple's platform-binary leaf authority.
            if auth == "Software Signing":
                out["platform"] = True
        elif line.startswith("flags=") or line.startswith("CodeDirectory"):
            low = line.lower()
            if "runtime" in low:
                out["hardened_runtime"] = True
            if "adhoc" in low:
                out["adhoc"] = True
    return out


def _classify_signature(dv: dict, is_platform: bool) -> str:
    if is_platform:
        return "platform"
    if dv.get("adhoc") or dv.get("signature") == "adhoc":
        return "adhoc"
    auths = dv.get("authorities") or []
    joined = " ".join(auths)
    if "Developer ID Application" in joined:
        return "developer_id"
    if "Apple Mac OS Application Signing" in joined or "Apple iPhone OS Application Signing" in joined:
        return "app_store"
    if any("Apple" in a for a in auths):
        return "platform"
    if auths:
        return "unknown"
    return "unsigned"


# -- entitlements -------------------------------------------------------------
def _parse_entitlements_plist(stdout_bytes: str) -> dict:
    """`codesign -d --entitlements :- --xml` emits an XML plist on stdout."""
    text = stdout_bytes.strip()
    if not text or "<?xml" not in text and "<plist" not in text:
        return {}
    start = text.find("<?xml")
    if start < 0:
        start = text.find("<plist")
    try:
        return plistlib.loads(text[start:].encode("utf-8"))  # type: ignore[return-value]
    except Exception:
        return {}


# -- spctl --------------------------------------------------------------------
def _parse_spctl(stderr: str, returncode: int) -> tuple[bool | None, str | None, bool]:
    """`spctl -a -vvv -t exec <path>`: 'accepted'/'rejected' + a source/origin on
    stderr. Returns (accepted, source, assessable).

    spctl declines to assess a bare (non-app) executable with "the code is valid
    but does not seem to be an app" — a valid-signature outcome, NOT a Gatekeeper
    block. That case returns assessable=False / accepted=None so callers don't
    mistake it for a real rejection. A bare `rejected` with no such reason (e.g.
    adhoc/unsigned) is a genuine block. spctl wording confirmed on macOS 26.5.2:
    "rejected (the code is valid but does not seem to be an app)", bare "accepted"/
    "rejected", "source=Notarized Developer ID", "origin=Software Signing"."""
    accepted: bool | None = returncode == 0
    source = None
    not_assessable = False
    for raw in stderr.splitlines():
        line = raw.strip()
        low = line.lower()
        if line.startswith("source="):
            source = line.split("=", 1)[1]
        elif line.startswith("origin="):
            source = source or line.split("=", 1)[1]
        if "does not seem to be an app" in low:
            not_assessable = True
        if low.endswith(": accepted") or low == "accepted":
            accepted = True
        elif low.endswith(": rejected") or low == "rejected" or low.startswith("rejected"):
            accepted = False
    if not_assessable:
        return None, source, False
    return accepted, source, True


def assess_code_identity(path: str, runner: Runner | None = None) -> CodeIdentity:
    """Collapse codesign/spctl/xattr into a CodeIdentity. Pass a `runner` to feed
    canned output (tests); omit it to use the live subprocess path."""
    ident = CodeIdentity()

    if runner is None:
        if not shutil.which("codesign"):
            ident.tools_available = False
            ident.notes.append("codesign not found on host; static code-identity skipped")
            return ident
        runner = subprocess_runner

    # codesign -dvvv (identity, cdhash, hardened runtime, authorities)
    rc, _out, err = runner(["codesign", "-dvvv", path])
    if rc != 0 and "code object is not signed" in (err.lower() + _out.lower()):
        ident.signature_type = "unsigned"
        ident.notes.append("codesign: not signed")
    else:
        dv = _parse_codesign_dv(err or _out)
        ident.signing_id = dv["signing_id"]
        ident.team_id = dv["team_id"]
        ident.cdhash = dv["cdhash"]
        ident.hardened_runtime = dv["hardened_runtime"]
        ident.authorities = dv["authorities"]
        ident.is_platform_binary = dv["platform"]
        ident.signature_type = _classify_signature(dv, ident.is_platform_binary)

    # entitlements
    erc, eout, _eerr = runner(["codesign", "-d", "--entitlements", ":-", "--xml", path])
    if erc == 0:
        ident.entitlements = _parse_entitlements_plist(eout)

    # spctl assessment + notarization signal
    src_rc, _sout, serr = runner(["spctl", "-a", "-vvv", "-t", "exec", path])
    accepted, source, assessable = _parse_spctl(serr, src_rc)
    ident.spctl_accepted = accepted
    ident.spctl_source = source
    ident.spctl_assessable = assessable
    if source and "Notarized" in source:
        ident.is_notarized = True

    # quarantine xattr
    qrc, qout, _qerr = runner(["xattr", "-p", "com.apple.quarantine", path])
    ident.quarantine = qrc == 0 and bool(qout.strip())

    return ident
