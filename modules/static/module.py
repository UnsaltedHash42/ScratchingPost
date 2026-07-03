"""Static Mach-O detection module (MODULE_CONTRACT.md §2, ROADMAP.md Phase 1).

Wires the Mach-O parser and the code-identity assessor into a STATIC-capability
DetectionModule. One-shot: scan_static() parses the sample, assesses its code
identity, and collapses both into Indicators with deterministic IDs and ATT&CK
tags. This tier alone is a useful standalone assessor (ROADMAP "Standalone tools").

Severity posture follows MODULE_CONTRACT.md §5: code-identity failures that gate
whether the thing runs weigh heavy; dylib-hijack surface and posture weaknesses
are corroborating signal.
"""

from __future__ import annotations

from typing import Iterable

from orchestrator.contracts.indicator import Indicator, Severity, Tier, indicator_id
from orchestrator.contracts.module import BaseModule, ModuleCaps, ModuleConfig
from orchestrator.contracts.sample import Sample

from .code_identity import CodeIdentity, Runner, assess_code_identity
from .macho import MachOInfo, is_macho, parse_macho

_MODULE = "static.macho"
_VERSION = "0.1"

# ATT&CK technique IDs used by this tier.
_T_SIGNING = "T1553.001"       # Subvert Trust Controls: Code Signing
_T_GATEKEEPER = "T1553.001"    # Gatekeeper bypass shares the code-signing umbrella
_T_DYLIB_HIJACK = "T1574.004"  # Hijack Execution Flow: Dylib Hijacking
_T_DYLD_VARS = "T1574.006"     # Hijack Execution Flow: Dynamic Linker Hijacking (DYLD_*)


class StaticMachOModule(BaseModule):
    """STATIC module. Optionally accepts an injected `runner` for the code-identity
    subprocess boundary (tests feed canned tool output; production omits it)."""

    def __init__(self, runner: Runner | None = None, ident: CodeIdentity | None = None) -> None:
        super().__init__()
        self._runner = runner
        # A pre-computed CodeIdentity may be injected so a conductor can assess the
        # sample's signing once and share it with the Apple emulation tier (which
        # also needs it), instead of each module shelling codesign/spctl for the
        # same file. Omitted -> this module assesses it itself (standalone use).
        self._ident = ident

    def name(self) -> str:
        return _MODULE

    def version(self) -> str:
        return _VERSION

    def capabilities(self) -> ModuleCaps:
        return ModuleCaps.STATIC

    def initialize(self, cfg: ModuleConfig) -> None:
        return None

    def scan_static(self, sample: Sample) -> Iterable[Indicator]:
        self._indicators = []
        if not is_macho(sample.path):
            return []
        macho = parse_macho(sample.path)
        ident = self._ident if self._ident is not None else assess_code_identity(sample.path, runner=self._runner)
        self._assess_identity(sample, ident)
        self._assess_macho(sample, macho)
        return list(self._indicators)

    # -- code identity -------------------------------------------------------
    def _assess_identity(self, sample: Sample, ident: CodeIdentity) -> None:
        key = sample.sha256

        def add(name, sev, desc, attack, evidence):
            self.emit(
                Indicator(
                    id=indicator_id(_MODULE, name, key),
                    name=name,
                    severity=sev,
                    tier=Tier.STATIC,
                    module=_MODULE,
                    attack=attack,
                    description=desc,
                    evidence=evidence,
                )
            )

        if not ident.tools_available:
            add(
                "code-identity-unavailable",
                Severity.INFO,
                "codesign/spctl unavailable on this host; code-identity not assessed",
                [],
                {"notes": ident.notes},
            )
            return

        st = ident.signature_type

        # Apple platform binaries are trusted by execution policy; spctl declining
        # to assess them ("not an app") and their lack of hardened-runtime/
        # notarization are expected, not findings. Record identity, skip posture.
        if ident.is_platform_binary or st == "platform":
            add("apple-platform-binary", Severity.INFO,
                "Apple platform binary (first-party, trusted by execution policy)",
                [], {"signing_id": ident.signing_id, "authorities": ident.authorities})
            return

        if st == "unsigned":
            add("unsigned-binary", Severity.HIGH,
                "Binary is unsigned; Gatekeeper blocks it from a quarantined launch",
                [_T_SIGNING], {"signature_type": st})
        elif st == "adhoc":
            add("adhoc-signed", Severity.MEDIUM,
                "Ad-hoc signature: no identity, no notarization, no Gatekeeper trust",
                [_T_SIGNING], {"signature_type": st, "cdhash": ident.cdhash})

        # Gatekeeper decision (Phase-1.5 double-count fix): the spctl/Gatekeeper
        # verdict is emitted ONLY by the Apple emulation tier (emulation.apple's
        # `gatekeeper-block`), which is the authoritative execution-policy signal.
        # The static tier used to also emit `gatekeeper-rejected` for the same
        # spctl block, double-counting one fact across two tiers (8 static + 12
        # emulation). Dropped here: the static tier reports signing *posture*
        # (unsigned/adhoc/not-notarized/entitlements) — the reasons Gatekeeper
        # would block — not the runtime verdict itself. Standalone static use
        # still flags the underlying problem via those posture indicators.

        if st in ("developer_id", "app_store", "unknown") and not ident.is_notarized:
            add("not-notarized", Severity.MEDIUM,
                "Signed but not notarized; first-launch Gatekeeper prompt/block on quarantine",
                [_T_GATEKEEPER],
                {"signature_type": st, "spctl_source": ident.spctl_source})

        if st not in ("unsigned",) and not ident.hardened_runtime:
            add("no-hardened-runtime", Severity.LOW,
                "Hardened runtime disabled; permits unsigned dylib loads and DYLD injection",
                [_T_DYLD_VARS], {"signature_type": st})

        for ent in ident.dangerous_entitlements():
            add(f"entitlement:{ent}", Severity.MEDIUM,
                f"Carries powerful entitlement {ent}",
                [_T_DYLD_VARS] if "dyld" in ent or "library-validation" in ent else [_T_SIGNING],
                {"entitlement": ent})

        if ident.quarantine:
            add("quarantine-xattr", Severity.INFO,
                "com.apple.quarantine xattr present (downloaded/untrusted provenance)",
                [], {"quarantine": True})

    # -- Mach-O structure ----------------------------------------------------
    def _assess_macho(self, sample: Sample, macho: MachOInfo) -> None:
        key = sample.sha256
        for idx, sl in enumerate(macho.slices):
            slice_key = f"{key}:{sl.cpu}"
            for d in sl.weak_dylibs:
                self.emit(Indicator(
                    id=indicator_id(_MODULE, "weak-dylib", slice_key, d.name),
                    name="weak-dylib-load",
                    severity=Severity.LOW,
                    tier=Tier.STATIC,
                    module=_MODULE,
                    attack=[_T_DYLIB_HIJACK],
                    description=f"Weak dylib load ({d.name}); a planted library at that path is picked up silently",
                    evidence={"dylib": d.name, "cpu": sl.cpu, "kind": d.kind},
                ))
            for d in sl.rpath_dylibs:
                self.emit(Indicator(
                    id=indicator_id(_MODULE, "rpath-dylib", slice_key, d.name),
                    name="rpath-dylib-load",
                    severity=Severity.LOW,
                    tier=Tier.STATIC,
                    module=_MODULE,
                    attack=[_T_DYLIB_HIJACK],
                    description=f"@rpath-relative dylib load ({d.name}); resolution order enables hijack via a writable rpath entry",
                    evidence={"dylib": d.name, "cpu": sl.cpu, "rpaths": sl.rpaths},
                ))
