"""Apple built-in offline-emulation module (ROADMAP.md Phase 1, MODULE_CONTRACT.md §1).

Scores "what a stock Mac's built-in stack would do" against the sample bytes, with
no VM and no third-party agent — the first real detection tier (ARCHITECTURE.md §12:
we lean only on Apple's on-disk XProtect YARA and the queryable Gatekeeper verdict,
never on extracted commercial-vendor artifacts).

Two signals:

  1. **XProtect YARA** — Apple ships its malware signatures as a readable YARA file
     on disk (`XProtect.yara`). We scan the sample against it; a match is what
     Apple's own XProtect would flag. Beyond the yes/no, we **bisect to the
     triggering bytes** (LitterBox's "which bytes set it off") so the report points
     at the offending region, not just the rule name.
  2. **Gatekeeper / spctl** — the execution-policy verdict (accept/block), reusing
     the static tier's code-identity assessor.

Both boundaries are injectable — a `YaraMatcher` for the scan and a `Runner` for
spctl — so the whole module is unit-testable on any host with no libyara and no
macOS tools. The live matcher (`xprotect_matcher`) lazily builds a yara-python
scanner over the on-disk rules and is guarded: if libyara is absent it raises a
clear error rather than importing at module load. Emitted indicators carry
`Tier.EMULATION` regardless of which method fired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from modules.static.code_identity import CodeIdentity, Runner, assess_code_identity
from orchestrator.contracts.indicator import Indicator, Severity, Tier, indicator_id
from orchestrator.contracts.module import BaseModule, ModuleCaps, ModuleConfig
from orchestrator.contracts.sample import Sample

_MODULE = "emulation.apple"
_VERSION = "0.1"

# On-disk XProtect YARA on modern macOS (Tahoe / 26). The legacy
# /System/Library/CoreServices path is gone; this is the current location.
# Verified present on macOS 26.5.2 (world-readable, 443 rules, imports "hash").
XPROTECT_YARA = (
    "/Library/Apple/System/Library/CoreServices/"
    "XProtect.bundle/Contents/Resources/XProtect.yara"
)


@dataclass
class YaraStringHit:
    offset: int
    identifier: str


@dataclass
class YaraMatch:
    rule: str
    tags: list[str] = field(default_factory=list)
    strings: list[YaraStringHit] = field(default_factory=list)


# A matcher takes raw bytes and returns the rules that fired (with any string hits).
YaraMatcher = Callable[[bytes], "list[YaraMatch]"]


def bisect_trigger(data: bytes, rule: str, matcher: YaraMatcher) -> tuple[int, int] | None:
    """Find the minimal contiguous byte window that still triggers `rule`.

    Bytes OUTSIDE the window are zeroed (not sliced out) so file offsets are
    preserved — YARA conditions gate on absolute offsets (`uint32(0) == magic`),
    which slicing would break. Returns `[lo, hi)` or None if `data` doesn't match.

    Assumes match monotonicity in the window (a superset window that contains the
    trigger still matches), which holds for the string/offset predicates XProtect
    rules use. Cost is O(log n) scans per side.
    """
    def matches(buf: bytes) -> bool:
        return any(m.rule == rule for m in matcher(buf))

    n = len(data)
    if n == 0 or not matches(data):
        return None

    def zeroed(lo: int, hi: int) -> bytes:
        out = bytearray(n)
        out[lo:hi] = data[lo:hi]
        return bytes(out)

    # Smallest hi in [1, n] such that keeping [0, hi) still matches.
    lo_b, hi_b = 1, n
    while lo_b < hi_b:
        mid = (lo_b + hi_b) // 2
        if matches(zeroed(0, mid)):
            hi_b = mid
        else:
            lo_b = mid + 1
    hi = hi_b

    # Largest lo in [0, hi-1] such that keeping [lo, hi) still matches.
    lo_b2, hi_b2 = 0, hi - 1
    while lo_b2 < hi_b2:
        mid = (lo_b2 + hi_b2 + 1) // 2
        if matches(zeroed(mid, hi)):
            lo_b2 = mid
        else:
            hi_b2 = mid - 1
    return (lo_b2, hi)


def xprotect_matcher(rules_path: str = XPROTECT_YARA) -> YaraMatcher:
    """Build a live matcher over Apple's on-disk XProtect YARA.

    Lazily imports yara-python (libyara) and compiles the rules once. Guarded: if
    libyara is not installed, or the rules file is missing, it raises a clear error
    instead of failing at import time — the module stays importable and testable
    with an injected matcher on hosts without yara."""
    try:
        import yara  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover - env-specific
        raise RuntimeError(
            "yara-python (libyara) is required for the live XProtect matcher; "
            "inject a YaraMatcher for offline/testing use"
        ) from e
    if not Path(rules_path).exists():  # pragma: no cover - env-specific
        raise RuntimeError(f"XProtect YARA rules not found at {rules_path}")

    rules = yara.compile(filepath=rules_path)

    def match(data: bytes) -> list[YaraMatch]:  # pragma: no cover - needs libyara
        out: list[YaraMatch] = []
        for m in rules.match(data=data):
            hits: list[YaraStringHit] = []
            # yara-python string-match shape changed across versions; handle both.
            for s in getattr(m, "strings", []):
                if hasattr(s, "instances"):  # yara-python >= 4.3
                    for inst in s.instances:
                        hits.append(YaraStringHit(offset=inst.offset, identifier=s.identifier))
                else:  # legacy (offset, identifier, data) tuple
                    offset, identifier = s[0], s[1]
                    hits.append(YaraStringHit(offset=offset, identifier=identifier))
            out.append(YaraMatch(rule=m.rule, tags=list(getattr(m, "tags", [])), strings=hits))
        return out

    return match


class AppleBuiltinModule(BaseModule):
    """Apple built-in emulation tier: XProtect YARA match (+ triggering-byte bisect)
    and the Gatekeeper/spctl verdict, over the sample bytes.

    STATIC-capability (one-shot on bytes, like the static tier) but its indicators
    are `Tier.EMULATION`: it emulates Apple's own detection offline. Inject `matcher`
    (a YaraMatcher) and `runner` (the code-identity subprocess boundary) for tests;
    omit them and the live XProtect scan + spctl run are used."""

    def __init__(
        self,
        matcher: YaraMatcher | None = None,
        runner: Runner | None = None,
        ident: CodeIdentity | None = None,
    ) -> None:
        super().__init__()
        self._matcher = matcher
        self._runner = runner
        # A conductor may inject a pre-computed CodeIdentity so this tier and the
        # static tier share one codesign/spctl assessment of the sample. Omitted ->
        # this module assesses it itself.
        self._ident = ident
        self._rules_path = XPROTECT_YARA

    def name(self) -> str:
        return _MODULE

    def version(self) -> str:
        return _VERSION

    def capabilities(self) -> ModuleCaps:
        return ModuleCaps.STATIC

    def initialize(self, cfg: ModuleConfig) -> None:
        # Allow overriding the rules path (e.g. a pinned copy) via module options.
        path = (cfg.options or {}).get("xprotect_yara")
        if path:
            self._rules_path = path

    def scan_static(self, sample: Sample) -> Iterable[Indicator]:
        self._indicators = []
        data = Path(sample.path).read_bytes()
        self._scan_xprotect(sample, data)
        self._assess_gatekeeper(sample)
        return list(self._indicators)

    # -- XProtect YARA -------------------------------------------------------
    def _scan_xprotect(self, sample: Sample, data: bytes) -> None:
        matcher = self._matcher or xprotect_matcher(self._rules_path)
        matches = matcher(data)
        for m in matches:
            trigger = self._trigger_evidence(data, m, matcher)
            self.emit(Indicator(
                id=indicator_id(_MODULE, "xprotect", sample.sha256, m.rule),
                name="xprotect-signature-match",
                severity=Severity.MALICIOUS,
                tier=Tier.EMULATION,
                module=_MODULE,
                # An XProtect family hit is Apple's own AV signature firing; the
                # family name is the payload, so evidence carries it rather than
                # forcing an ill-fitting ATT&CK technique.
                attack=[],
                description=f"Apple XProtect signature '{m.rule}' matches; a stock Mac would flag this",
                evidence={"rule": m.rule, "tags": m.tags, **trigger},
            ))

    def _trigger_evidence(self, data: bytes, m: YaraMatch, matcher: YaraMatcher) -> dict:
        """Locate the triggering bytes: prefer YARA's own reported string offsets;
        fall back to the zeroing bisect for condition-only rules."""
        if m.strings:
            hits = [{"offset": h.offset, "identifier": h.identifier} for h in m.strings]
            offsets = [h.offset for h in m.strings]
            return {"string_hits": hits, "trigger_range": [min(offsets), max(offsets)]}
        window = bisect_trigger(data, m.rule, matcher)
        return {"trigger_range": list(window)} if window else {}

    # -- Gatekeeper / spctl --------------------------------------------------
    def _assess_gatekeeper(self, sample: Sample) -> None:
        # This tier owns the authoritative Gatekeeper/spctl verdict (the static
        # tier defers to it — see module.py's Gatekeeper decision note), so
        # `gatekeeper-block` is emitted here and only here.
        ident: CodeIdentity = (
            self._ident if self._ident is not None
            else assess_code_identity(sample.path, runner=self._runner)
        )
        if not ident.tools_available:
            return

        def add(name, sev, desc, evidence):
            self.emit(Indicator(
                id=indicator_id(_MODULE, name, sample.sha256),
                name=name, severity=sev, tier=Tier.EMULATION, module=_MODULE,
                attack=["T1553.001"], description=desc, evidence=evidence,
            ))

        # Only a genuine block counts. spctl declining a bare Mach-O ("not an app",
        # assessable=False) is not a Gatekeeper rejection.
        if ident.spctl_accepted is False and ident.spctl_assessable:
            add("gatekeeper-block", Severity.HIGH,
                "Gatekeeper (spctl) would block execution on a quarantined launch",
                {"spctl_source": ident.spctl_source})
        elif ident.spctl_accepted is True:
            add("gatekeeper-accept", Severity.INFO,
                "Gatekeeper (spctl) accepts execution",
                {"spctl_source": ident.spctl_source})


def make_module(
    matcher: YaraMatcher | None = None,
    runner: Runner | None = None,
    ident: CodeIdentity | None = None,
) -> AppleBuiltinModule:
    return AppleBuiltinModule(matcher=matcher, runner=runner, ident=ident)
