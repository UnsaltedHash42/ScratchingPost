"""Phase-1 conductor: the vertical slice wired into one call (ROADMAP.md Phase 1).

`analyze(sample, profile, env)` is the spine the docs describe — the single entry
point that runs the whole Phase-1 chain and returns one aggregate verdict:

  1. Static tiers (in-process, on the sample bytes): the Mach-O/code-identity
     module and the Apple built-in emulation module. Both need the sample's
     code identity; the default set assesses it ONCE here and injects the shared
     result into both, rather than each shelling codesign/spctl for the same file.
  2. Detonation seam (ARCHITECTURE.md §8): detonate the sample in `profile`,
     collect its ESF telemetry, and always revert the environment afterwards.
  3. Behavioral tier: replay the collected telemetry through the single-threaded
     pipeline against the behavioral modules.
  4. Aggregate every tier's indicators into one Detection Score (§5).
  5. Render the operator-facing report from that score.

Every external dependency stays behind an injected boundary: the detonation
`env` (replay-backed `LocalAppliance` in dev/test, live `VmProvider` in
production), the code-identity `runner`, and the XProtect `matcher`. So the whole
chain is exercisable end to end with no VM, no libyara, and no macOS tools.

The concrete detection modules are imported lazily (inside the default factory),
keeping `import orchestrator` free of a framework->plugin import at load time —
the same lazy-touch discipline `detonation/api.py` uses for the sensors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .contracts.events import Event
from .contracts.indicator import Indicator
from .contracts.module import DetectionModule, ModuleCaps
from .contracts.sample import Sample
from .detonation.api import DetonationEnvironment
from .pipeline.replay import replay_events
from .scoring.report import render_json, render_report
from .scoring.score import DetectionScore, score_indicators


@dataclass
class AnalysisResult:
    """Everything one analyze() run produced: the aggregate score, the flat list
    of contributing indicators, and the raw telemetry/alerts for inspection."""

    sample: Sample
    profile: str
    run_id: str
    score: DetectionScore
    indicators: list[Indicator] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return self.score.verdict

    def report(self) -> str:
        """Operator-facing text report (MODULE_CONTRACT.md §5)."""
        return render_report(self.score, self.sample)

    def report_json(self, indent: int | None = 2) -> str:
        return render_json(self.score, self.sample, indent=indent)


def default_static_modules(
    *, runner=None, matcher=None, ident=None
) -> list[DetectionModule]:
    """The Phase-1 static+emulation set, sharing one code-identity assessment.

    Lazily imports the concrete modules so `orchestrator` stays import-clean."""
    from modules.emulation.apple_builtin import AppleBuiltinModule
    from modules.static import StaticMachOModule

    return [
        StaticMachOModule(runner=runner, ident=ident),
        AppleBuiltinModule(matcher=matcher, runner=runner, ident=ident),
    ]


def _run_dispatch(sample: Sample, module: DetectionModule) -> list[Indicator]:
    """Drive one dispatch module through the seam: it detonates its OWN profile (a
    guest running the agent), then collect() pulls that agent's alerts as indicators
    and reverts. The profile comes from the module (its `profile` attribute), not the
    conductor's behavioral profile — dispatch runs are independent detonations."""
    module_profile = getattr(module, "profile", None) or "wazuh"
    run_id = module.dispatch(sample, module_profile)
    return list(module.collect(run_id))


def analyze(
    sample: Sample,
    profile: str,
    env: DetonationEnvironment,
    *,
    static_modules: Sequence[DetectionModule] | None = None,
    behavioral_modules: Sequence[DetectionModule] = (),
    dispatch_modules: Sequence[DetectionModule] = (),
    runner=None,
    matcher=None,
    ident=None,
    timeout: float = 30.0,
) -> AnalysisResult:
    """Run the full slice over `sample` and return one aggregate result.

    `env` is the detonation environment (injected). `static_modules` defaults to
    the Phase-1 static+emulation set (they share one code-identity assessment);
    pass your own to override. `behavioral_modules` consume the collected ESF
    telemetry via replay. `dispatch_modules` (Phase 2, e.g. Wazuh) each detonate
    their OWN profile via their own seam and contribute the agent's alerts as
    dispatch-tier indicators. `runner`/`matcher`/`ident` inject the code-identity and
    XProtect boundaries for the default modules (all optional; live paths used if
    omitted)."""
    # 1. Static + emulation tiers, on the sample bytes. The default set shares one
    #    codesign/spctl assessment across both modules; a caller-supplied set owns
    #    its own identity handling.
    if static_modules is None:
        if ident is None:
            from modules.static.code_identity import assess_code_identity

            ident = assess_code_identity(sample.path, runner=runner)
        static_modules = default_static_modules(runner=runner, matcher=matcher, ident=ident)

    indicators: list[Indicator] = []
    for module in static_modules:
        if module.capabilities() & ModuleCaps.STATIC:
            indicators.extend(module.scan_static(sample))

    # 2. Detonation seam: detonate -> collect telemetry -> ALWAYS revert. collect
    #    must precede revert (revert drops the run's bookkeeping), and revert runs
    #    even if collect raises, so the lab is left clean.
    run_id = env.detonate(sample, profile, timeout)
    try:
        collected = env.collect(run_id)
    finally:
        env.revert(profile)
    events = list(collected.events)
    alerts = list(collected.alerts)

    # 3. Behavioral tier: replay the telemetry through the ordered pipeline.
    if behavioral_modules:
        indicators.extend(replay_events(events, behavioral_modules))

    # 3b. Dispatch tier (Phase 2): each dispatch module detonates its own profile
    #     (a guest running a real agent) and returns that agent's verdict. Separate
    #     from the behavioral detonation above — a different profile, its own revert.
    for module in dispatch_modules:
        if module.capabilities() & ModuleCaps.DISPATCH:
            indicators.extend(_run_dispatch(sample, module))

    # 4. + 5. Aggregate into the Detection Score; the report is rendered on demand
    #    from AnalysisResult.
    score = score_indicators(indicators)
    return AnalysisResult(
        sample=sample,
        profile=profile,
        run_id=run_id,
        score=score,
        indicators=indicators,
        events=events,
        alerts=alerts,
    )
