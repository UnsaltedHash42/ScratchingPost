"""Wazuh dispatch module (MODULE_CONTRACT.md §7, ROADMAP.md Phase 2).

The first real-agent detection tier. Wazuh on macOS is not an ESF behavioral
sensor, so ScratchingPost uses it as a **dispatch** module: detonate the sample in
the `wazuh` profile (a guest running a live Wazuh agent reporting to a manager),
then collect the *manager's own alerts* for that run and translate them into
`Indicator`s tagged `Tier.DISPATCH`. The point is to capture the agent's verdict,
not to re-derive detection from telemetry (§2 design note).

The Wazuh manager sits behind an injected `WazuhBackend` boundary — the same
pattern as the VM provider (`detonation/vm.py`) and the code-identity `Runner`
(`modules/static/code_identity.py`). Tests inject a fake backend returning canned
alerts, so the whole dispatch→collect→translate→score chain runs with no live
manager, no agent, and no guest.

Scope (Phase-2 entry, deliberately NOT "Wazuh proper" yet): this is the module +
boundary + alert→Indicator translation. The persistent manager/indexer/dashboard
stack, the ESF-telemetry custom log source, and the MITRE-tagged custom decoders/
rules (MODULE_CONTRACT.md §7, ROADMAP Phase 2) are the next step, and the live
`WazuhBackend` implementation is left as a guarded stub because the manager API
surface is version-sensitive (ROADMAP "Verify at build": 4.14.x vs 5.0).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Protocol, runtime_checkable

from orchestrator.contracts.indicator import Indicator, Severity, Tier, indicator_id
from orchestrator.contracts.module import BaseModule, ModuleCaps, ModuleConfig
from orchestrator.contracts.sample import Sample
from orchestrator.detonation.api import DetonationEnvironment

_MODULE = "dispatch.wazuh"
_VERSION = "0.1"


@dataclass
class WazuhAlert:
    """One Wazuh manager alert, normalized to the fields we translate.

    Mirrors the shape of a Wazuh alert (`rule.id`, `rule.level`, `rule.description`,
    `rule.mitre.id`, `rule.groups`, `agent.name`, `@timestamp`); `raw` keeps the
    original document for provenance."""

    rule_id: str
    level: int                       # Wazuh severity 0-15
    description: str
    mitre: list[str] = field(default_factory=list)  # ATT&CK technique IDs
    groups: list[str] = field(default_factory=list)
    agent: str | None = None
    timestamp: float | None = None
    raw: dict = field(default_factory=dict)


@runtime_checkable
class WazuhBackend(Protocol):
    """The injected boundary to a Wazuh manager. `alerts_since` returns the alerts
    the manager recorded in a time window (how a live detonation is correlated:
    the manager knows nothing of our run_id, so we filter by the detonation window
    and, when set, the profile guest's agent)."""

    def alerts_since(self, since: float, *, agent: str | None = None) -> list[WazuhAlert]: ...


# Wazuh rule level -> our severity. Wazuh levels run 0-15 (12+ = high-importance /
# attack). Dispatch already weighs heaviest per-tier (§5), so real-agent hits carry
# hard on their own; we do NOT auto-assign `malicious` here (that severity floors
# the whole verdict and is reserved for definitive convictions like an XProtect
# signature). Injectable via the module's `min_level` / a custom mapper if retuning.
def alert_to_severity(level: int) -> Severity:
    if level >= 12:
        return Severity.HIGH
    if level >= 7:
        return Severity.MEDIUM
    if level >= 4:
        return Severity.LOW
    return Severity.INFO


@dataclass
class _RunWindow:
    profile: str
    since: float
    agent: str | None


class WazuhModule(BaseModule):
    """DISPATCH module. Detonates in the `wazuh` profile via the injected detonation
    seam, then translates the manager's alerts (from the injected backend) into
    dispatch-tier Indicators.

    `env` is the detonation environment (ARCHITECTURE.md §8). `backend` is the Wazuh
    manager boundary. `clock` stamps the detonation start so `collect` can ask the
    backend for that window; injectable for deterministic tests. `min_level` drops
    alerts below a Wazuh level (noise floor)."""

    def __init__(
        self,
        env: DetonationEnvironment,
        backend: WazuhBackend,
        *,
        profile: str = "wazuh",
        agent: str | None = None,
        clock: Callable[[], float] = time.time,
        timeout: float = 60.0,
        min_level: int = 3,
    ) -> None:
        super().__init__()
        self._env = env
        self._backend = backend
        # A dispatch module detonates its OWN profile (a guest running the Wazuh
        # agent), not the conductor's behavioral profile. The conductor reads this to
        # drive dispatch independently of the apple detonation.
        self.profile = profile
        self._agent = agent
        self._clock = clock
        self._timeout = timeout
        self._min_level = min_level
        self._runs: dict[str, _RunWindow] = {}

    def name(self) -> str:
        return _MODULE

    def version(self) -> str:
        return _VERSION

    def capabilities(self) -> ModuleCaps:
        return ModuleCaps.DISPATCH

    def initialize(self, cfg: ModuleConfig) -> None:
        if cfg.profile:
            self.profile = cfg.profile
        opts = cfg.options or {}
        if "min_level" in opts:
            self._min_level = int(opts["min_level"])
        if "agent" in opts:
            self._agent = opts["agent"]

    def dispatch(self, sample: Sample, profile: str) -> str:
        """Detonate the sample in `profile` (guest runs the Wazuh agent) and record
        the run's start so collect() can pull the manager's alerts for the window.

        Correlate by the run's *own* agent name when the detonation environment
        assigned one: with per-clone unique enrollment (LocalAppliance.agent_name_for)
        each run registers a distinct agent, so filtering the window by that name is
        exact and back-to-back runs never cross-attribute or collide on the shared id.
        Falls back to the statically configured `agent` (e.g. the shared golden name)
        when the environment exposes no per-run name — the pre-enrollment behavior."""
        since = self._clock()
        run_id = self._env.detonate(sample, profile, self._timeout)
        agent = self._agent
        resolver = getattr(self._env, "agent_name_for", None)
        if callable(resolver):
            run_agent = resolver(run_id)
            if run_agent:
                agent = run_agent
        self._runs[run_id] = _RunWindow(profile=profile, since=since, agent=agent)
        return run_id

    def collect(self, run_id: str) -> Iterable[Indicator]:
        """Pull the manager's alerts for the run's window, drop noise below
        `min_level`, and translate each into a dispatch-tier Indicator. Always
        reverts the detonation profile afterward so the lab is left clean."""
        window = self._runs.get(run_id)
        if window is None:
            raise KeyError(f"unknown run_id: {run_id}")
        try:
            alerts = self._backend.alerts_since(window.since, agent=window.agent)
            return [
                self._translate(a) for a in alerts if a.level >= self._min_level
            ]
        finally:
            self._env.revert(window.profile)
            self._runs.pop(run_id, None)

    def _translate(self, alert: WazuhAlert) -> Indicator:
        return Indicator(
            # Stable key: rule + description collapses repeats of the same rule in a
            # run to one indicator (the finding, not each hit).
            id=indicator_id(_MODULE, alert.rule_id, alert.description),
            name=f"wazuh-rule-{alert.rule_id}",
            severity=alert_to_severity(alert.level),
            tier=Tier.DISPATCH,
            module=_MODULE,
            attack=list(alert.mitre),
            description=alert.description,
            evidence={
                "rule_id": alert.rule_id,
                "level": alert.level,
                "groups": alert.groups,
                "agent": alert.agent,
            },
        )


# The HTTP boundary: post a JSON body to a URL and return the parsed JSON response.
# Injected the same way as the VM `CommandRunner` and code-identity `Runner`, so the
# query construction + response parsing are exercised with no live indexer, and the
# only live-network touch is the default transport.
HttpPost = Callable[..., dict]


def _default_post(url: str, *, json: dict, auth: tuple[str, str], verify: bool, timeout: float) -> dict:
    """Live transport (optional `[wazuh]` extra). Kept out of import path so the
    module loads without `requests`; only a real query pulls it in."""
    import requests  # noqa: PLC0415

    resp = requests.post(url, json=json, auth=auth, verify=verify, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _to_iso_utc(epoch: float) -> str:
    """Epoch seconds -> ISO-8601 UTC with millisecond precision, e.g.
    `2026-07-01T18:04:05.123Z` — the format the indexer's `@timestamp` range query
    expects (verified against the Indexer API docs)."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_ts(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    # Wazuh stamps like 2026-07-01T18:04:05.123+0000; normalize the offset/Z for fromisoformat.
    text = value.replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class LiveWazuhBackend:
    """Live Wazuh backend — queries the Wazuh **indexer**, not the server API.

    Version pin (ROADMAP "Verify at build", checked 2026-07): Wazuh **4.14.x**
    (v4.14.6 latest patch). 5.0 is still in beta and its indexer upgrade is one-way, so
    production stays on 4.14 until 5.0 GA; the custom-log-source integration is
    unaffected between them. Watch the 5.0 note when it lands.

    Alerts are documents in the indexer's `wazuh-alerts-4.x-*` indices — the server
    API on :55000 manages agents/rules/config and does **not** serve alert documents.
    So a detonation window is correlated by querying the Indexer REST API:

        POST https://<indexer>:9200/wazuh-alerts*/_search
        { range on @timestamp >= window start [, term on agent.name], sort, size }

    with basic auth over self-signed TLS. The single query is capped at 10k hits by
    the indexer's `max_result_window`; `size` bounds it (a detonation window is small).
    The HTTP call is the injected `post` boundary."""

    DEFAULT_PORT = 9200

    def __init__(
        self,
        indexer_url: str,
        *,
        user: str,
        password: str,
        index: str = "wazuh-alerts*",
        verify: bool | str = True,
        size: int = 1000,
        timeout: float = 30.0,
        post: HttpPost | None = None,
    ) -> None:
        # `verify` defaults to True. The indexer ships a self-signed cert; point this
        # at the indexer's root CA bundle (a path) rather than disabling verification.
        self.indexer_url = indexer_url.rstrip("/")
        self.user = user
        self.password = password
        self.index = index
        self.verify = verify
        self.size = size
        self.timeout = timeout
        self._post = post or _default_post

    def _search_url(self) -> str:
        return f"{self.indexer_url}/{self.index}/_search"

    def _build_query(self, since: float, agent: str | None) -> dict:
        filters: list[dict] = [{"range": {"@timestamp": {"gte": _to_iso_utc(since)}}}]
        if agent:
            filters.append({"term": {"agent.name": agent}})
        return {
            "size": self.size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": filters}},
        }

    def alerts_since(self, since: float, *, agent: str | None = None) -> list[WazuhAlert]:
        doc = self._post(
            self._search_url(),
            json=self._build_query(since, agent),
            auth=(self.user, self.password),
            verify=self.verify,
            timeout=self.timeout,
        )
        hits = ((doc or {}).get("hits") or {}).get("hits") or []
        return [_hit_to_alert(h) for h in hits]


def _hit_to_alert(hit: dict) -> WazuhAlert:
    """Map one indexer `_search` hit to a `WazuhAlert`. Defensive at this boundary:
    real alert documents vary in which optional fields (mitre, groups, agent) are set."""
    src = hit.get("_source") or {}
    rule = src.get("rule") or {}
    mitre = (rule.get("mitre") or {}).get("id") or []
    agent = (src.get("agent") or {}).get("name")
    return WazuhAlert(
        rule_id=str(rule.get("id", "")),
        level=int(rule.get("level", 0) or 0),
        description=rule.get("description", ""),
        mitre=list(mitre),
        groups=list(rule.get("groups") or []),
        agent=agent,
        timestamp=_parse_ts(src.get("@timestamp")),
        raw=src,
    )
