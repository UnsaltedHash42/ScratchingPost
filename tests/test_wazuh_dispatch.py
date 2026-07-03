"""Wazuh dispatch tier (modules/dispatch/wazuh.py).

The Wazuh manager is behind an injected `WazuhBackend`, so the whole
dispatch->collect->translate->score chain runs with no live manager, no agent, and
no guest — the same offline-testability the VM provider and code-identity runner
give the other tiers.
"""

from pathlib import Path

import pytest

from modules.dispatch import (
    LiveWazuhBackend,
    WazuhAlert,
    WazuhModule,
    alert_to_severity,
)
from orchestrator.contracts.indicator import Severity, Tier
from orchestrator.contracts.module import ModuleCaps
from orchestrator.contracts.sample import Sample
from orchestrator.detonation import LocalAppliance
from orchestrator.scoring import score_indicators

FIX = Path(__file__).parent / "fixtures" / "macho"


class RecordingEnv:
    """Minimal DetonationEnvironment: hands back a run_id and records detonate/
    revert so the dispatch lifecycle can be asserted without a real appliance."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self._n = 0

    def detonate(self, sample, profile, timeout):
        self._n += 1
        run_id = f"run{self._n}"
        self.calls.append(("detonate", profile, timeout, run_id))
        return run_id

    def revert(self, profile):
        self.calls.append(("revert", profile))


class EnrollingEnv(RecordingEnv):
    """A DetonationEnvironment that assigns a unique per-run agent name (as
    LocalAppliance does under per-clone unique enrollment) via `agent_name_for`."""

    def __init__(self, agent_name):
        super().__init__()
        self._agent_name = agent_name

    def agent_name_for(self, run_id):
        return self._agent_name


class FakeBackend:
    """Canned Wazuh manager: returns a fixed alert set and records the query
    window/agent it was asked for."""

    def __init__(self, alerts):
        self.alerts = alerts
        self.queries: list[tuple] = []

    def alerts_since(self, since, *, agent=None):
        self.queries.append((since, agent))
        return list(self.alerts)


def _sample():
    return Sample.from_path(str(FIX / "thin_arm64"))


def _alert(rule_id="100002", level=12, desc="Shell spawned by suspicious parent",
           mitre=("T1059.004",), groups=("macos", "attack"), agent="wazuh-guest"):
    return WazuhAlert(
        rule_id=rule_id, level=level, description=desc, mitre=list(mitre),
        groups=list(groups), agent=agent, timestamp=1000.0, raw={"rule": {"id": rule_id}},
    )


def test_capabilities_is_dispatch_only():
    mod = WazuhModule(RecordingEnv(), FakeBackend([]))
    assert mod.capabilities() is ModuleCaps.DISPATCH


def test_level_to_severity_boundaries():
    assert alert_to_severity(2) is Severity.INFO
    assert alert_to_severity(4) is Severity.LOW
    assert alert_to_severity(7) is Severity.MEDIUM
    assert alert_to_severity(12) is Severity.HIGH
    assert alert_to_severity(15) is Severity.HIGH


def test_dispatch_detonates_then_collect_translates_alert():
    env = RecordingEnv()
    backend = FakeBackend([_alert()])
    mod = WazuhModule(env, backend, agent="wazuh-guest", clock=lambda: 123.0, timeout=45.0)

    run_id = mod.dispatch(_sample(), "wazuh")
    assert env.calls[0] == ("detonate", "wazuh", 45.0, run_id)

    inds = list(mod.collect(run_id))
    assert len(inds) == 1
    ind = inds[0]
    assert ind.tier is Tier.DISPATCH
    assert ind.module == "dispatch.wazuh"
    assert ind.severity is Severity.HIGH          # level 12
    assert ind.name == "wazuh-rule-100002"
    assert ind.attack == ["T1059.004"]
    assert ind.evidence["rule_id"] == "100002"
    assert ind.evidence["level"] == 12

    # The manager was queried for the detonation window + the profile's agent.
    assert backend.queries == [(123.0, "wazuh-guest")]


def test_dispatch_correlates_by_env_per_run_agent_name():
    # With per-clone unique enrollment the env assigns each run a distinct agent name;
    # the module must correlate the window by THAT name, not the statically configured
    # (shared) one — so back-to-back runs never cross-attribute or collide on id 001.
    env = EnrollingEnv("scratchingpost-deadbeefcafef00d")
    backend = FakeBackend([_alert()])
    mod = WazuhModule(env, backend, agent="scratchingpost-wazuh.shared", clock=lambda: 1.0)
    list(mod.collect(mod.dispatch(_sample(), "wazuh")))
    assert backend.queries == [(1.0, "scratchingpost-deadbeefcafef00d")]


def test_dispatch_falls_back_to_configured_agent_without_per_run_name():
    # No per-run name (env exposes none, or enrollment fell back to the shared
    # identity) -> keep the configured agent, the pre-enrollment behavior.
    for env in (RecordingEnv(), EnrollingEnv(None)):
        backend = FakeBackend([_alert()])
        mod = WazuhModule(env, backend, agent="scratchingpost-wazuh.shared", clock=lambda: 2.0)
        list(mod.collect(mod.dispatch(_sample(), "wazuh")))
        assert backend.queries == [(2.0, "scratchingpost-wazuh.shared")]


def test_min_level_filters_noise():
    env = RecordingEnv()
    backend = FakeBackend([_alert(rule_id="1", level=2, desc="low"),
                           _alert(rule_id="2", level=8, desc="real")])
    mod = WazuhModule(env, backend)  # default min_level=3
    run_id = mod.dispatch(_sample(), "wazuh")
    inds = list(mod.collect(run_id))
    assert [i.evidence["rule_id"] for i in inds] == ["2"]


def test_collect_reverts_profile_and_forgets_run():
    env = RecordingEnv()
    mod = WazuhModule(env, FakeBackend([_alert()]))
    run_id = mod.dispatch(_sample(), "wazuh")
    list(mod.collect(run_id))
    assert ("revert", "wazuh") in env.calls
    # Run bookkeeping cleared: a second collect is a KeyError.
    with pytest.raises(KeyError):
        mod.collect(run_id)


def test_collect_reverts_even_if_backend_raises():
    class Boom:
        def alerts_since(self, since, *, agent=None):
            raise RuntimeError("manager unreachable")

    env = RecordingEnv()
    mod = WazuhModule(env, Boom())
    run_id = mod.dispatch(_sample(), "wazuh")
    with pytest.raises(RuntimeError, match="manager unreachable"):
        mod.collect(run_id)
    assert ("revert", "wazuh") in env.calls  # lab still left clean


def test_unknown_run_id_raises():
    mod = WazuhModule(RecordingEnv(), FakeBackend([]))
    with pytest.raises(KeyError):
        mod.collect("nope")


def test_indicator_ids_deterministic_for_same_alert():
    env = RecordingEnv()
    backend = FakeBackend([_alert()])
    mod = WazuhModule(env, backend)
    a = list(mod.collect(mod.dispatch(_sample(), "wazuh")))
    b = list(mod.collect(mod.dispatch(_sample(), "wazuh")))
    assert [i.id for i in a] == [i.id for i in b]


def test_dispatch_indicators_feed_the_score():
    env = RecordingEnv()
    backend = FakeBackend([_alert(level=12)])  # HIGH dispatch = 8 * 2.0 = 16
    mod = WazuhModule(env, backend)
    inds = list(mod.collect(mod.dispatch(_sample(), "wazuh")))
    result = score_indicators(inds)
    assert result.by_tier["dispatch"] == 16.0
    assert result.verdict == "suspicious"  # 16 >= suspicious threshold (12)


def test_over_real_local_appliance_seam():
    # Drive the actual detonation seam (LocalAppliance) rather than a fake env:
    # dispatch->detonate returns a real run_id, collect->revert clears it.
    env = LocalAppliance()  # no capture resolver: dispatch doesn't need telemetry
    backend = FakeBackend([_alert()])
    mod = WazuhModule(env, backend)
    run_id = mod.dispatch(_sample(), "wazuh")
    inds = list(mod.collect(run_id))
    assert inds and inds[0].tier is Tier.DISPATCH


def _search_hit(rule_id="100002", level=12, desc="ptrace attach",
                mitre=("T1055.008",), groups=("scratchingpost", "injection"),
                agent="wazuh-guest", ts="2026-07-01T18:04:05.123+0000"):
    return {
        "_source": {
            "@timestamp": ts,
            "rule": {"id": rule_id, "level": level, "description": desc,
                     "mitre": {"id": list(mitre)}, "groups": list(groups)},
            "agent": {"name": agent},
        }
    }


class FakePost:
    """Injected HTTP boundary: records the request and returns a canned indexer
    `_search` response, so LiveWazuhBackend runs with no live indexer."""

    def __init__(self, hits):
        self.hits = hits
        self.calls: list[dict] = []

    def __call__(self, url, *, json, auth, verify, timeout):
        self.calls.append({"url": url, "json": json, "auth": auth,
                           "verify": verify, "timeout": timeout})
        return {"hits": {"hits": list(self.hits)}}


def _live_backend(post):
    # verify is the indexer's self-signed CA bundle path (not disabled).
    return LiveWazuhBackend(
        "https://indexer.local:9200/", user="admin", password="secret",
        verify="/etc/wazuh/root-ca.pem", post=post,
    )


def test_live_backend_queries_indexer_search_endpoint():
    post = FakePost([_search_hit()])
    _live_backend(post).alerts_since(1000.0, agent="wazuh-guest")

    call = post.calls[0]
    # Indexer _search endpoint (NOT the :55000 server API), trailing slash trimmed.
    assert call["url"] == "https://indexer.local:9200/wazuh-alerts*/_search"
    assert call["auth"] == ("admin", "secret")
    assert call["verify"] == "/etc/wazuh/root-ca.pem"
    filters = call["json"]["query"]["bool"]["filter"]
    # Window start is a @timestamp range; agent scopes to the profile guest.
    assert filters[0]["range"]["@timestamp"]["gte"].endswith("Z")
    assert {"term": {"agent.name": "wazuh-guest"}} in filters
    assert call["json"]["sort"] == [{"@timestamp": {"order": "asc"}}]


def test_live_backend_omits_agent_filter_when_unset():
    post = FakePost([])
    _live_backend(post).alerts_since(0.0)
    filters = post.calls[0]["json"]["query"]["bool"]["filter"]
    assert not any("term" in f for f in filters)


def test_live_backend_parses_hits_into_alerts():
    post = FakePost([_search_hit(rule_id="100002", level=12, mitre=("T1055.008", "T1622"))])
    alerts = _live_backend(post).alerts_since(1000.0)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "100002"
    assert a.level == 12
    assert a.mitre == ["T1055.008", "T1622"]
    assert a.agent == "wazuh-guest"
    assert a.timestamp is not None

    # End to end through the module: a translated indicator carries the ATT&CK ids.
    ind = WazuhModule(RecordingEnv(), FakeBackend(alerts))
    got = list(ind.collect(ind.dispatch(_sample(), "wazuh")))
    assert got[0].attack == ["T1055.008", "T1622"]


def test_live_backend_tolerates_sparse_alert_documents():
    # Real alerts vary in which optional fields are present; parsing must not raise.
    post = FakePost([{"_source": {"rule": {"id": "5502", "level": 5}}}])
    alerts = _live_backend(post).alerts_since(0.0)
    assert alerts[0].rule_id == "5502" and alerts[0].mitre == [] and alerts[0].agent is None


def test_live_backend_default_transport_needs_requests():
    # Without an injected transport the live path pulls in `requests` (the [wazuh]
    # extra); it must fail loud if absent, never silently return nothing.
    import importlib.util

    if importlib.util.find_spec("requests") is not None:
        pytest.skip("requests installed; default transport would attempt a real POST")
    backend = LiveWazuhBackend("https://indexer.local:9200", user="u", password="p")
    with pytest.raises(ModuleNotFoundError):
        backend.alerts_since(0.0)
