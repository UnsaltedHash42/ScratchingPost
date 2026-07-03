"""Live end-to-end: a real detonation in the `wazuh` profile, through the whole
dispatch path — LocalAppliance (live, wazuh golden) -> WazuhModule -> LiveWazuhBackend
-> conductor.analyze -> DetectionScore.

Heavy and opt-in. Unlike `test_wazuh_live.py` (which only exercises the indexer query),
this clones and boots the `ScratchingPost-wazuh` golden, detonates a real sample in it,
and correlates the agent's manager-side alerts for the run window. It therefore needs
BOTH a reachable indexer AND the wazuh detonation golden built (BUILD_GOLDEN.md), so it
gates on an explicit opt-in and self-skips everywhere else — the offline suite and the
lighter live suite are unaffected.

Enable (operator, once the golden exists and the stack is up):
  SCRATCHINGPOST_WAZUH_E2E=1        required to run at all (heavy Parallels detonation)
  SCRATCHINGPOST_WAZUH_GOLDEN       wazuh golden name (default: ScratchingPost-wazuh)
  WAZUH_INDEXER_URL                 e.g. https://wazuh.indexer:9200
  WAZUH_INDEXER_USER / _PASS        indexer creds (default admin / SecretPassword)
  WAZUH_INDEXER_CA                  indexer root CA path (TLS stays on)
  WAZUH_INDEXER_RESOLVE             optional "host=ip" so a node-name cert verifies to loopback
  WAZUH_E2E_AGENT                   optional agent.name to scope the window to the run's guest
"""

import os
import socket
import time

import pytest

from orchestrator import analyze
from orchestrator.contracts.sample import Sample
from orchestrator.detonation import LocalAppliance, ParallelsProvider
from orchestrator.scoring.score import DetectionScore
from modules.dispatch.wazuh import LiveWazuhBackend, WazuhModule

from pathlib import Path

pytestmark = pytest.mark.skipif(
    not os.environ.get("SCRATCHINGPOST_WAZUH_E2E"),
    reason="SCRATCHINGPOST_WAZUH_E2E unset (heavy live wazuh detonation)",
)

FIX = Path(__file__).parent / "fixtures" / "macho"
GOLDEN = os.environ.get("SCRATCHINGPOST_WAZUH_GOLDEN", "ScratchingPost-wazuh")
URL = os.environ.get("WAZUH_INDEXER_URL")
USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
PASS = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
CA = os.environ.get("WAZUH_INDEXER_CA")
VERIFY = CA if CA else True
AGENT = os.environ.get("WAZUH_E2E_AGENT")
# Path the wazuh golden's Wazuh agent tails (ossec.conf <localfile>); the seam pushes
# the run's converted uniform capture here so the agent forwards it and the custom
# MITRE rules fire attributed to the guest agent.
INGEST = os.environ.get("WAZUH_E2E_INGEST", "/var/log/scratchingpost/events.jsonl")


def _apply_resolve():
    spec = os.environ.get("WAZUH_INDEXER_RESOLVE")
    if not spec or "=" not in spec:
        return
    name, ip = spec.split("=", 1)
    orig = socket.getaddrinfo
    socket.getaddrinfo = lambda host, *a, **k: orig(ip if host == name else host, *a, **k)


_apply_resolve()


def test_wazuh_profile_detonation_flows_to_score():
    if not URL:
        pytest.skip("WAZUH_INDEXER_URL unset")

    sample = Sample.from_path(str(FIX / "thin_arm64"))

    # The behavioral tier is not under test here: a replay-backed appliance with no
    # capture yields empty telemetry, so analyze() runs the dispatch tier in isolation.
    behavioral_env = LocalAppliance()

    # The dispatch module drives its OWN live appliance, cloning the wazuh golden (the
    # agent-baked image) via the per-profile golden map.
    live_env = LocalAppliance(
        live=True,
        vm=ParallelsProvider(),
        golden_images={"wazuh": GOLDEN},
        # Feed the run's converted uniform capture to the in-guest Wazuh agent so the
        # custom ESF rules fire (stock eslogger's raw output would match none of them).
        agent_ingest_path=INGEST,
        # Rule-relevant, low-volume event set: dropping the write/mmap/mprotect/signal
        # firehose keeps a real capture at a few hundred KB (a full boot-storm capture is
        # ~300 MB and both buries the sample and trips rules on system noise).
        eslogger_events=("exec", "create", "rename", "get_task", "trace",
                         "cs_invalidated", "btm_launch_item_add"),
        # Wait out the boot storm before capturing, and let the ES client subscribe
        # before the sample runs (else its adhoc exec is dropped/missed).
        detonate_settle=20.0,
        eslogger_start_delay=3.0,
    )
    backend = LiveWazuhBackend(URL, user=USER, password=PASS, verify=VERIFY)
    mod = WazuhModule(live_env, backend, agent=AGENT, timeout=12.0)

    result = analyze(sample, "apple", env=behavioral_env, dispatch_modules=[mod])

    # The whole path returned one aggregate score; every dispatch indicator is
    # well-typed and tagged dispatch-tier.
    assert isinstance(result.score, DetectionScore)
    dispatch = [i for i in result.indicators if i.tier.value == "dispatch"]
    for ind in dispatch:
        assert ind.module == "dispatch.wazuh"
        assert isinstance(ind.attack, list)

    # A custom ScratchingPost ESF rule (id 100000+) must fire: the adhoc-signed
    # fixture's own exec trips rule 100020 (unsigned/adhoc execution, T1553), proving
    # our detection content — not just the agent's baseline alerts — convicted the
    # detonation via the real agent -> manager -> indexer path.
    def _rid(ind):
        try:
            return int(ind.evidence.get("rule_id", ""))
        except (TypeError, ValueError):
            return -1

    custom = [i for i in dispatch if _rid(i) >= 100000]
    assert custom, (
        "expected a custom ScratchingPost rule (id 100000+) to fire on the detonation; "
        f"dispatch rule ids seen: {[i.evidence.get('rule_id') for i in dispatch]}"
    )


BEHAVIOR_SAMPLE = Path(__file__).parents[1] / "samples" / "behavior" / "persist_launchagent"
INJECT_SAMPLE = Path(__file__).parents[1] / "samples" / "behavior" / "inject_taskport"


def _dispatch_env():
    return LocalAppliance(
        live=True,
        vm=ParallelsProvider(),
        golden_images={"wazuh": GOLDEN},
        agent_ingest_path=INGEST,
        eslogger_events=("exec", "create", "rename", "get_task", "trace",
                         "cs_invalidated", "btm_launch_item_add"),
        detonate_settle=20.0,
        eslogger_start_delay=3.0,
    )


def test_wazuh_convicts_persistence_behavior():
    """Behavior detection (not just adhoc exec): a self-acting sample drops a
    LaunchAgent plist on launch and the custom rule 100010 (T1543.001) fires through
    the wired + subtree-scoped + clock-synced path. Proves ScratchingPost catches
    malicious *behavior* — ROADMAP limitation 2 — not only that an unsigned binary ran.

    Build the sample first: `samples/behavior/build.sh`."""
    if not URL:
        pytest.skip("WAZUH_INDEXER_URL unset")
    if not BEHAVIOR_SAMPLE.exists():
        pytest.skip(f"behavior sample not built: {BEHAVIOR_SAMPLE} (run samples/behavior/build.sh)")

    sample = Sample.from_path(str(BEHAVIOR_SAMPLE))
    backend = LiveWazuhBackend(URL, user=USER, password=PASS, verify=VERIFY)
    mod = WazuhModule(_dispatch_env(), backend, agent=AGENT, timeout=12.0)

    result = analyze(sample, "apple", env=LocalAppliance(), dispatch_modules=[mod])

    dispatch = [i for i in result.indicators if i.tier.value == "dispatch"]
    fired = {str(i.evidence.get("rule_id")) for i in dispatch}
    assert "100010" in fired, (
        "expected rule 100010 (LaunchAgents persistence, T1543.001) to fire on the "
        f"self-acting sample; dispatch rule ids seen: {sorted(fired)}"
    )
    persist = next(i for i in dispatch if str(i.evidence.get("rule_id")) == "100010")
    assert "T1543.001" in persist.attack


def test_wazuh_convicts_injection_behavior():
    """Injection detection (ROADMAP limitation 2, the piece left open after
    persistence): a self-acting sample acquires another process's Mach task port
    with task_for_pid — the surviving macOS injection primitive — and the custom
    rule 100001 (task-port acquisition, T1055) fires through the wired +
    subtree-scoped + clock-synced path. The get_task event's acting process is the
    sample itself, so subtree scoping keeps it while system-service get_task noise
    (coreservicesd) is dropped.

    Build the sample first: `samples/behavior/build.sh`."""
    if not URL:
        pytest.skip("WAZUH_INDEXER_URL unset")
    if not INJECT_SAMPLE.exists():
        pytest.skip(f"injection sample not built: {INJECT_SAMPLE} (run samples/behavior/build.sh)")

    sample = Sample.from_path(str(INJECT_SAMPLE))
    backend = LiveWazuhBackend(URL, user=USER, password=PASS, verify=VERIFY)
    mod = WazuhModule(_dispatch_env(), backend, agent=AGENT, timeout=12.0)

    result = analyze(sample, "apple", env=LocalAppliance(), dispatch_modules=[mod])

    dispatch = [i for i in result.indicators if i.tier.value == "dispatch"]
    fired = {str(i.evidence.get("rule_id")) for i in dispatch}
    assert "100001" in fired, (
        "expected rule 100001 (task-port acquisition, T1055) to fire on the "
        f"self-injecting sample; dispatch rule ids seen: {sorted(fired)}"
    )
    inject = next(i for i in dispatch if str(i.evidence.get("rule_id")) == "100001")
    assert "T1055" in inject.attack
