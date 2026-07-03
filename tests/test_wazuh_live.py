"""Live integration: LiveWazuhBackend against a real Wazuh indexer.

Opt-in and self-skipping: runs only when `WAZUH_INDEXER_URL` points at a reachable
indexer, so the default offline suite is unaffected and the repo stays portable. This
is the durable version of the manual "verify, don't guess" proof done when the Phase-2
Wazuh stack was first stood up (wazuh-docker 4.14.x single-node).

Environment:
  WAZUH_INDEXER_URL       e.g. https://wazuh.indexer:9200   (required to run)
  WAZUH_INDEXER_USER      indexer user (default: admin)
  WAZUH_INDEXER_PASS      indexer password (default: SecretPassword)
  WAZUH_INDEXER_CA        path to the indexer's root CA (verify against it; TLS stays on)
  WAZUH_INDEXER_RESOLVE   optional "host=ip" (curl --resolve equivalent) so a demo cert
                          issued for the node name verifies while connecting to loopback
"""

import os
import socket
import time

import pytest

from modules.dispatch.wazuh import LiveWazuhBackend, WazuhModule

URL = os.environ.get("WAZUH_INDEXER_URL")
pytestmark = pytest.mark.skipif(not URL, reason="WAZUH_INDEXER_URL unset (live indexer test)")

USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
PASS = os.environ.get("WAZUH_INDEXER_PASS", "SecretPassword")
CA = os.environ.get("WAZUH_INDEXER_CA")
VERIFY = CA if CA else True
ALERTS_INDEX = "wazuh-alerts-4.x-*"


def _apply_resolve():
    """Honor WAZUH_INDEXER_RESOLVE=host=ip so TLS verifies against a node-name cert
    while connecting to loopback (real hostname check, no /etc/hosts edit, no verify=off)."""
    spec = os.environ.get("WAZUH_INDEXER_RESOLVE")
    if not spec or "=" not in spec:
        return
    name, ip = spec.split("=", 1)
    orig = socket.getaddrinfo
    socket.getaddrinfo = lambda host, *a, **k: orig(ip if host == name else host, *a, **k)


_apply_resolve()


def _reachable() -> bool:
    if not URL:
        return False
    host = URL.split("://", 1)[-1].split("/", 1)[0]
    hostname, _, port = host.partition(":")
    target = os.environ.get("WAZUH_INDEXER_RESOLVE", "").split("=", 1)
    connect_host = target[1] if len(target) == 2 and target[0] == hostname else hostname
    try:
        with socket.create_connection((connect_host, int(port or 9200)), timeout=3):
            return True
    except OSError:
        return False


requires_reachable = pytest.mark.skipif(not _reachable(), reason="indexer URL not reachable")


@requires_reachable
def test_query_roundtrips_and_parses_real_alerts():
    # A wide window over whatever the manager has recorded: the query must round-trip
    # over CA-verified TLS and every hit must parse into a well-typed WazuhAlert.
    be = LiveWazuhBackend(URL, user=USER, password=PASS, verify=VERIFY)
    alerts = be.alerts_since(time.time() - 30 * 86400)
    assert isinstance(alerts, list)
    for a in alerts:
        assert isinstance(a.rule_id, str) and a.rule_id
        assert isinstance(a.level, int)
        assert isinstance(a.mitre, list)


@requires_reachable
def test_seeded_mitre_alert_parses_into_indicator():
    # Seed one MITRE-tagged alert, query it back scoped to its agent, and confirm the
    # full path: real _search -> WazuhAlert (mitre intact) -> dispatch-tier Indicator.
    import requests  # noqa: PLC0415

    now = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now))
    index = time.strftime("wazuh-alerts-4.x-%Y.%m.%d", time.gmtime(now))
    agent = "scratchingpost-livetest"
    doc = {
        "@timestamp": ts,
        "rule": {"id": "100002", "level": 12, "description": "ptrace attach (livetest)",
                 "mitre": {"id": ["T1055.008", "T1622"]}, "groups": ["scratchingpost", "injection"]},
        "agent": {"name": agent, "id": "999"},
    }
    base = URL.rstrip("/")
    try:
        r = requests.post(f"{base}/{index}/_doc?refresh=wait_for",
                          json=doc, auth=(USER, PASS), verify=VERIFY, timeout=10)
        r.raise_for_status()

        be = LiveWazuhBackend(URL, user=USER, password=PASS, verify=VERIFY)
        alerts = [a for a in be.alerts_since(now - 300, agent=agent) if a.rule_id == "100002"]
        assert alerts, "seeded alert not returned"
        assert alerts[0].mitre == ["T1055.008", "T1622"]

        class _Env:
            def detonate(self, *a): return "r"
            def revert(self, *a): pass

        class _Backend:
            def alerts_since(self, since, *, agent=None): return alerts

        mod = WazuhModule(_Env(), _Backend(), agent=agent)
        inds = list(mod.collect(mod.dispatch(None, "wazuh")))
        assert inds[0].tier.value == "dispatch"
        assert inds[0].attack == ["T1055.008", "T1622"]
    finally:
        requests.post(f"{base}/{ALERTS_INDEX}/_delete_by_query?refresh=true",
                      json={"query": {"term": {"agent.name": agent}}},
                      auth=(USER, PASS), verify=VERIFY, timeout=10)
