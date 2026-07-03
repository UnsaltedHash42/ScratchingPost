# `wazuh` profile — manager config + custom detection content

The Wazuh dispatch tier (`modules/dispatch/wazuh.py`, MODULE_CONTRACT.md §7). Wazuh is
**not** an ESF behavioral sensor on macOS, so it plays two roles:

- **Persistent detection backend** on the durable side (ARCHITECTURE.md §9): manager +
  indexer + dashboard. Holds rules, alert history, fleet inventory — survives a revert.
- **Real-agent dispatch module**: detonate the sample in the `wazuh` profile (a guest
  running the Wazuh agent), then `collect()` the manager's alerts for that run window and
  translate them into dispatch-tier `Indicator`s.

The behavioral telemetry Wazuh can't collect on macOS comes from ScratchingPost's own ESF
recorder, piped in as a **custom log source** with the **MITRE-tagged custom rules** here.

## Version pin

**Wazuh 4.14.x** (v4.14.6 latest patch, checked 2026-07). 5.0 is still in beta; its indexer
upgrade is one-way, so production stays on 4.14 until 5.0 GA. The custom-log-source
integration (JSON localfile + `local_rules.xml`) is unaffected between the two. Revisit the
alert-query path if 5.0's native indexer connector changes the `wazuh-alerts-*` index shape.

## Where alerts come from (the live backend)

Alerts are documents in the indexer's `wazuh-alerts-4.x-*` indices — the **server API on
:55000 manages agents/rules/config and does not serve alert documents**. `LiveWazuhBackend`
therefore queries the **Indexer REST API**:

```
POST https://<indexer>:9200/wazuh-alerts*/_search
{ "query": {"bool": {"filter": [ {"range": {"@timestamp": {"gte": "<window-start ISO8601>"}}},
                                  {"term": {"agent.name": "<profile guest>"}} ]}},
  "sort": [{"@timestamp": {"order": "asc"}}], "size": 1000 }
```

Basic auth over self-signed TLS. A detonation window is small, well under the indexer's 10k
`max_result_window`. The HTTP call is an injected boundary, so the query construction and
response parsing are unit-tested with no live indexer (`tests/test_wazuh_dispatch.py`).

## Files here

| File | Install location on the Wazuh **manager** |
|---|---|
| `local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` |
| `local_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` (only for the tagged-syslog transport; see the file) |
| `ossec.conf.snippet` | merge the `<localfile>` into `/var/ossec/etc/ossec.conf` (agent or manager, wherever the recorder writes) |

After editing rules/decoders, `sudo /var/ossec/bin/wazuh-control restart` and confirm with
`/var/ossec/bin/wazuh-logtest` that a sample ESF JSON line fires the expected rule.

## Ingestion contract

The recorder emits the uniform Event schema (`orchestrator.contracts.events.Event.to_dict`),
one JSON object per line: top-level `event_type`, nested `process.*` code-identity, `payload.*`.
`<log_format>json</log_format>` engages Wazuh's built-in JSON decoder; rules address fields by
dotted name. Rule ids use the reserved 100000+ range; levels follow Wazuh's 0-15 scale (12+ =
high, mapped to ScratchingPost HIGH by `alert_to_severity`). Every attack rule carries its MITRE
technique id(s), which the dispatch module reads back from `rule.mitre.id`.

## Standing up the stack — status

The persistent manager/indexer/dashboard stack is a Linux deployment (Docker or a durable
Linux VM). **Stood up and verified** (wazuh-docker **4.14.6** single-node, indexer on
`:9200`): `LiveWazuhBackend` round-trips `_search` over CA-verified TLS and parses real
hits, and `local_rules.xml` fires in the manager with correct MITRE tagging (confirmed via
`wazuh-logtest`). Reproduce the stand-up from Wazuh's official deployment, pinned to 4.14
(single-node dev topology):

```sh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.6 --depth 1
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator   # one-time cert bootstrap
docker compose up -d                                              # manager :55000, indexer :9200, dashboard :443
```

Then point `LiveWazuhBackend` at `https://<host>:9200` with the indexer credentials and the
generated root CA as `verify`. The demo indexer cert is issued for the node name
(`DNS:wazuh.indexer`, not `localhost`), so verify against the CA by reaching the indexer
under that name (a `--resolve`/hosts entry to loopback for a single-node lab), or use a cert
that covers your access hostname — do not disable verification.

**Done (manager/indexer side):** `LiveWazuhBackend` verified against the live indexer over
CA-verified TLS (`tests/test_wazuh_live.py`, live-gated on `WAZUH_INDEXER_URL`); rules loaded
and firing (`wazuh-logtest`).

**Done (guest side) — the ESF→Wazuh custom log source is wired end-to-end.** The
`ScratchingPost-wazuh` golden has the 4.14.6 macOS agent (`WAZUH_MANAGER=10.0.0.9`) baked in
and now also has the `<localfile>` above installed in `/Library/Ossec/etc/ossec.conf`, tailing
`/var/log/scratchingpost/events.jsonl`. Proven live by `tests/test_wazuh_e2e.py`: a real full
clone + detonation of an adhoc Mach-O trips custom rule **100020** (unsigned/adhoc exec, T1553),
forwarded by the guest agent → manager → indexer, correlated by `LiveWazuhBackend` and scored.
Config survives a full clone (the E2E clones the golden per run).

### How the ESF stream reaches Wazuh (the mechanism)

Stock `eslogger` does **not** emit the uniform schema the rules key on — its raw ES output uses
a numeric `event_type` (9=exec, 13=create, …) and `process.executable.path`, so a source pointed
straight at eslogger fires none of the 100000+ rules. So the seam:

1. runs stock eslogger in the guest and converts the raw capture to the uniform schema
   **host-side** (`sensors.eslogger.parser` → `Event.to_dict`), then
2. pushes that uniform JSONL back into the running clone at
   `LocalAppliance.agent_ingest_path` (= the `<localfile>` location), where the **real in-guest
   agent** tails and forwards it — so alerts attribute to `scratchingpost-wazuh.shared`.

Two capture-quality knobs are required and set by the wazuh env (both default off elsewhere):

- **`detonate_settle`** (~20 s): wait out the boot storm before capturing. A fresh macOS guest
  emits ~15k events/s at boot; capturing through it produces a ~300 MB firehose that buries the
  sample, drops its events under ES-client load, and trips rules on system noise (e.g.
  `coreservicesd` `get_task` → 100001). After the settle a short capture is a few hundred KB.
- **`eslogger_start_delay`** (~3 s): pause after launching eslogger before the sample runs, so
  the ES client finishes subscribing (an instant sample otherwise acts before eslogger listens).
- **`eslogger_events`** reduced to the rule-relevant, low-volume set
  (`exec create rename get_task trace cs_invalidated btm_launch_item_add`) — dropping the
  `write`/`mmap`/`mprotect`/`signal` firehose (each alone re-floods to hundreds of MB).

### Rebuilding the golden's agent config (if the golden is rebuilt)

```sh
# in the guest (prlctl exec runs as root; no GUI needed — this is config, not a sysext):
#  1. merge the <localfile> from ossec.conf.snippet into /Library/Ossec/etc/ossec.conf
#  2. mkdir -p /var/log/scratchingpost && : > /var/log/scratchingpost/events.jsonl
#  3. /Library/Ossec/bin/wazuh-control restart
#  4. confirm: grep "Analyzing file: '/var/log/scratchingpost/events.jsonl'" /Library/Ossec/logs/ossec.log
```

## Agent identity: shared (default) vs per-clone unique

Every clone reuses the golden's baked `client.keys` (agent id 001,
`scratchingpost-wazuh.shared`), correlated by time window + agent name. This is the
**default and the reliable path**, with two caveats handled in code (`_sync_guest_clock`,
graceful agent stop before clone delete) plus one operational rule: a stale id-001 remoted
connection inherited at session start zeroes the dispatch tier, so **restart the manager
daemons once before the first live run of a session**
(`docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart`).

`LocalAppliance(unique_enrollment=True)` (**default False**) instead enrolls each clone as
its own agent — `agent-auth -A scratchingpost-<clone-uuid>` (manager address read from the
guest's own `ossec.conf`), correlated by `agent_name_for(run_id)` — which removes the
shared-id collision at the root. It registers, correlates, and forwards correctly in
isolation, **but is not yet reliable in the wazuh-docker lab**: every Parallels clone NATs to
the Dockerized manager through one source IP (`192.168.65.1`), and `remoted` intermittently
(~1 run in 3) rejects a freshly-enrolled agent from that shared IP (`Invalid ID N for source
ip ...`) so it never connects and forwards nothing. The durable fix is **per-clone routable
identity** (bridged per-clone networking, or a non-Dockerized manager so each guest reaches
`remoted` as itself) — infrastructure, not guest-side retry. Enable `unique_enrollment=True`
only in an environment without the shared-source-IP race.
