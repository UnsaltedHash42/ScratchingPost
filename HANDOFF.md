# ScratchingPost — Handoff (end of 2026-07-02, session 8)

## What shipped this session (session 8) — per-clone unique agent enrollment (BUILT, OFF by default)

Chose candidate step 1 from the session-7 handoff (per-clone unique agent enrollment, the
"durable fix" for the shared-id-001 collision). It is **built, unit-tested (107→113 green),
and proven in isolation, but shipped OFF by default** because it is not yet reliable in this
lab. The reliable path (shared identity + graceful-stop + one-time session-start manager
restart) is unchanged and remains the default — no regression.

- **What it does:** `LocalAppliance(unique_enrollment=True)` (default **False**) enrolls each
  dispatch clone as its OWN Wazuh agent over exec — `agent-auth -m <manager from the guest's
  own ossec.conf> -A scratchingpost-<clone-uuid>` — with a safe fallback to the shared identity
  on any failure. `WazuhModule` correlates the run's alerts by that per-run name via the new
  `LocalAppliance.agent_name_for(run_id)` (duck-typed; falls back to the configured agent).
  No golden rebuild (tooling is already baked). New method `_enroll_unique_agent` +
  `_restart_and_wait_connected`; unit tests in `tests/test_detonation_api.py`.
- **Two real bugs found and fixed en route** (both live-diagnosed via the manager's authd/remoted
  log + `wazuh-agentd.state`):
  1. **Name must be the clone uuid, not run_id.** run_id is deterministic
     (`fnv1a(sha256:profile:counter)`), so repeat runs of a sample requested the SAME agent name
     and **authd rejected the duplicate** ("Agent 'NNN' can't be replaced since it is not
     disconnected") — this was the dominant cause of the "random" forward failures.
  2. **Confirm the MANAGER ack, not the agent's log.** The agent logs "Connected to the server"
     on TCP connect, but remoted drops its messages until it reloads the just-registered key.
     `_restart_and_wait_connected` polls `wazuh-agentd.state` for a real `last_ack`
     (manager-confirmed) and re-kicks the agent on the reload race.
- **Why it's off (the wall):** even after both fixes, ~1 live run in 3 still fails — the enrolled
  agent shows **"Never connected"** on the manager and forwards nothing. Root cause is
  environmental: every Parallels clone NATs to the **Dockerized** manager through ONE source IP
  (`192.168.65.1`), and remoted intermittently rejects an agent from that shared IP ("Invalid ID
  N for source ip ..."). Preempting id 001's boot connection (`wazuh-control stop` at enroll start
  so the unique agent claims the IP first) reduced but did not eliminate it. **The durable fix is
  per-clone routable identity** (bridged per-clone networking, or a non-Dockerized manager so each
  guest reaches remoted as itself), which is infra work — not more guest-side retry. Enable
  `unique_enrollment=True` only in an env without the shared-source-IP race.
- **Detection is NOT the issue** — proven again live this session: when a run's unique agent does
  connect, persist trips 100010, inject trips 100001, adhoc trips 100020 (scoped captures fire the
  rules via `wazuh-logtest`). Only the enroll→forward channel is flaky under the shared-IP race.
- **Lab left clean:** manager daemons restarted + all run-agents removed (only `001
  scratchingpost-wazuh.shared` remains), both goldens stopped, no run clones, Wazuh stack UP.

## Session 7 (end of 2026-07-02)

**State:** Phase 1 + Phase 1.5 conductor + Phase 2 Wazuh dispatch tier, ESF→Wazuh wired
end-to-end — and as of session 7 the sandbox **convicts both persistence AND injection behavior**,
not just an unsigned exec. Session 6 proved persistence (rule **100010**, T1543.001); session 7
proves **injection**: a self-acting sample (`samples/behavior/inject_taskport`) acquires another
process's Mach task port with `task_for_pid` and custom rule **100001 (task-port acquisition,
T1055, level 12)** fires through the full path (agent → manager → indexer → dispatch → score),
live-verified. **107 tests green + 6 skipped** (`/opt/homebrew/anaconda3/bin/python3 -m pytest
-q`; anaconda 3.12, not `.venv`). Skips: 1 requests-absent guard + 2 live-indexer (skip when
`WAZUH_INDEXER_URL` unset) + 3 live E2E (skip unless `SCRATCHINGPOST_WAZUH_E2E` set). VM lab
clean: goldens `ScratchingPost` (UUID `aab7fbd1…`) + `ScratchingPost-wazuh` (`a871bc3f…`) stopped,
no run clones. Wazuh Docker stack left UP.

## What shipped this session (session 7) — injection detection PROVEN (step 1a, path 2)

Took **path 2** of step 1a (self-acting self-injecting sample; the cheaper option that fits the
existing ~12 s window — no live-callback infra needed). Live-verified end to end.

- **New sample `samples/behavior/inject_taskport`** (adhoc arm64, source + wired into `build.sh`).
  On launch it `fork()`s a child (a plain fork of itself: same uid, adhoc, no hardened runtime),
  `usleep`s so the child is schedulable, then calls `task_for_pid(mach_task_self(), child, &port)`
  — the surviving macOS injection primitive — and immediately kills the child. It only *reads* the
  task port (no `mach_vm_write`, no remote thread), so it is minimal and safe; the clone is
  reverted regardless. Self-signs with `com.apple.security.get-task-allow` (via a build.sh
  entitlements plist) so `task_for_pid` succeeds even off the SIP-disabled guest — belt-and-braces;
  on the guest (root, SIP off) it is unrestricted anyway. **Verified the acquisition works on the
  host too** (`./inject_taskport` → `acquired task port for pid …`).
- **The kernel emits an ESF `get_task` event whose acting process is the sample**, so subtree
  scoping (session 6) *keeps* it (its subject pid is the sample's own) while system-service
  get_task noise (`coreservicesd`) is dropped. Confirmed against the real run's retained capture:
  raw eslogger had **3 get_task** events; the scoped capture pushed to the agent = **1 exec + 1
  get_task**, and that get_task line fires **100001 / level 12 / T1055 (Process Injection)** in the
  live manager via `wazuh-logtest` with `$(process.path)` resolving to the sample.
- **Live E2E `tests/test_wazuh_e2e.py::test_wazuh_convicts_injection_behavior`** (same wired +
  scoped + clock-synced path + env as the persistence test). **PASSED live (80.6 s):** a fresh
  100001 alert landed in the indexer from `scratchingpost-wazuh.shared` → dispatch indicator with
  `T1055` → score.
- **Reliability recurrence (documented, not a new bug):** the *first* injection run this session
  forwarded ZERO alerts even though detection worked — the shared-agent-identity collision. The
  Wazuh stack had been up 21 h, so a **stale remoted connection for agent id 001 survived from
  before this session** and silently refused the clone's agent (no `503` agent-started, nothing
  forwarded). The session-6 graceful-stop-before-delete fix covers *within-session* serial runs but
  not a stale connection inherited at session start. Cleared it with the documented one-time
  mitigation — `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart` — and
  the re-run passed. **This reinforces that the durable fix is per-clone unique agent enrollment**
  (open item below; the golden already has authd fallback — we observed a clone auto-register as
  agent 002 under its own hostname on a key collision). See the `wazuh-dispatch-reliability` memory.

## What shipped this session (session 6) — behavior detection + reliability

Blake: "do all three [behavior-detection steps], order up to you; build it to be a working app
and not to pass your tests." Did steps 2 + 1b (all live-validated); 1a deferred (needs infra).

- **Step 2 — subtree scoping (ROADMAP limitation 3, DONE).** `scope_events_to_subtree`
  (`orchestrator/detonation/api.py`) filters the capture pushed to the Wazuh agent to the
  sample's own **pid / ppid / `responsible_pid` lineage**, seeded on the sample's own exec
  (matched with `/private/tmp`→`/tmp` symlink normalization — without which the match fails on a
  real guest and scoping drops everything). Live-verified: two `coreservicesd` `get_task` noise
  events dropped (no 100001 false positive) while the sample's exec+behavior kept. **Safe
  fallback:** if the sample's exec is absent from the capture, forward the *full* capture rather
  than an empty one.
- **Step 1b — behavior detection PROVEN.** `samples/behavior/persist_launchagent` (adhoc arm64,
  source + `build.sh` in repo) drops `~/Library/LaunchAgents/…plist` on launch. Live detonation
  → rule **100010 (T1543.001, level 12) fires** end to end → SUSPICIOUS 46. Confirmed the rule
  matches our real event via `wazuh-logtest` too. Live-gated test
  `tests/test_wazuh_e2e.py::test_wazuh_convicts_persistence_behavior`.
- **Two live-only dispatch reliability bugs fixed** (both made the dispatch tier return ZERO
  indicators even though the rules fired — see the `wazuh-dispatch-reliability` memory):
  - **Clock skew.** A fresh clone boots ~tens of minutes behind real time; the agent stamps
    forwarded alerts with that skewed time, landing them *before* `WazuhModule`'s real-clock
    query window (verified: a run's 100020 landed 72 min behind → 0 indicators). Fix:
    `_sync_guest_clock` sets the guest clock to host UTC (`date -u ccyymmddHHMM.SS`) after boot,
    dispatch path only.
  - **Shared agent identity.** Every clone reuses the golden's `client.keys` (agent id 001).
    Abruptly deleting a clone leaves the manager's remoted holding a stale connection, so the next
    clone reusing key 001 is silently refused (`remoted: Agent key already in use`) — back-to-back
    runs forward nothing (verified: 3 rapid runs → 0 alerts each). Fix: `_revert_live` gracefully
    stops the in-guest agent (`/Library/Ossec/bin/wazuh-control stop`) **before** deleting the
    clone, freeing id 001 immediately (verified: 001 goes Disconnected, next run forwards). To
    clear an already-stuck id, `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart`.
  - Both unit-locked in `tests/test_detonation_api.py` (clock-set on the dispatch path only;
    agent-stop before delete on revert).
- **Step 1a — NOT started (needs Blake's infra).** Interactive/live-callback detonation to trip
  injection (100001) by tasking a Poseidon beacon needs the Mythic http listener reachable from
  the guest LAN + a window longer than 12 s. Deferred rather than build untested infra.

## What shipped this session (session 5) — ESF→Wazuh wiring

- **Key finding (evidence-backed):** stock `eslogger` does NOT emit our uniform schema — its
  raw ES output uses a **numeric** `event_type` (9=exec, 13=create, …) and
  `process.executable.path`. The custom rules key on the **uniform** schema (`event_type`
  string, `process.path`, `process.signature_type`, `payload.path`) produced only by the
  host-side `parse_line`→`Event.to_dict`. So the naive "point the agent's `<localfile>` at
  eslogger output" fires **zero** custom rules. (Verified: uniform JSON fires 100001 via
  `wazuh-logtest`; raw eslogger fields never match.)
- **Blake chose agent-side ingestion** (real-agent attribution). Guest has **no usable
  Python** (`/usr/bin/python3` is the CLT stub; `xcode-select --install` is GUI-gated), so
  the converter can't run in-guest. Resolution (delivers the same agent attribution without a
  guest runtime): keep the **host-side conversion** (exact tested parser, zero drift) and
  **push the converted uniform JSONL back into the running clone** at the agent's `<localfile>`
  path; the real in-guest agent forwards it → alerts attribute to `scratchingpost-wazuh.shared`.
- **Seam changes** (`orchestrator/detonation/api.py`, all default-off so the apple path + every
  existing test are unchanged):
  - `agent_ingest_path` — after host-side conversion, append the uniform capture into the clone
    at this guest path (chunked base64, then decode once — a full argv overflows ARG_MAX) and
    settle `agent_ingest_settle` (~20 s) for the agent→manager→indexer hop.
  - `detonate_settle` (~20 s) — wait out the boot storm before capturing. A fresh guest emits
    ~15k events/s at boot; capturing through it is a ~300 MB firehose that buries the sample,
    drops its events under ES-client load, and trips rules on system noise (`coreservicesd`
    `get_task`→100001). After the settle a short capture is a few hundred KB.
  - `eslogger_start_delay` (~3 s) — pause after launching eslogger before the sample runs so the
    ES client subscribes first (else an instant sample's exec is missed).
  - `_push_file` now chunks the base64 (100 KB/exec) so an arbitrarily large capture never
    overflows a single `exec` argv.
  - New unit tests: ingest push pushes the *uniform* capture to the localfile path; default-off
    leaves the apple path untouched.
- **Golden wired (config only, via `prlctl exec` — NO GUI wall):** installed the `<localfile>`
  (json, `/var/log/scratchingpost/events.jsonl`) into the agent's
  `/Library/Ossec/etc/ossec.conf` (backup at `ossec.conf.pre-scratchingpost`), created the
  ingest dir + empty file, restarted the agent, confirmed `logcollector: Analyzing file:
  '/var/log/scratchingpost/events.jsonl'`. Config survives a full clone (the passing E2E clones
  the golden per run). Manager already had `local_rules.xml` loaded (session 3); rules fire on
  uniform JSON (`wazuh-logtest` → 100001/T1055).
- **E2E** now uses the reduced event set (`exec create rename get_task trace cs_invalidated
  btm_launch_item_add`), `detonate_settle=20`, `eslogger_start_delay=3`, `agent_ingest_path`,
  window 12 s, and asserts a custom rule (id≥100000) fired. **PASSED live (79.8 s).**
- Docs reconciled: `profiles/wazuh/ossec.conf.snippet` comment (mechanism corrected) +
  `profiles/wazuh/README.md` (guest side marked done + mechanism/recipe + rebuild steps).

## Prior handoff (end of 2026-07-02, session 4)

**State (session 4):** Phase 1 + Phase 1.5 conductor + Phase 2 Wazuh dispatch tier (live indexer
backend, MITRE-tagged detection content, conductor wiring — all LIVE-VERIFIED against a
real wazuh-docker 4.14.6 stack). This session added the **per-profile golden map** (code +
test) and a **live-gated E2E test** for the wazuh detonation path. **101 tests green + 4
skipped.**

## What shipped this session (session 4)

- **Per-profile golden map** (`orchestrator/detonation/api.py`). `LocalAppliance` gained an
  optional `golden_images: dict[str,str]` arg alongside the existing single `golden_image`.
  `_golden_for(profile)` returns the per-profile override if registered, else falls back to
  `golden_image`. `detonate` resolves the profile's golden once and threads it through
  `_new_clone_name(golden)` and `_detonate_live(..., golden)`, so `detonate(sample,"wazuh")`
  clones `ScratchingPost-wazuh` while `apple` (and any unmapped profile) stays on
  `ScratchingPost`. Per-run clone name now traces back to the profile's golden. The change is
  fully behind the existing seam — **`WazuhModule` needed no change**: it already detonates
  `profile="wazuh"` through its injected `env`, so a caller just builds
  `LocalAppliance(golden_images={"wazuh":"ScratchingPost-wazuh"}, live=True, vm=…)`.
  Test: `tests/test_detonation_api.py::test_per_profile_golden_map_selects_the_right_image`.
- **Live-gated E2E test** `tests/test_wazuh_e2e.py`: drives the full path
  `LocalAppliance(live, wazuh golden) → WazuhModule → LiveWazuhBackend → conductor.analyze →
  DetectionScore`. Opt-in (`SCRATCHINGPOST_WAZUH_E2E=1` + `WAZUH_INDEXER_URL` + golden built),
  self-skips otherwise. **EXECUTED LIVE and PASSED** (2026-07-02, 61s): real Parallels
  clone/boot/detonate of `ScratchingPost-wazuh`, real query of the live indexer for the run
  window, translate → score. Ran with CA `…/root-ca.pem` + `WAZUH_INDEXER_RESOLVE=wazuh.indexer=127.0.0.1`.
  - **Real agent alerts landed in-window and flowed to the score:** 14 hits from
    `scratchingpost-wazuh.shared` in the run window (agent started, user login, session created,
    rootcheck anomaly, netstat port change, SCA/CIS-Tahoe findings), all level ≥3 → dispatch
    indicators. So the whole live path is proven against real agent telemetry, not just wiring.
  - **Caveat — these are the agent's BASELINE alerts, not our custom content.** They're Wazuh's
    native rootcheck/SCA/log-analysis alerts fired as the clone booted, NOT the MITRE-tagged
    ESF rules in `profiles/wazuh/local_rules.xml` (ids 100000+), and NOT driven by the sample.
    The benign sample tripped no custom rule. **The ESF→Wazuh custom-log-source integration is
    NOT wired inside the golden yet** — `profiles/wazuh/ossec.conf.snippet` (the `<localfile>`
    ESF json log source) must be installed in the golden and eslogger must write where the agent
    reads, so the agent ingests our ESF telemetry and the custom rules can fire on a detonation.
    That is the next Wazuh-tier piece.
  - The test's assertions are intentionally lenient (a benign sample's alert set is
    nondeterministic); for a run scoped to the guest, pass `WAZUH_E2E_AGENT=scratchingpost-wazuh.shared`
    so the score reflects the detonation guest, not manager (agent 000) housekeeping.

## Golden BUILT + gate PASSED (session 4, GUI session — Blake)

- **`ScratchingPost-wazuh` golden EXISTS and survives a FULL clone.** Blake ran
  `profiles/wazuh/BUILD_GOLDEN.md` on a GUI session: full-cloned the base, installed the
  4.14.6 macOS agent pointed at `WAZUH_MANAGER=10.0.0.9`, started it, confirmed check-in
  (`agent_control -l` → `001 scratchingpost-wazuh.shared` **Active**), then full-cloned the
  wazuh golden to `-run1` and confirmed the clone booted **Active** with the same identity
  (full clone copies `client.keys` — expected, fine for serial detonation). Run clone deleted;
  both goldens left stopped. **Gate passed** — the wazuh golden is detonation-ready.
- Manager container `single-node-wazuh.manager-1` has agent `001 scratchingpost-wazuh.shared`
  permanently registered from the golden — this is the identity every wazuh clone reuses
  (correlation is by time-window + agent name). Leave it. Host LAN IP **10.0.0.9** (DHCP).
- Indexer root CA for CA-verified TLS:
  `~/tools/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem`.
- **Task 2 (custom ESF sysext) — SKIPPED**, still blocked on the
  `systemextensionsctl developer on` GUI-click wall. Do NOT write Swift until the sysext
  load-path (survives full clone + loads) is confirmed on an interactive session.
- Not started (do not build ahead): Elastic offline emulation, mach_vm injection scanner,
  web UI, MCP, commercial EDR profiles.

## Next
1. **ESF→Wazuh wiring is DONE** (see session-5 section). Optional hardening if revisited:
   the custom rules can fire on system-noise events that slip past the boot-storm settle (e.g.
   `coreservicesd` `get_task`→100001); scoping the pushed capture to the sample's process subtree
   (pid/`responsible_pid` lineage) would forward only sample-caused behavior and remove those
   false positives. Not blocking — the E2E is deterministic on the sample's own adhoc exec (100020).
2. **Mythic real-agent test — DONE (session 5).** Updated the roshar Mythic teamserver
   (3.3.1-rc64 → v3.4.0.61) so current Poseidon can sync, built a real Poseidon macOS **arm64**
   payload (build param `architecture=ARM_x64`), and detonated it in the wazuh profile: custom
   rule **100020/T1553** fired on its adhoc exec (+ native netstat rule 533 from its beacon) →
   SUSPICIOUS 30. See the `mythic-real-agent-state` memory for the update procedure + scripting
   gotchas (rebuild `mythic-cli` via `make linux_docker` to bump the server image; `mythic==0.2.10`
   lib is schema-incompatible → submit build with `return_on_complete=False` + poll Postgres).
   Follow-on (optional): to trip persistence/injection rules (100001/100004/100010) rather than
   just adhoc-exec, task a live Poseidon callback — needs the http listener reachable from the
   guest and a longer window than a 12 s detonation.
3. Task 2 (custom ESF sysext) on a GUI session: verify sysext-survives-full-clone + load, THEN
   write Swift. Still blocked on the `systemextensionsctl developer on` GUI-click wall.

## Infra notes (session 4)
- **Mythic (roshar) is NOT usable right now.** The `mythic` MCP points at `http://10.0.0.11:7443`;
  `c2_payload_list` failed — `/auth` returned HTML, not JSON, so the teamserver isn't properly up.
  No payload types are installed either (Blake). When it's back: `c2_payload_build target_os=macos`
  builds a Poseidon macOS payload — a real agent detonation would be a strong wazuh-tier test, but
  ONLY after the ESF→Wazuh log source is wired in the golden (else our custom rules can't see it).
- **A malicious detonation was deliberately NOT run this session.** Rationale: our custom MITRE
  rules can't fire until the ESF custom log source is in the golden (GUI-gated), so a malicious
  sample would only trip Wazuh's native macOS checks — no new signal. Do it after step 1 of Next.

## Next-session kickoff prompt (paste to start session 9)
> ScratchingPost — session 9. Read HANDOFF.md (end of 2026-07-02 session 8) — esp. the
> session-8 section above — the docs/ROADMAP.md "Where it actually stands, and what's shaky"
> section, docs/ARCHITECTURE.md §6/§7/§9, samples/behavior/README.md, profiles/wazuh/README.md
> (unique_enrollment section), and the project-status + wazuh-dispatch-reliability +
> build-working-app-not-tests + mythic-real-agent-state memories. Docs are authoritative.
> Tests: /opt/homebrew/anaconda3/bin/python3 -m pytest -q — 113 passed + 6 skipped (offline; the
> 3 live E2E among the skips pass when the manager is clean, env below).
>
> Behavior detection is PROVEN for BOTH persistence and injection, live end to end via the wired +
> subtree-scoped + clock-synced path (shared-identity, the DEFAULT): persist_launchagent → 100010
> (T1543.001); inject_taskport → 100001 (T1055); adhoc → 100020 (T1553). E2Es in
> tests/test_wazuh_e2e.py; env: SCRATCHINGPOST_WAZUH_E2E=1, WAZUH_INDEXER_URL=https://
> wazuh.indexer:9200, WAZUH_INDEXER_CA=~/tools/wazuh-docker/single-node/config/
> wazuh_indexer_ssl_certs/root-ca.pem, WAZUH_INDEXER_RESOLVE=wazuh.indexer=127.0.0.1,
> WAZUH_E2E_AGENT=scratchingpost-wazuh.shared. Detection/scoping are solid; the flaky part is
> only the enroll→forward channel (see below). IMPORTANT (Blake): build a WORKING APP, verify
> against real detonations, not just green tests.
>
> RELIABILITY GOTCHA (still the operational rule for the DEFAULT shared path): a stale remoted
> connection for shared agent id 001 zeroes the dispatch tier. If a live E2E returns 0 dispatch
> indicators, restart the manager daemons FIRST (`docker exec single-node-wazuh.manager-1
> /var/ossec/bin/wazuh-control restart`), then re-run; diagnose detection separately via
> wazuh-logtest on the retained scoped capture ($TMPDIR/scratchingpost-runs/<run_id>/
> events.scoped.jsonl).
>
> Session 8 built per-clone UNIQUE agent enrollment (candidate step 1) but it is OFF by default
> (`LocalAppliance.unique_enrollment=False`) — blocked by a NAT-single-IP remoted race (~1 run in
> 3 the enrolled agent "Never connected"; all clones NAT to the Dockerized manager through
> 192.168.65.1). The durable fix is per-clone routable identity (bridged networking / non-Dockerized
> manager), i.e. INFRA, not more guest code. See the wazuh-dispatch-reliability memory. Do NOT
> re-attempt guest-side enrollment retry — it won't fix the shared-IP root cause.
>
> Candidate next steps (pick one, don't build ahead):
>   1. [needs infra — enables the unique-enrollment win already built] Give each clone a routable
>      identity to the manager: bridged per-clone networking, or run the Wazuh manager natively
>      (not Docker) so guests reach remoted as themselves. Then flip unique_enrollment=True and the
>      shared-id collision is gone for good. Infra/networking work, not app code.
>   2. [needs infra] Live-callback / interactive detonation mode: task a Poseidon beacon to inject /
>      persist on command. Needs the Mythic http listener (roshar) reachable from the guest LAN +
>      a window longer than 12 s. Deferred since session 6 for lack of a reachable listener.
>   3. Custom ESF sysext (durable fix for boot-storm event drops) — still GUI-blocked
>      (systemextensionsctl developer on); needs an interactive guest session.
> Do NOT start Elastic emulation, mach_vm scanner, web UI, MCP, or commercial EDR profiles. Keep
> external deps behind injected boundaries, tests alongside code, leave the lab clean (goldens
> stopped, no run clones; leave the Wazuh Docker stack running).
>
> --- (previous session-6 kickoff, for reference) ---
> ScratchingPost — session 6. Read HANDOFF.md (end of 2026-07-02 session 5), the
> docs/ROADMAP.md "Where it actually stands, and what's shaky" section (the honest limitations),
> docs/ARCHITECTURE.md §6/§7/§9, profiles/wazuh/README.md + ossec.conf.snippet + local_rules.xml,
> and the project-status + architecture-footprint + mythic-real-agent-state memories. Docs are
> authoritative.
> Tests: /opt/homebrew/anaconda3/bin/python3 -m pytest -q (anaconda 3.12) — 103 passed + 4 skipped.
>
> Context: the ESF→Wazuh custom log source is WIRED END-TO-END. A real detonation's eslogger
> capture is converted host-side to the uniform schema and pushed into the running clone at the
> agent's <localfile> (/var/log/scratchingpost/events.jsonl); the real in-guest agent forwards it
> and our custom MITRE rules fire on the manager, attributed to scratchingpost-wazuh.shared. The
> live E2E (tests/test_wazuh_e2e.py) PASSES with a tightened assertion requiring a custom rule
> (id 100000+): an adhoc Mach-O detonation trips 100020 (T1553) → indexer → backend → module →
> conductor → score. Capture recipe (in the wazuh env): detonate_settle≈20s (skip boot storm),
> eslogger_start_delay≈3s (ES client subscribe), reduced eslogger_events (no write/mmap/mprotect/
> signal firehose). Run the E2E with SCRATCHINGPOST_WAZUH_E2E=1 WAZUH_INDEXER_URL=https://
> wazuh.indexer:9200 WAZUH_INDEXER_CA=~/tools/wazuh-docker/single-node/config/
> wazuh_indexer_ssl_certs/root-ca.pem WAZUH_INDEXER_RESOLVE=wazuh.indexer=127.0.0.1
> WAZUH_E2E_AGENT=scratchingpost-wazuh.shared.
>
> Real-agent Mythic/Poseidon test is DONE (session 5): Poseidon macOS arm64 detonation tripped
> custom rule 100020 through the wired path (roshar teamserver updated to v3.4.0.61; see the
> mythic-real-agent-state memory).
>
> The honest state: the pipeline works end to end but detection is SHALLOW and NOISY. The only
> rule that fires on a real sample is "unsigned/adhoc ran" (100020) — weak signal. The eslogger
> capture drops events under the boot-storm firehose (worked around, not solid), and system noise
> trips rules (false positives). The single most valuable next step is proving we catch malicious
> BEHAVIOR, not just execution. Candidate steps (pick one, don't build ahead):
>   1. **[most valuable] Prove behavior detection.** Make persistence/injection/LaunchAgent rules
>      (100001/100004/100010) actually fire on a live sample — either an interactive/live-callback
>      detonation mode (task a Poseidon beacon; needs the http listener reachable from the guest +
>      a longer-than-12s window) or malicious samples that self-act on launch.
>   2. Scope the pushed capture to the sample's process subtree (pid/responsible_pid lineage) to
>      kill system-noise false positives (e.g. coreservicesd get_task→100001).
>   3. Custom ESF sysext (durable fix for event drops) — still blocked on the
>      systemextensionsctl developer-on GUI wall; needs an interactive guest session.
> Do NOT start Elastic emulation, mach_vm scanner, web UI, MCP, or commercial EDR profiles. Keep
> external deps behind injected boundaries, tests alongside code, leave the lab clean (goldens
> stopped, no run clones; leave the Wazuh Docker stack running).

## Load-bearing facts (unchanged)
- Golden is a **50 GB `.macvm`**; **full clones only** (linked clones break the Parallels Tools
  handshake); **golden stopped before cloning**; `prlctl exec` joins trailing args under
  `bash -c` (pass a pipeline as one argv); fresh clone rejects `exec` (rc=255) ~5–60 s
  (`_wait_guest_ready` polls `whoami`); `script -q /dev/null` prepends `^D\x08\x08` to line 1
  (`parse_line` anchors on `{`); eslogger ptrace event is spelled **`trace`**; Parallels shared
  folders do NOT mount in a macOS guest (transfer is base64-over-exec). Alerts come from the
  **indexer** (`wazuh-alerts-4.x-*`, `POST :9200/…/_search`), NOT the server API on :55000.
  A full clone copies `client.keys`, so the clone reports as the **same agent identity** — fine
  for serial detonation (correlate by time window + agent name), which is what `alerts_since` does.
