# ScratchingPost — Development Plan

Strategy: **vertical slice first, then widen.** Get one payload type running end to end
through the full pipeline before broadening, so you have something real fast and you de-risk
the two hardest seams early: the **ESF recorder** and the **orchestrator ↔ detonation API**.

The MVP scope is deliberately large (all four tiers, all payload types, plus standalone
tools). The phasing below is how you reach that without building a wide, half-working thing.

---

## Where it actually stands, and what's shaky (2026-07-02)

The spine works end to end: clone a VM, detonate a Mach-O, capture ESF telemetry, check
Apple's XProtect/Gatekeeper, score it, report — and feed the behavior into a **live Wazuh
agent** whose custom MITRE rules pass judgment too (proven with a real Poseidon C2 implant,
which our rules caught on execution). That's a real, working slice. But several hard problems
are only partly solved, and they — not the remaining feature breadth — are what gate whether
this becomes genuinely useful. Be honest about these when planning:

1. **The ESF capture is brittle.** A booting macOS guest emits ~15k events/sec; stock
   `eslogger` buries the sample and *drops events under load* (a sample's own exec was dropped
   in testing). Current mitigation — wait out the boot storm (~20 s), delay the sample until
   eslogger subscribes (~3 s), capture only a narrow rule-relevant event set — is tuning, not
   robustness. A sample that acts the instant it launches can still fall in the gap. The proper
   fix is the **custom ESF system extension** (bounded queues, path muting, AUTH events) — which
   is itself blocked (item 6). Until then, treat behavioral coverage as best-effort, not complete.

2. **Detection depth — persistence AND injection behavior now proven.** For a long time the only
   rule that fired on a real detonation was "an unsigned/adhoc binary executed" (100020) — weak
   signal alone. As of session 7 this is **closed for self-acting behavior**: two self-acting
   samples each trip their behavioral rule through the wired + subtree-scoped + clock-synced path,
   live-proven end to end (agent → manager → indexer → dispatch → score):
   - `samples/behavior/persist_launchagent` drops a LaunchAgent plist → rule **100010** (LaunchAgents
     persistence, T1543.001, level 12) — session 6,
     `tests/test_wazuh_e2e.py::test_wazuh_convicts_persistence_behavior`.
   - `samples/behavior/inject_taskport` acquires another process's Mach task port with
     `task_for_pid` (the surviving macOS injection primitive) → rule **100001** (task-port
     acquisition, T1055, level 12) — session 7,
     `tests/test_wazuh_e2e.py::test_wazuh_convicts_injection_behavior`. The get_task event's acting
     process is the sample itself, so subtree scoping keeps it while system-service get_task noise
     (coreservicesd) is dropped.

   So the sandbox convicts real malicious *behavior* — both persistence and injection — not just an
   unsigned exec. **Still open:** rules that need a real implant to *act* over a live channel (task
   a Poseidon beacon to inject/persist on command) — those want a live-callback / interactive
   detonation mode (needs the http listener reachable from the guest + a window longer than 12 s).
   The fire-and-forget ~12 s window suffices for self-acting samples but not for tasked implants.

3. **[DONE] False positives from system noise.** The capture is system-wide, so macOS's own
   services tripped our rules (e.g. `coreservicesd` doing legitimate `task_for_pid` → injection
   rule 100001). Fixed in session 6: `scope_events_to_subtree` (`orchestrator/detonation/api.py`)
   filters the forwarded capture to the sample's own process subtree (pid / ppid / `responsible_pid`
   lineage, seeded on the sample's own exec, `/private/tmp` symlink normalized) before it reaches
   the agent. Live-verified: a run's two `coreservicesd` `get_task` events were dropped (no 100001)
   while the sample's own exec/behavior was kept. Falls back to the full capture if the sample's
   exec was dropped from the capture, rather than forwarding nothing.

   **Two live-only reliability bugs also fixed in session 6** (both silently zeroed the dispatch
   tier even though the rules fired): (a) a fresh clone boots ~tens of minutes behind real time, so
   agent-forwarded alert timestamps fell outside the module's real-clock query window — fixed by
   setting the guest clock to host UTC after boot (`_sync_guest_clock`); (b) all clones share the
   golden's agent identity (id 001), so an abrupt clone delete left the manager holding a stale
   connection and back-to-back runs forwarded nothing — fixed by gracefully stopping the in-guest
   agent before deleting the clone (`_revert_live`). See the `wazuh-dispatch-reliability` memory.

   **The residual shared-id-001 gotcha** (a stale connection inherited at session start) still needs
   a one-time manager-daemon restart before the first live run, and that is the current operational
   rule. **Session 8 built per-clone unique agent enrollment** (`LocalAppliance.unique_enrollment`,
   `agent-auth -A scratchingpost-<clone-uuid>`, correlate by `agent_name_for`) to remove that gotcha
   at the root, but it is **OFF by default and not yet reliable**: all Parallels clones NAT to the
   Dockerized manager through one source IP, and remoted intermittently (~1 run in 3) rejects a
   freshly-enrolled agent from that shared IP so it never connects. The durable fix is per-clone
   routable identity (bridged networking / non-Dockerized manager) — infra, not app code. Until then
   the shared identity + graceful-stop + session-start restart is the reliable path.

4. **Not portable.** Despite the hypervisor-agnostic design, it's welded to one specific Mac +
   Parallels + a hand-built golden image. The golden build and guest provisioning are manual;
   "download and run" is far off.

5. **Barely tested against real malware.** The pipeline has mostly run benign samples plus one
   real C2 implant. Behavior against evasive/anti-analysis samples (VM detection, long sleeps,
   environment checks) is unknown.

6. **Blocked: the custom ESF sysext.** Loading a system extension needs `systemextensionsctl
   developer on`, which is a GUI auth click `prlctl exec` can't drive. This blocks both the
   deeper-telemetry sensor (the fix for item 1) and knowing whether a sysext survives a full
   clone. Needs an interactive guest session.

7. **Slow and serial.** One sample at a time, ~90 s each (clone/boot/settle/detonate/collect/
   revert). Fine for research, not for volume; real throughput needs the Phase 4 multi-host split.

---

## Phase 0 — Foundations

Lock the decisions and scaffold. No detection logic yet.

- **Name + license.** Name locked: **ScratchingPost**. Recommend **GPL-3.0** to match LitterBox (lets you borrow its scoring/report code cleanly),
  and it is compatible with pulling in Wazuh's GPLv2-licensed ideas and Elastic's open rules.
  If you would rather reimplement LitterBox's scoring from scratch, you keep license freedom;
  decide now.
- **Repo structure.** `/orchestrator` (Python), `/sensors` (Swift/Obj-C/C: recorder, sysext,
  injection scanner), `/modules` (detection modules), `/docs` (these three files), `/profiles`
  (tart image build scripts), `/web` (UI, later).
- **Contracts as code.** Implement `DetectionModule`, `ModuleCaps`, `Event`, `ProcessInfo`,
  `Indicator` from `MODULE_CONTRACT.md`. These are the spine everything hangs on.
- **Dev environment.** `tart` installed, `macos-tahoe-base` pulled, a scripted golden-image
  build that does SIP-off + system-extension developer mode + the entitlement provisioning
  (`ARCHITECTURE.md` §7). Smoke test: `eslogger` emitting JSON inside the guest.

**Exit criteria:** you can `tart clone` a provisioned guest, run eslogger, and get events into
the uniform schema on your host.

---

## Phase 1 — Vertical slice (one Mach-O executable, end to end)

One payload type (a single Mach-O executable), through every stage, thin but complete.

- **Static tier.** Mach-O parser (load commands, `LC_LOAD_DYLIB` imports, symbols, fat slices)
  plus the code-identity assessor: `codesign`/`spctl`/notarization/entitlements/quarantine
  collapsed into a verdict. **Reuse Callandor** for the dylib-hijack surface. This tier alone
  is a useful tool (see Standalone Tools).
- **Behavioral tier v0.** The **eslogger-based recorder** → uniform event schema →
  capture-to-JSONL + **replay**. Build replay early; it is what makes every later module cheap
  to develop.
- **One detection tier.** Start with **Apple built-in offline emulation** (`spctl` verdict +
  bisect against XProtect's on-disk YARA to find triggering bytes). It needs zero extra infra
  and proves the module contract. Do **Wazuh dispatch second** as the first real-agent proof.
- **Detection Score v0 + minimal report.** Aggregate indicators across the tiers you have.
- **Orchestrator ↔ detonation API as a localhost seam.** Implement the four calls
  (`detonate`/`stream_telemetry`/`collect`/`revert`) even though both sides are the same
  appliance. This is the seam you refuse to skip.

**Exit criteria:** upload a Mach-O, get static findings + ESF telemetry + an Apple-built-in
verdict + a Detection Score + a report, with the detonation env reverting between runs.

---

## Phase 2 — Behavioral depth + real agents

- **[DONE] Wazuh integration proper.** Persistent manager/indexer/dashboard (wazuh-docker
  4.14.6) on the durable side; ESF telemetry piped into the in-guest agent as a custom
  `<localfile>` JSON log source with MITRE-tagged rules; Wazuh dispatch module returns its
  alerts as indicators into the score. Live-proven end to end incl. a real Poseidon macOS
  detonation. **Note the schema reality that bit us:** stock eslogger emits raw ES (numeric
  `event_type`, `process.executable.path`), which matches *none* of the rules — the uniform
  conversion happens host-side and the result is pushed into the guest for the agent to forward.
- **[BLOCKED — GUI] Custom ESF system extension.** Replace eslogger where it falls short: AUTH
  events, path muting/inversion, richer enrichment, and — critically — **bounded queues so the
  boot-storm firehose stops dropping the sample's events** (limitation 1). Blocked on the
  `systemextensionsctl developer on` GUI wall (limitation 6). Reference: Mac Monitor, AtomicESClient.
- **[DONE for self-acting behavior — the real depth] Prove detection of malicious *behavior*, not
  just execution.** Subtree scoping (limitation 3) is done, and self-acting samples now trip both
  the **persistence** rule 100010 (T1543.001, session 6) and the **injection** rule 100001 (T1055,
  `task_for_pid`, session 7) end to end — the sandbox convicts real behavior, not just an unsigned
  exec. Two live-only reliability bugs that were zeroing the dispatch tier (guest clock skew,
  shared-agent-identity collision) are also fixed; per-clone unique agent enrollment (session 8)
  would close the residual shared-id-001 gotcha but is off by default, blocked by a NAT-single-IP
  remoted race (see the "Where it stands" reliability note). **Remaining:** rules that need a real
  implant to *act* over a live channel — build the interactive/live-callback detonation mode (task a
  Poseidon beacon; needs the http listener reachable from the guest + a window longer than 12 s).
- **[NOT STARTED] Elastic offline emulation module.** Run Elastic's protections-artifacts YARA +
  behavioral rules against your telemetry, offline, no VM. (Verify current repo layout at build.)
- **[NOT STARTED] Memory / injection scanner (standalone + module).** Walk a live process's VM
  regions via `mach_vm_region_recurse`; flag unbacked executable memory; diff loaded dylibs
  against the on-disk Mach-O's load commands; check per-region `csflags`. **This is the
  research-frontier piece** — no polished Moneta/PE-Sieve equivalent exists for macOS. Most
  citable output of the project.

**Exit criteria:** three real detection tiers (Apple built-in, Elastic offline, Wazuh live)
plus first-party behavioral heuristics, all feeding one score — and at least one of them shown
convicting real malicious *behavior* (persistence/injection), not just an unsigned exec.

---

## Phase 3 — Widen payload types + product polish

- **All payload types.** App bundles, `pkg`, `dmg`, `mobileconfig`, LaunchAgents/Daemons, and
  the **`osascript`/JXA script-content module** (the AMSI-gap fill: capture interpreter exec +
  args, pull the body, YARA it). This drives the static parser's breadth more than anything.
- **Web UI + console.** Borrow heavener's console stack (ClickHouse / Postgres / Redis / Go
  API / React), adapted. Live alerts via SSE, an investigation view (process tree, enrichment,
  telemetry window, which indicator fired and why), and a Rule/Coverage Atlas.
- **MCP + CLI.** The GrumpyCats equivalent: CLI, Python library, and an MCP server so an LLM
  agent can drive analysis end to end. This layer is OS-agnostic and ports almost directly.
- **Scoring/report tuning + baseline-diffing.** Tune per-tier weights; HTML/JSON reporting
  (borrow LitterBox); BashBelt-style baseline-diffing so you can compare a payload against a
  known-clean baseline.

**Exit criteria:** the full LitterBox feature surface, macOS-native, driveable by CLI/MCP/UI.

---

## Phase 4 — Commercial dispatch + scale

- **Commercial EDR profiles.** One tart image per vendor (CrowdStrike, SentinelOne, Sophos,
  Jamf Protect). Real-agent dispatch, accept the burn. Never artifact extraction
  (`ARCHITECTURE.md` §12).
- **Split the seam across hosts.** Move detonation onto separate Apple Silicon host(s). Because
  Apple caps you at **2 concurrent macOS VMs per host**, real parallelism needs multiple hosts;
  use **Orchard** to orchestrate the fleet.

---

## Standalone tools that fall out of this

Each is independently useful and worth shipping/publishing on its own timeline:

- **ESF telemetry recorder** with a clean, replayable JSON schema (Phase 1 wrapper → Phase 2
  system extension). A scriptable, capture-to-replay ESF recorder built for automation is a
  real gap; Mac Monitor is interactive, not automation-first.
- **macOS process memory / injection scanner** (Phase 2). The Moneta-for-macOS that does not
  exist. Highest research value.
- **One-shot static assessor** (Phase 1). `codesign` + `spctl` + notarization + entitlements +
  quarantine + extracted-XProtect-YARA collapsed into a single "would a stock Mac run this, and
  would it flag it" verdict.

---

## Verify at build (do not trust from memory)

These are load-bearing and version-sensitive. Confirm each when you reach it. Status
tags reflect what was verified on the reference guest (macOS 26.5.2 / Tahoe, build
25F84, Parallels 26.4) during Phase 1:

- **[RESOLVED — 26.5.2]** **Exact XProtect paths and rule format.** Current path is
  `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara`
  (the legacy `/System/Library/CoreServices` path is gone); 443 rules, world-readable,
  `imports "hash"`. Encoded in `modules/emulation/apple_builtin.py:XPROTECT_YARA`. XProtect
  Remediator family-scanner enumeration still unexamined (not needed for the YARA tier).
- **[PARTIAL — 26.5.2]** **ES event availability.** The Phase 1 core set (exec/fork/exit/
  create/write/rename/unlink/mmap/mprotect/signal/trace/get_task/cs_invalidated/
  btm_launch_item_add) is confirmed accepted by `eslogger --list-events`; note the ptrace
  event is spelled **`trace`**. AUTH events and BTM specifics beyond the launch-item add
  still need the custom sysext (Phase 2) — eslogger does not surface them.
- **[OPEN]** **Whether an installed ESF system extension survives a clone.** Untested. Note
  linked clones are already ruled out for this guest (they regenerate the `.macvm` machine
  identity and break the Parallels Tools handshake — full clones only). Whether a sysext
  survives a *full* clone is the open question; if not, move agent install to a first-boot
  script. The revert-per-run story for the Wazuh/commercial profiles depends on this.
- **[OPEN — Phase 2]** **Elastic protections-artifacts current layout** (YARA + behavioral
  rule locations, license terms for redistribution vs. runtime use).
- **[PINNED — 4.14.x]** **Wazuh version + alert-query API.** Pinned to **4.14.x**
  (v4.14.6 latest patch, checked 2026-07); 5.0 is still beta and its indexer upgrade is
  one-way, so production stays on 4.14 until GA. Key correction: alerts are documents in
  the **indexer** (`wazuh-alerts-4.x-*`, `POST :9200/wazuh-alerts*/_search`, `@timestamp`
  range query, basic auth over self-signed TLS) — the server API on :55000 manages
  agents/rules/config and does **not** serve alerts. Encoded in
  `modules/dispatch/wazuh.py:LiveWazuhBackend`; custom log source + MITRE rules in
  `profiles/wazuh/`. Watch the 5.0 native indexer connector for `wazuh-alerts-*` shape changes.
  **Live-verified** against a real wazuh-docker **4.14.6** single-node stack: `LiveWazuhBackend`
  round-trips `_search` over CA-verified TLS and parses real hits + MITRE tags into indicators
  (`tests/test_wazuh_live.py`, live-gated); `local_rules.xml` loads in the manager and rules
  fire with correct JSON decoding + MITRE enrichment (`wazuh-logtest`: 100001→T1055,
  100010→T1543.001, 100020→T1553, …).
- **[RESOLVED — Phase 2]** **`wazuh` golden image + live agent-checkin + ESF log source.** The
  `ScratchingPost-wazuh` golden has the 4.14.6 agent baked in; it survives a **full** clone and
  checks in as `scratchingpost-wazuh.shared` (verified by the passing live E2E, which clones the
  golden per run). The ESF→Wazuh custom log source is wired: the host-converted uniform capture
  is pushed into the clone at `/var/log/scratchingpost/events.jsonl`, which the agent's
  `<localfile>` tails and forwards, and custom rules fire attributed to the real agent
  (`tests/test_wazuh_e2e.py`, `profiles/wazuh/README.md`). A real Poseidon macOS payload was
  convicted this way (rule 100020).
- **[VERIFIED — capture drops]** **Stock eslogger drops events under load.** A booting guest
  emits ~15k events/s; the sample's own exec was *lost* in a raw firehose capture (~300 MB/12 s),
  and system noise (`coreservicesd get_task`) tripped rules. Mitigated in the wazuh live env with
  a boot-storm settle, an eslogger-subscribe delay, and a reduced event set (no
  write/mmap/mprotect/signal). This is a workaround; the durable fix is the custom sysext with
  bounded queues (see limitations 1 + 6).
- **[N/A]** **Nested virt** behavior on the M5 — the sibling-detonation model was chosen, so
  nested-virt state is a non-issue unless that decision is revisited.

---

## The two things Claude Code cannot design for you (already done, in `/docs`)

1. The **module contract + event schema** (`MODULE_CONTRACT.md`) — so in-process modules and
   dispatch modules both report into one score.
2. The **VM/agent topology + provisioning** (`ARCHITECTURE.md`) — the appliance model, tart
   image build with the SIP/entitlement steps, the snapshot-revert flow, the seam.

With those locked, the first Claude Code task is Phase 0 + the Phase 1 static tier and ESF
recorder as the first vertical slice.
