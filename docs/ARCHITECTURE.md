# ScratchingPost — Architecture & Topology

> **Name:** ScratchingPost. Stays in LitterBox's feline-furniture lineage (Whiskers,
> GrumpyCats): a scratching post is where a cat tears things up, and this is where you tear
> payloads apart before they go live. Repo directory is lowercase `scratchingpost` (matching
> the `litterbox` convention); prose uses ScratchingPost.

## 1. What this is

ScratchingPost is the macOS counterpart to [LitterBox](https://github.com/BlackSnufkin/LitterBox).
A self-hosted payload-analysis sandbox: you upload a sample, ScratchingPost runs it through
static, behavioral, and detection tiers inside a contained macOS environment, produces a
**Detection Score** with a triggering-indicators breakdown, and tells you whether the
payload is field-ready before it leaves the lab. Same job as LitterBox, different OS, and
therefore a substantially different threat model and detection surface.

The scoring and reporting model is borrowed and adapted from LitterBox, with credit.
Nothing about a commercial vendor's proprietary artifacts is extracted or redistributed
(see §12).

## 2. Why this is a re-architecture, not a port

The most sophisticated code in both LitterBox's scanners and in prior-art EDR-emulation
work (heavener) exists because of Windows-specific facts that do not hold on macOS:

- **No userland inline-hooking arms race.** Windows EDRs patch `ntdll` inline, so attackers
  unhook, use direct/indirect syscalls, and spoof call stacks, and the EDR tries to detect
  that evasion. macOS EDRs consume the kernel-mediated Endpoint Security Framework (ESF).
  There is no `ntdll` equivalent getting patched, so there is nothing to unhook, no
  syscall-provenance subgame, no stack-spoof detection. That entire branch has no macOS
  counterpart.
- **Injection primitives are mostly dead.** PE-Sieve / Moneta / Hollows-Hunter detect PE
  injection and hollowing. The classic macOS analog (`task_for_pid` + `mach_vm_write` +
  remote thread) is largely blocked against hardened or platform binaries on modern macOS.
- **The detection surface is code-identity and policy, not memory tricks.** Signing,
  notarization, quarantine (`com.apple.quarantine`), entitlements, hardened runtime,
  Gatekeeper/`spctl` verdicts, TCC posture, and launch persistence are the signals that
  drive a verdict. Several have no Windows equivalent.
- **The AMSI gap.** macOS has no system-provided script-content-scanning hook. `osascript`/JXA
  and interpreter abuse are invisible to content inspection unless we build it. ScratchingPost fills
  this by capturing interpreter `exec` + args via ESF, pulling the script body, and
  YARA-scanning it ourselves.

## 3. Deployment model: control plane on the host, one disposable detonation VM

**Decision (Light footprint — supersedes an earlier "everything in one macOS appliance VM"
draft).** The control plane runs on the **host**: the orchestrator, web UI, static analysis,
ESF-capture conversion, scoring, and reporting are a plain Python app (later a thin container),
not a macOS VM. The only macOS VM is the **detonation guest** — one disposable clone, spun per
run from a profile golden and reverted after. This is LitterBox-parity (LitterBox is one
isolated VM) without forcing the control plane into a VM it does not need.

Footprint at rest is **zero** detonation VMs; during a run, **one**. Profiles (`apple`,
`wazuh`, `vendor-*`) are golden **images**, not running machines — you clone whichever the run
needs, one at a time. See §4 for how this stays inside Apple's 2-macOS-VM cap.

Rationale:
- **Light for operators.** Baseline is one macOS VM + a Python app. The static/Apple/Elastic
  tiers need no Docker at all; the durable services (§9) are opt-in and Linux/Docker, so they
  do not consume a macOS-VM slot.
- **Native where it must be.** Everything that has to run native on macOS (ESF, executing
  Mach-O, live Gatekeeper/XProtect verdicts) is in the detonation guest; everything else does
  not need to be.

### The orchestrator / detonation seam

The control plane talks to the detonation guest through one narrow API (§8), so where
detonation runs is swappable without a rewrite. In the current implementation the control
plane clones/boots/exec's the guest through an injected `VmProvider` (§5) and pulls results
back out every run.

- **Baseline:** control plane on the host drives one disposable detonation VM. Clean clone →
  detonate → capture → **push results OUT to host-side storage** → revert to clean. Nothing you
  care about lives in the revertible image, so a bad run costs a revert and nothing else.
- **Isolation posture (optional).** Detonation of payloads **you wrote and trust** is the
  primary use. For genuinely hostile samples, wall the control plane off from detonation — run
  the control plane in its own macOS VM (a self-contained appliance) or on a separate box, with
  the detonation guest as a peer. That is a posture choice, not a requirement; we warn in the
  README (§13) and leave host/VM separation to the operator.
- **Scale-out:** the same seam drives detonation guests on other hosts for parallelism (§4, §11).

## 4. Host requirements & hard constraints

- **Apple Silicon required.** macOS guests only virtualize on Apple Silicon via
  Virtualization.framework. There is no Linux/Docker path for macOS guests.
- **Apple caps concurrent macOS VMs at 2 per host, at the kernel level.** With the Light model
  (§3) the baseline is **1 macOS VM** — the detonation guest — because the control plane runs on
  the host. The optional Docker durable services (§9) run in Docker's **Linux** VM, which does
  **not** count against the macOS cap. The cap only bites in two cases: the isolated posture
  (control-plane appliance VM + detonation guest = 2, the ceiling), and **parallel detonations**
  (each needs its own macOS guest). **No parallel detonations on a single host**; parallelism
  requires more hosts (see Orchard, §11).
- **Nested virtualization** works only on M3/M4/M5 with macOS 15+. Your M5 has it, so a
  single-host appliance-plus-nested-detonation setup is *possible*. Prefer sibling (peer)
  detonation guests anyway, so nested-virt state is a non-issue.
- **Dev vs lab hardware.** The M5 MacBook is fine for building the vertical slice and the
  first profiles. Running Docker's Linux VM *and* macOS guests simultaneously on a laptop is
  heavy; a real lab wants a Mac mini or Studio as the always-on host. Not a blocker now, but
  it is coming.

## 5. VM management: the hypervisor-agnostic provider abstraction

**Decision (supersedes an earlier tart-only draft):** the VM layer is
hypervisor-agnostic. For a shippable tool the answer is "any macOS VM hypervisor you want" —
users run tart, Parallels, UTM, or raw Virtualization.framework, and welding the orchestrator
to one narrows adoption. So the orchestrator never shells out to a hypervisor directly; it
drives a **`VmProvider`** (`orchestrator/detonation/vm.py`), and each hypervisor is one
implementation of that interface. Adding UTM later is a new provider, not a rewrite.

The provider surface (deliberately narrow, the primitives revert-per-run needs):

| Method | Meaning |
|---|---|
| `clone(base, target)` | snapshot-cheap copy of a golden image (the revert-per-run primitive) |
| `boot` / `suspend` | start a clone; warm-VM suspend/resume (macOS cold boot is ~20-40s) |
| `share_dir(vm, host_dir, name)` | share a host directory in, to push results OUT of the guest |
| `exec(vm, argv)` | run a command in the guest (needs a guest agent) |
| `ip(vm)` | the guest's IP |
| `revert(vm, base)` | restore a per-run VM to clean (uniform impl: delete + re-clone golden) |
| `delete(vm)` | destroy a per-run clone |

Every provider goes through an injected command runner, so command construction is
unit-tested with no hypervisor present and the live subprocess path is only touched for real
runs (same boundary as the code-identity assessor).

**Parallels first** (`ParallelsProvider`, `prlctl`) — the reference lab hypervisor:

```bash
prlctl clone scratchingpost-base --name scratchingpost-detonation-apple --linked  # instant, cheap
prlctl set  scratchingpost-detonation-apple --cpu 4 --memory 8192
prlctl set  <run-vm> --shf-host-add sppost --path /host/out --mode rw             # results share
prlctl exec <run-vm> -- /usr/bin/eslogger exec ...                                # guest exec (needs Parallels Tools)
```

- **Linked clone = snapshot.** `--linked` gives a near-instant, space-cheap copy; revert = delete + re-clone golden.
- **Guest exec/IP require Parallels Tools** installed in the guest. Without it `prlctl exec`
  fails; the provider surfaces that as a clear error rather than hanging.
- **Shared folder** is the results-out channel (mount point on the Tahoe guest is
  `TODO(verify-on-guest)`; the seam's guest-side capture path must match it).

**tart second** (`TartProvider`) — kept for the existing `profiles/*.sh` build path. tart's
model diverges in ways the abstraction has to absorb: `tart run` is a long-lived foreground
process (not a one-shot boot), tart has no guest-exec (you reach the guest over SSH), and
sharing is a `tart run --dir` flag rather than persistent VM state. Where those don't fit a
synchronous provider call, `TartProvider` raises with the reason instead of pretending. tart
mechanics that do map: `tart clone` (= snapshot), `suspend`/`resume`, `tart ip`, OCI
push/pull for versioned images (note: push does not carry the suspend snapshot).

> **Two-concurrent-macOS-VM cap** (§4) applies to every hypervisor — it is a Virtualization.framework
> kernel limit, not a tart or Parallels one. Provider choice does not change it.

> **Verify at build:** whether an installed ESF **system extension** survives a clone cleanly
> (both `tart clone` and a Parallels linked clone). The revert-per-run story for the
> Wazuh/commercial profiles depends on the agent surviving the clone. If it does not, bake
> agent install into a first-boot script instead of the golden image.

## 6. Detonation profiles

One golden image per detection profile, each built once with the ESF recorder installed and
the SIP-off / entitlement provisioning baked in (§7). This is LitterBox's "EDR profiles"
idea lifted to the VM-image level; provider clones (§5) make it cheap. **Profiles are images,
not running machines:** one is cloned per run and reverted after, so only a single detonation
VM ever runs at a time (§3, §4) — you do not stand up a machine per profile.

- **`apple`** — clean image, Apple built-in stack only (XProtect, Gatekeeper, TCC). Scores
  "what a stock Mac would do." No third-party agent (kept clean so the stock-Mac baseline is
  honest).
- **`wazuh`** — the base detonation image **+ a Wazuh agent baked in**, enrolled to the durable
  Wazuh manager (Docker, §9). Same single detonation VM slot, different image.
- **`vendor-*`** — one image per commercial EDR (CrowdStrike, SentinelOne, Sophos, Jamf
  Protect). Real-agent dispatch, accept the burn. Added in a later phase.

## 7. ESF telemetry provisioning (the load-bearing setup)

This is the gnarliest part of standing up a profile. The clean behavioral telemetry on modern
macOS comes through ESF, which requires the `com.apple.developer.endpoint-security.client`
entitlement. Apple only whitelists that entitlement for notarized distribution. For a lab you
sidestep it.

**Two-stage recorder strategy (this changes the build order in your favor):**

1. **eslogger first.** Apple ships `/usr/bin/eslogger`, a stock utility that emits ES events
   as JSON. On a SIP-disabled VM you get telemetry flowing on day one without writing a
   system extension. Wrap and parse its output into the uniform event schema.
   ```bash
   # inside the guest, as root
   eslogger exec fork exit create rename unlink mmap mprotect signal \
     btm_launch_item_add > /Volumes/My\ Shared\ Files/events.jsonl
   ```
2. **Custom system extension later.** Build the real ESF client for what eslogger does not
   give you: AUTH events (allow/deny), path muting/inversion, and richer enrichment. Reference
   implementations: Red Canary's Mac Monitor, the AtomicESClient example, Apple's
   NullEndpointSecurity sample.

**Provisioning the guest for a self-signed ESF client (test/lab only):**

- **Disable SIP** in the guest (`csrutil disable` from recovery). Apple DTS confirms SIP-off
  is sufficient for ESF testing; notarization is what lifts the SIP requirement for real
  deployment, which we are not doing. Do this **only in the disposable VM**, never on a host
  you care about.
- **Run as root.** ES clients must be privileged (`ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`
  otherwise). A Launch Agent cannot connect; use a **system extension** (gets SIP tamper
  protection) or a **Launch Daemon** wrapped in a bundle so it can carry a provisioning
  profile. For research either works; the system extension is the cleaner long-term target.
- **Sign with the entitlement.** Self-signed cert carrying:
  ```xml
  <key>com.apple.developer.endpoint-security.client</key><true/>
  <key>com.apple.developer.team-identifier</key><string>YOURTEAMID</string>
  <key>com.apple.security.get-task-allow</key><true/>
  ```
  The container app additionally needs
  `com.apple.developer.system-extension.install`.
- **Enable system-extension developer mode** in the guest so unnotarized extensions load:
  `systemextensionsctl developer on`.

Bake all of the above into the golden image so every clone comes up ready. Script it; do not
click through it per profile.

> The SIP-off "contaminates the endpoint" caveat that matters for live IR does **not** apply
> to us. We detonate in a disposable VM that gets reverted, not on a victim host under
> investigation.

## 8. The orchestrator ↔ detonation API contract

Even in the MVP where both sides are localhost in one appliance, the orchestrator talks to
the detonation environment through one narrow API. This is what lets you split them later
without a rewrite.

Conceptual surface (see `MODULE_CONTRACT.md` for how modules plug into this):

- `detonate(sample, profile, timeout)` → run the sample in the profile's environment.
- `stream_telemetry()` → the uniform ESF-derived event stream, live or captured.
- `collect(run_id)` → pull telemetry + any agent/EDR alerts for the run.
- `revert(profile)` → restore the detonation environment to clean.

In MVP, the implementation behind this API is "run locally, tail eslogger, read results from
the shared dir, `tart clone` back to clean." Later, the same API drives sibling guests over
the network.

## 9. Persistent services (the durable side)

Some state must survive a revert. It lives on the durable side of the seam and is **not** part
of any revertible detonation image.

- **Wazuh manager + indexer + dashboard (opt-in).** Holds rules, alert history, fleet
  inventory. You do not want to rebuild that every revert. Runs as a persistent service the
  control plane talks to, in **Docker (Linux)** — the standard Wazuh deployment, and Linux
  containers so it does not consume a macOS-VM slot (§4). The Wazuh **agent** goes in the
  disposable detonation golden, not the manager. Every real-agent tier has this shape:
  persistent brain on the durable side, agent baked into the detonation image. **Only needed
  for the Wazuh dispatch tier** — the static/Apple/Elastic tiers need no manager and no Docker.
- **Datastores** (carried over from heavener's console stack, all ship clean arm64/macOS
  builds): ClickHouse (append-only alert/event storage + materialized views for histograms),
  Postgres (mutable app state: run inventory, triage, saved views, rule atlas), Redis
  (idempotency + SSE pub/sub for the live UI). Also opt-in; the MVP can persist results to
  flat files until the console lands.
- **Results storage.** Every run's static findings, telemetry capture, indicators, and
  Detection Score, written durably (host-side) before the detonation env is reverted.

These run **host-side** — the control plane's own process/files, plus Docker for the Wazuh
manager and any datastores. Nothing durable lives in the revertible detonation image. Keeping
the durable services in Docker (Linux) is what lets a multi-user deployment later move them to a
dedicated Linux box without a rewrite. **Docker here is the manager/console backend, not a
requirement for core analysis.**

## 10. Run lifecycle

```
1. Upload sample to the appliance UI/API.
2. Static tier runs in-process (no detonation needed): Mach-O parse, signing/notarization/
   entitlements/quarantine assessment, YARA, XProtect-YARA bisect.
3. Orchestrator selects profile(s), calls detonate() through the seam.
4. Detonation env: clean clone is up, ESF recorder running. Sample executes under timeout.
5. Telemetry streams to the uniform schema; agent/EDR alerts (if any profile) are collected.
6. Behavioral + emulation modules consume the telemetry and emit indicators.
7. All results pushed OUT to durable storage.
8. Detonation env reverted (tart clone back to golden).
9. Detection Score aggregated across tiers; report rendered.
```

## 11. Constraints & honest caveats

- **The 2-VM cap kills single-host parallelism.** Baseline is one detonation guest (control
  plane on the host, §3); even at the isolated posture the ceiling is two macOS VMs. Either way
  you detonate serially. For concurrent detonations you need more Apple Silicon hosts; tart's
  companion **Orchard** orchestrates VMs across a cluster of hosts when you get there.
- **Wazuh is not a macOS behavioral sensor.** Its real-time FIM is Windows/Linux only; on
  macOS it does scheduled FIM + YARA-on-change + SCA + rootcheck + log analysis. It is a
  readable ruleset, a zero-burn self-hosted detection backend, and a correlation/console
  layer. The behavioral telemetry comes from **your** ESF recorder, piped into Wazuh as a
  custom log source. Do not expect ESF-grade process telemetry from Wazuh natively.
- **VM weight.** Appliance + detonation + datastores on a laptop is heavy. Fine for dev, plan
  for a Mac mini/Studio lab host.

## 12. What we deliberately do not do

Prior-art EDR emulation (heavener) extracts and runs commercial vendors' proprietary ML models
and behavioral rule corpora. That is legally loaded (EULA anti-reversing, DMCA, trade secret),
and **redistributing vendor artifacts in a public repo is worse than running them privately.**

ScratchingPost's emulation tier leans only on:
- **Apple's built-in stack** (XProtect YARA rules are on-disk and readable; Gatekeeper/`spctl`
  verdicts are queryable), and
- **Elastic's openly published detections** (protections-artifacts: YARA + behavioral rules).

Commercial vendors go through **real-agent dispatch** (running their shipped agent as
intended), never artifact extraction. This keeps a public tool clean legally and keeps you out
of trouble as a newly public name.

## 13. Security advisory (README, LitterBox-style)

- **Development use only.** Designed for testing environments. Production deployment presents
  significant risk.
- **Isolation is the operator's responsibility.** Run only in isolated VMs or a dedicated
  forensics/testing host. ScratchingPost is a professional tool and assumes professional host/VM
  separation. If you do not have it, do not detonate untrusted samples.
- **No warranty.** Provided as-is, use at your own risk.
- **Legal compliance.** Users are responsible for ensuring usage complies with applicable laws.
