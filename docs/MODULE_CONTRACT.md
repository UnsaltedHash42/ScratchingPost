# ScratchingPost — Detection Module Contract & Event Schema

This is the contract that lets all detection tiers report indicators into one Detection
Score. It is the macOS equivalent of heavener's `IEdrModule`, adapted for the fact that
ScratchingPost's modules run in two different execution models.

**Language split (honest polyglot reality):**
- **Orchestrator, UI, scoring, static parsers, module host: Python.** Matches LitterBox
  (Flask), matches your existing Python work, and the control plane does not need to be native.
- **ESF recorder, custom system extension, memory/injection scanner: Swift / Obj-C / C.**
  These touch the kernel and Mach internals; they must be native. They expose their output to
  the Python host over the uniform event schema (§3) and simple IPC (a local socket or the
  JSONL capture format in §6).

## 1. The four detection tiers as module types

| Tier | Execution model | Runs where | Examples |
|---|---|---|---|
| **Static** | in-process, synchronous | Linux-side / anywhere (bytes) | Mach-O parse, signing/notarization/entitlements/quarantine, YARA, XProtect-YARA bisect |
| **Behavioral** | consumes event stream | reads ESF telemetry | exec-tree analysis, injection/dylib heuristics, TCC-reach heuristics, script-content (AMSI-gap) |
| **Offline emulation** | in-process, consumes events | anywhere | Apple built-in (XProtect YARA + Gatekeeper verdicts), Elastic (protections-artifacts rules) |
| **Real-agent dispatch** | async, submit-and-collect | detonation env | Wazuh (live agent), commercial EDR profiles |

The key design tension: **static and emulation modules are synchronous and in-process;
real-agent modules are "go detonate this and wait."** The contract must serve both.

## 2. The module interface

One interface, with a capabilities descriptor (heavener's `ModuleCaps` idea) so the host
knows which methods a given module actually implements. Real-agent modules don't implement
`scan_static`; static modules don't implement `on_event`.

```python
from dataclasses import dataclass
from enum import Flag, auto
from typing import Protocol, Iterable

class ModuleCaps(Flag):
    STATIC      = auto()   # implements scan_static()
    BEHAVIORAL  = auto()   # implements on_event()
    DISPATCH    = auto()   # implements dispatch()/collect()

@dataclass
class ModuleConfig:
    data_dir: str                 # rule files, model files, vendor data
    profile: str | None = None    # detonation profile for dispatch modules
    options: dict = None          # module-specific knobs

class DetectionModule(Protocol):
    def name(self) -> str: ...
    def version(self) -> str: ...
    def capabilities(self) -> ModuleCaps: ...

    def initialize(self, cfg: ModuleConfig) -> None: ...
    def shutdown(self) -> None: ...

    # STATIC modules: one-shot analysis of the sample bytes.
    def scan_static(self, sample: "Sample") -> Iterable["Indicator"]: ...

    # BEHAVIORAL / emulation modules: fed the uniform event stream in order,
    # with a live view of the process model. Accumulate state, emit later.
    def on_event(self, event: "Event", model: "ProcessModel") -> None: ...

    # DISPATCH modules: run the sample in the detonation env, then collect.
    # Implemented over the orchestrator<->detonation API seam (ARCHITECTURE.md §8).
    def dispatch(self, sample: "Sample", profile: str) -> str: ...   # -> run_id
    def collect(self, run_id: str) -> Iterable["Indicator"]: ...

    # All modules: drain everything accumulated this run.
    def drain_indicators(self) -> list["Indicator"]: ...
```

Design notes:
- Dispatch modules can be modeled two ways. Either they emit `Indicator`s directly from
  `collect()` (agent's own alerts), **or** they translate the agent's telemetry back into the
  uniform event schema and let it re-enter through `on_event()` on the shared pipeline. Prefer
  the former for real agents (you want the agent's verdict, not to re-derive it) and the
  latter for the ESF recorder itself (which is the source of the behavioral stream).
- Single-threaded, ordered event delivery, exactly like heavener's `EventPipeline`. Detection
  logic cares about ordering: exec → file-write → dylib-load is a different story shuffled.
  One worker thread guarantees every behavioral module sees events in the same order.

## 3. The uniform event schema (macOS `Event`)

The macOS equivalent of heavener's `BehavioralEvent`, derived from the ESF taxonomy rather
than ETW/kernel-callbacks. A typed header plus an event-specific payload.

**Core event types (mapped from ESF, confirmed available):**

| ScratchingPost event | ESF source | Why it matters |
|---|---|---|
| `EXEC` | `ES_EVENT_TYPE_NOTIFY_EXEC` | process creation, argv, env (DYLD_INSERT_LIBRARIES visible here), signing info of the image |
| `FORK` | `NOTIFY_FORK` | process tree |
| `EXIT` | `NOTIFY_EXIT` | lifecycle |
| `FILE_CREATE/WRITE/RENAME/UNLINK` | `NOTIFY_CREATE` / `WRITE` / `RENAME` / `UNLINK` | drops, staging, ransomware bursts |
| `MMAP` | `NOTIFY_MMAP` | executable mappings, dylib loads |
| `MPROTECT` | `NOTIFY_MPROTECT` | W^X transitions, RWX regions |
| `SIGNAL` | `NOTIFY_SIGNAL` | debugging / control |
| `PTRACE` | `NOTIFY_PTRACE` | anti-debug and injection attempts |
| `GET_TASK` | `NOTIFY_GET_TASK` (+ variants) | task-port acquisition = the surviving injection primitive |
| `CS_INVALIDATED` | `NOTIFY_CS_INVALIDATED` | code signature invalidated at runtime = tampering/unsigned exec |
| `BTM_LAUNCH_ITEM_ADD` | `NOTIFY_BTM_LAUNCH_ITEM_ADD` | **persistence as a first-class event**: LaunchAgent/Daemon/login-item add, no path-heuristic guessing |
| `XPROTECT` | `NOTIFY_XP_MALWARE_DETECTED` / `_REMEDIATED` | Apple's own detection firing |
| `TCC_MODIFY` / auth events | ESF AUTH events (needs custom sysext, not eslogger) | payload reaching for protected resources |
| `SCRIPT_EXEC` | synthesized from `EXEC` of an interpreter + arg capture | **the AMSI-gap fill**: pull the script body, YARA it |
| `DYLIB_LOAD` | derived from `MMAP` / image events | dylib injection & hijacking (Callandor territory) |

**The process model node (`ProcessInfo`), macOS-flavored.** Where heavener carries
integrity level, SID, and PE version-info, ScratchingPost carries code-identity fields:

```python
@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    responsible_pid: int          # macOS "responsible process" — gamed to inherit TCC grants
    path: str
    argv: list[str]
    env: dict[str, str]           # DYLD_* injection lives here
    # --- code identity (the macOS detection surface) ---
    team_id: str | None
    signing_id: str | None
    cdhash: str
    is_platform_binary: bool
    signature_type: str           # unsigned | adhoc | developer_id | app_store | platform
    is_notarized: bool
    hardened_runtime: bool
    entitlements: dict            # dangerous ones flagged: get-task-allow, disable-library-validation, cs.allow-dyld-environment-variables
    quarantine: bool              # com.apple.quarantine xattr present
    csflags: int                  # runtime code-signing flags (CS_VALID, CS_HARD, etc.)
    # --- behavioral state accumulated across events ---
    loaded_dylibs: list[str]      # compare against on-disk Mach-O load commands to find injected images
    injected_by_pid: int | None
    task_port_opened_by: int | None
    ext: dict                     # per-process scratch dict modules read/write across events
```

The process tree is dual-indexed (by pid for live lookup, by a stable uid for historical
lookup after pid reuse), same pattern as heavener's ProcessModel.

## 4. The `Indicator` schema

What every module emits, regardless of tier. This is the common currency the Detection Score
consumes.

```python
@dataclass
class Indicator:
    id: str                       # deterministic (FNV-1a of stable key) for idempotent replay
    name: str
    severity: str                 # info | low | medium | high | malicious
    tier: str                     # static | behavioral | emulation | dispatch
    module: str                   # which module produced it
    attack: list[str]             # MITRE ATT&CK technique IDs — BashBelt-style tagging
    description: str
    evidence: dict                # event refs, matched rule, flagged bytes, entitlement, etc.
```

ATT&CK tagging is a first-class field, carried the way BashBelt tags its modules. It drives
both the report and coverage introspection (a "Rule Atlas" equivalent: what surface is
actually being watched).

## 5. Detection Score aggregation

Borrowed and adapted from LitterBox's model, with credit. LitterBox does a good job here and
there is no reason to reinvent the shape; what changes is the **inputs**, because the macOS
signals are different.

- Each tier contributes weighted indicators. A `malicious`-severity static verdict (e.g.
  fails notarization + carries `get-task-allow` + unsigned dylib load) can dominate; a stack
  of `low` behavioral heuristics accumulates.
- The score exposes a **triggering-indicators breakdown**, not just a number: which tier,
  which module, which ATT&CK technique, what evidence. This is the operator-facing payload of
  the whole tool.
- Weighting is per-tier and tunable. Suggested starting posture: real-agent dispatch verdicts
  and Apple/Elastic emulation hits weigh heaviest (they mirror production detection); static
  code-identity failures weigh heavy (they gate whether the thing even runs); behavioral
  heuristics are corroborating signal that raises confidence.

> This is explicitly adapted from LitterBox. Credit it in the code and the README.

## 6. The capture / replay system (heavener's best idea, lift it whole)

Decouple module development from the detonation environment. Capture the ESF stream once,
develop and test every behavioral and emulation module against the capture, no live VM or
entitlement needed per iteration.

- **Capture:** the recorder (eslogger wrapper in MVP, custom sysext later) writes the uniform
  event stream to JSONL. A capture is a self-contained attack scenario.
- **Replay:** the module host loads a JSONL capture and pushes every event through the same
  single-threaded pipeline into the active modules, producing idempotent indicators (that is
  why indicator IDs are deterministic hashes).

```
# capture once, on the SIP-off detonation guest
eslogger exec fork exit create rename unlink mmap mprotect ptrace \
  get_task cs_invalidated btm_launch_item_add > scenario_dylib_hijack.jsonl

# iterate on module logic on your dev host, no VM in the loop
scratchingpost replay scenario_dylib_hijack.jsonl --module apple --module elastic
```

Development cycle mirrors heavener: run the payload on the guest once, capture, then replay
against modules on your laptop, tweak enrichment/routing, replay again.

## 7. Wazuh integration (corrected specifics)

Wazuh on macOS is **not** an ESF behavioral sensor (its real-time FIM is Windows/Linux only).
So the integration is:

- **Wazuh manager/indexer/dashboard** = persistent detection backend on the durable side
  (ARCHITECTURE.md §9). It provides correlation, alerting, the console, plus FIM +
  YARA-on-change + SCA + rootcheck + a readable XML ruleset you can borrow and adapt.
- **Your ESF recorder** = the macOS behavioral sensor Wazuh lacks. Pipe the uniform event
  stream into Wazuh as a **custom log source** with **custom decoders + rules** (tagged with
  MITRE technique IDs in `local_rules.xml`, which is Wazuh's native idiom).
- As a ScratchingPost module, Wazuh is a **dispatch** module: detonate in the `wazuh` profile,
  `collect()` the manager's alerts for the run, translate them into `Indicator`s.

Net: Wazuh becomes both a real-agent detection tier **and** the correlation/console backend,
while the behavioral events it can't collect on macOS come from your recorder.
