"""Orchestrator <-> detonation API seam (ARCHITECTURE.md §8).

The narrow interface between the orchestrator and the environment where a sample
actually runs. In the MVP both sides are localhost inside one appliance, but the
seam is defined as the four-call contract it will stay when detonation later
splits to disposable sibling guests over the network — so that split is a new
`DetonationEnvironment` implementation, not a rewrite.

    detonate(sample, profile, timeout) -> run_id
    stream_telemetry(run_id)           -> uniform Event stream (live or captured)
    collect(run_id)                    -> telemetry + any agent/EDR alerts
    revert(profile)                    -> restore the detonation env to clean

`LocalAppliance` implements the localhost/single-appliance case. Its telemetry is
served from a JSONL capture via an injectable resolver, which is exactly the
capture/replay path (MODULE_CONTRACT.md §6) and lets the whole seam run with no
VM. The live path drives a hypervisor-agnostic `VmProvider` (`vm.py`): clone the
golden image, boot, push the sample in, run stock `eslogger` + the sample in the
guest, pull the raw capture back, convert it to the uniform schema host-side, then
delete the clone. The provider is injected, so the whole live flow (clone/boot/exec
ordering + raw→uniform conversion) is exercisable with a fake provider. Transfer is
over `exec` (not a shared folder): verified on macOS 26.5.2 that Parallels shared
folders do not mount inside a macOS guest, and that eslogger must run under a PTY
(`script`) or it block-buffers and loses events.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import gettempdir
from typing import Callable, Iterator, Protocol, runtime_checkable

from ..contracts.events import Event, EventType
from ..contracts.indicator import fnv1a_64
from ..contracts.sample import Sample
from ..pipeline.replay import read_capture, write_capture
from .vm import VmError, VmProvider


@dataclass
class CollectResult:
    run_id: str
    profile: str
    events: list[Event] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)  # agent/EDR verdicts (dispatch tiers)


@runtime_checkable
class DetonationEnvironment(Protocol):
    def detonate(self, sample: Sample, profile: str, timeout: float) -> str: ...
    def stream_telemetry(self, run_id: str) -> Iterator[Event]: ...
    def collect(self, run_id: str) -> CollectResult: ...
    def revert(self, profile: str) -> None: ...


@dataclass
class _RunRecord:
    run_id: str
    sample: Sample
    profile: str
    timeout: float
    capture_path: str | None
    vm_name: str | None = None  # per-run clone (live mode), deleted on revert
    # The Wazuh agent name this run enrolled under (dispatch path, unique per clone),
    # or None when the run used the golden's shared identity. The dispatch module
    # correlates the manager's alerts by this so back-to-back runs never collide.
    agent_name: str | None = None
    status: str = "detonated"


# Resolver maps a (sample, profile) run to a JSONL capture that stands in for the
# run's telemetry. Injected in dev/test; None in live mode.
CaptureResolver = Callable[[Sample, str], "str | None"]


class LocalAppliance:
    """Localhost/single-appliance DetonationEnvironment.

    `capture_resolver` supplies a JSONL capture per run (dev/replay mode). With
    `live=True` and an injected `VmProvider`, the clone→detonate→collect→revert path
    runs against a real guest instead.
    """

    # Guest-side raw/uniform capture filenames. The raw file is stock-eslogger ES
    # JSON; the uniform file is our Event schema after host-side conversion.
    RAW_CAPTURE = "events.raw.jsonl"
    UNIFORM_CAPTURE = "events.jsonl"
    # Uniform capture filtered to the sample's own process subtree (what the Wazuh
    # agent forwards, so its rules fire on the sample's behavior, not system noise).
    SCOPED_CAPTURE = "events.scoped.jsonl"

    # Boot-readiness poll for a freshly cloned guest (live mode). The guest agent
    # takes seconds-to-a-minute after power-on before `prlctl exec` can open a
    # session; poll until it answers rather than sleeping a fixed guess.
    GUEST_READY_TIMEOUT = 180.0
    GUEST_READY_INTERVAL = 2.0

    def __init__(
        self,
        capture_resolver: CaptureResolver | None = None,
        live: bool = False,
        golden_image: str = "ScratchingPost",
        golden_images: "dict[str, str] | None" = None,
        vm: VmProvider | None = None,
        share_root: str | None = None,
        eslogger_events: "tuple[str, ...] | None" = None,
        agent_ingest_path: str | None = None,
        agent_ingest_settle: float = 20.0,
        detonate_settle: float = 0.0,
        eslogger_start_delay: float = 0.0,
        unique_enrollment: bool = True,
        enrollment_password: str | None = None,
    ) -> None:
        self.capture_resolver = capture_resolver
        self.live = live
        # `golden_image` is the default/fallback golden; `golden_images` overrides it
        # per profile (e.g. {"wazuh": "ScratchingPost-wazuh"}) so a dispatch profile
        # clones its own agent-baked image while `apple` stays on the clean base
        # (ARCHITECTURE.md §6 — one golden per profile). A profile absent from the map
        # falls back to `golden_image`.
        self.golden_image = golden_image
        self.golden_images = golden_images or {}
        self.vm = vm
        # Host root under which each run gets a share dir the guest writes into.
        self.share_root = Path(share_root) if share_root else Path(gettempdir()) / "scratchingpost-runs"
        self.eslogger_events = eslogger_events
        # Dispatch (wazuh) profiles run a Wazuh agent inside the guest. The custom
        # MITRE rules key on ScratchingPost's *uniform* Event schema, which stock
        # `eslogger` does not emit (its raw ES output uses a numeric `event_type` and
        # `process.executable.path`); the uniform form is produced only by the host-side
        # conversion below. So for those profiles we push the converted uniform capture
        # back into the clone at the path the agent's <localfile> tails, and let the real
        # in-guest agent forward it to the manager (alerts attribute to that agent).
        # None (the apple path) skips this entirely. `agent_ingest_settle` is the pause
        # for the agent -> manager -> indexer hop before the run window is queried.
        self.agent_ingest_path = agent_ingest_path
        self.agent_ingest_settle = agent_ingest_settle
        # A freshly booted macOS guest storms with events (Spotlight, launch services,
        # log/db writes) for ~20 s; capturing through it buries the sample and drops its
        # events under ES client load. `detonate_settle` waits out the storm before the
        # capture so it stays small and the sample's events survive. `eslogger_start_delay`
        # is the pause after launching eslogger before the sample runs, so the ES client
        # finishes subscribing first (an instant sample otherwise acts before eslogger is
        # listening). Both default to 0 (the apple path); the wazuh env sets them, and
        # pairs them with a rule-relevant, low-volume `eslogger_events` set (no
        # write/mmap/mprotect/signal firehose) so the pushed capture is a few hundred KB.
        self.detonate_settle = detonate_settle
        self.eslogger_start_delay = eslogger_start_delay
        # Dispatch (wazuh) profiles: enroll each clone as its OWN unique Wazuh agent
        # (via `agent-auth`) instead of reusing the golden's baked identity (agent id
        # 001, `scratchingpost-wazuh.shared`). Every clone sharing id 001 was the root
        # of a reliability trap — a stale remoted connection for 001 silently refused
        # the next clone, zeroing the dispatch tier until a manual manager restart (see
        # the wazuh-dispatch-reliability memory). A unique identity per run removes the
        # collision entirely, so back-to-back runs never need the restart. Best-effort
        # with a safe fallback: if enrollment can't complete (no manager address, authd
        # unreachable), the clone keeps the shared identity and still forwards. Gated on
        # the dispatch path (`agent_ingest_path`); the apple path never runs an agent.
        self.unique_enrollment = unique_enrollment
        # Optional authd registration password (`agent-auth -P`); None when the manager
        # accepts passwordless registration (wazuh-docker default).
        self.enrollment_password = enrollment_password
        self._runs: dict[str, _RunRecord] = {}
        self._counter = 0

    def _new_run_id(self, sample: Sample, profile: str) -> str:
        self._counter += 1
        return f"{fnv1a_64(f'{sample.sha256}:{profile}:{self._counter}'):016x}"

    def detonate(self, sample: Sample, profile: str, timeout: float) -> str:
        run_id = self._new_run_id(sample, profile)
        vm_name = None
        agent_name = None
        if self.live:
            golden = self._golden_for(profile)
            vm_name = self._new_clone_name(golden)
            capture_path, agent_name = self._detonate_live(
                sample, profile, timeout, run_id, vm_name, golden
            )
        else:
            capture_path = self.capture_resolver(sample, profile) if self.capture_resolver else None
        self._runs[run_id] = _RunRecord(
            run_id=run_id,
            sample=sample,
            profile=profile,
            timeout=timeout,
            capture_path=capture_path,
            vm_name=vm_name,
            agent_name=agent_name,
        )
        return run_id

    def agent_name_for(self, run_id: str) -> str | None:
        """The unique Wazuh agent name this run's clone enrolled under (dispatch path),
        or None if the run used the golden's shared identity (enrollment off/failed, or
        not a dispatch run). `WazuhModule` reads this after `detonate` so it correlates
        the manager's alerts by the run's own agent name — the durable fix for the
        shared-id-001 collision (no more manager restart between back-to-back runs)."""
        rec = self._runs.get(run_id)
        return rec.agent_name if rec else None

    def stream_telemetry(self, run_id: str) -> Iterator[Event]:
        rec = self._require(run_id)
        if rec.capture_path is None:
            return iter(())
        return read_capture(rec.capture_path)

    def collect(self, run_id: str) -> CollectResult:
        rec = self._require(run_id)
        events = list(self.stream_telemetry(run_id))
        # Agent/EDR alerts (dispatch tiers, e.g. Wazuh) attach here in a later
        # phase; the localhost apple profile has none.
        return CollectResult(run_id=run_id, profile=rec.profile, events=events, alerts=[])

    def revert(self, profile: str) -> None:
        if self.live:
            self._revert_live(profile)
        # Drop bookkeeping for runs of this profile; nothing durable lives here.
        self._runs = {rid: r for rid, r in self._runs.items() if r.profile != profile}

    # -- helpers -------------------------------------------------------------
    def _require(self, run_id: str) -> _RunRecord:
        rec = self._runs.get(run_id)
        if rec is None:
            raise KeyError(f"unknown run_id: {run_id}")
        return rec

    def _golden_for(self, profile: str) -> str:
        # The golden image to clone for this profile: the per-profile override if
        # one is registered, else the default `golden_image`.
        return self.golden_images.get(profile, self.golden_image)

    def _new_clone_name(self, golden: str) -> str:
        # Per-run clone named after the profile's golden image with a UUID appended,
        # so concurrent/serial clones never collide and trace back to their golden.
        return f"{golden}-{uuid.uuid4().hex}"

    def _wait_guest_ready(self, vm_name: str) -> None:
        """Poll guest-exec until the Parallels Tools agent answers.

        A freshly booted clone rejects `exec` with a non-zero rc until the guest
        agent can open a session (~5-60 s on macOS 26.5.2). Drives the injected
        provider's `exec`, so a fake provider (tests) returns ready on the first
        poll and no real time passes."""
        import time  # noqa: PLC0415

        deadline = time.monotonic() + self.GUEST_READY_TIMEOUT
        while True:
            rc, out, _err = self.vm.exec(vm_name, ["/usr/bin/whoami"])
            if rc == 0 and out.strip():
                return
            if time.monotonic() >= deadline:
                raise VmError(
                    f"guest {vm_name} did not become exec-ready within "
                    f"{self.GUEST_READY_TIMEOUT:g}s (Parallels Tools not answering)"
                )
            time.sleep(self.GUEST_READY_INTERVAL)

    # -- live path (validate guest specifics before enabling in production) ---
    def _detonate_live(
        self, sample: Sample, profile: str, timeout: float, run_id: str, vm_name: str, golden: str
    ) -> "tuple[str, str | None]":
        """Clone the golden image, boot it, run stock eslogger + the sample in the
        guest, pull the raw ES capture back, and convert it to the uniform schema.

        Transfer is over `exec`, not a shared folder: verified on macOS 26.5.2 that
        Parallels shared folders do not mount inside a macOS guest, so we push the
        sample in (base64 over exec) and `cat` the capture back out. Every hypervisor
        call still goes through the injected `VmProvider`.

        Returns `(uniform_capture_path, agent_name)`. `agent_name` is the unique Wazuh
        agent this clone enrolled under on the dispatch path (None when it kept the
        golden's shared identity, or for the apple path)."""
        if self.vm is None:
            raise VmError(
                "live detonation needs a VmProvider (LocalAppliance(vm=ParallelsProvider(), live=True)); "
                "use capture_resolver for replay mode"
            )

        share = self.share_root / run_id
        share.mkdir(parents=True, exist_ok=True)
        guest_dir = f"/tmp/scratchingpost-{run_id}"
        sample_guest = f"{guest_dir}/{Path(sample.path).name}"
        raw_guest = f"{guest_dir}/{self.RAW_CAPTURE}"

        # 1. clean snapshot of the golden image + boot it, then wait until the guest
        #    agent answers — `boot` returns as soon as the VM is powered on, well
        #    before `prlctl exec` can open a session (verified macOS 26.5.2).
        self.vm.clone(golden, vm_name)
        self.vm.boot(vm_name)
        self._wait_guest_ready(vm_name)
        # Dispatch (wazuh) profiles correlate the manager's alerts by a real-clock
        # time window (WazuhModule records `since = host now`, then queries
        # `@timestamp >= since`). A fresh clone can boot ~tens of minutes behind real
        # time — its RTC is stale and NTP has not converged within the short
        # detonation window — so the in-guest agent stamps forwarded alerts with that
        # skewed time and they land *before* the window start; the dispatch tier then
        # sees zero alerts even though the rules fired (verified: a run's 100020
        # landed 72 min behind and was missed). Set the guest clock to host UTC before
        # capturing so alert timestamps align with the query window. Only the dispatch
        # path needs this (the apple path orders by mach_time/seq, not wall clock).
        agent_name: str | None = None
        if self.agent_ingest_path:
            self._sync_guest_clock(vm_name)
            # Enroll this clone as its own unique Wazuh agent so it never collides with
            # a prior run on the shared golden identity (id 001). Best-effort: on any
            # failure it keeps the baked identity and forwards under that instead.
            if self.unique_enrollment:
                agent_name = self._enroll_unique_agent(vm_name, run_id)
        if self.detonate_settle > 0:
            import time  # noqa: PLC0415

            time.sleep(self.detonate_settle)

        # 2. push the sample in over exec (no shared folder on a macOS guest).
        self.vm.exec(vm_name, ["/bin/mkdir", "-p", guest_dir])
        self._push_file(vm_name, sample.path, sample_guest)

        # 3. inside the guest (as root): stock eslogger over our event set to a guest
        #    file while the sample runs under a wall-clock cap. Only Apple's
        #    /usr/bin/eslogger is needed — no repo code in the guest.
        self.vm.exec(vm_name, self._guest_detonate_cmd(sample_guest, raw_guest, timeout))

        # 4. pull the raw ES JSONL back out and convert to the uniform Event schema so
        #    stream_telemetry()/read_capture() can serve it.
        rc, out, _err = self.vm.exec(vm_name, ["/bin/cat", raw_guest])
        raw_host = share / self.RAW_CAPTURE
        raw_host.write_text(out if rc == 0 else "")
        uniform_host = share / self.UNIFORM_CAPTURE
        _convert_raw_capture(raw_host, uniform_host)

        # 5. dispatch profiles only: hand the uniform capture to the in-guest Wazuh
        #    agent so its custom rules fire and the manager attributes the alerts to
        #    the real agent. The clone is still alive here (revert/delete is later), so
        #    we append the capture to the file the agent's <localfile> tails, then let
        #    it forward before the caller queries the manager for this window.
        if self.agent_ingest_path:
            import time  # noqa: PLC0415

            # Forward only the sample's own process subtree, so the agent's rules
            # fire on the sample's behavior and not on system-wide noise the
            # capture also caught (ROADMAP limitation 3). If the sample's exec was
            # dropped from the capture (boot-storm load), scoping can't find the
            # root — fall back to the full capture rather than forward nothing.
            scoped_events, root_pid = scope_events_to_subtree(
                list(read_capture(uniform_host)), sample_guest
            )
            if root_pid is not None:
                ingest_host = share / self.SCOPED_CAPTURE
                write_capture(ingest_host, scoped_events)
            else:
                ingest_host = uniform_host

            guest_dir_for_ingest = str(Path(self.agent_ingest_path).parent)
            self.vm.exec(vm_name, ["/bin/mkdir", "-p", guest_dir_for_ingest])
            self._push_file(vm_name, str(ingest_host), self.agent_ingest_path, append=True)
            if self.agent_ingest_settle > 0:
                time.sleep(self.agent_ingest_settle)
        return str(uniform_host), agent_name

    def _sync_guest_clock(self, vm_name: str) -> None:
        """Set the guest clock to the host's current UTC (BSD `date` set format
        `ccyymmddHHMM.SS`), as root over `exec`. Removes the fresh-clone clock skew
        that otherwise puts agent-forwarded alert timestamps outside the dispatch
        query window. NTP, if enabled in the guest, only corrects *toward* real time,
        so a manual set is never pushed back to the stale value."""
        import time  # noqa: PLC0415

        stamp = time.strftime("%Y%m%d%H%M.%S", time.gmtime())
        self.vm.exec(vm_name, ["/bin/date", "-u", stamp])

    def _enroll_unique_agent(self, vm_name: str, run_id: str) -> "str | None":
        """Register this clone as its own unique Wazuh agent and return the name it
        enrolled under, or None to fall back to the golden's shared identity.

        Every clone otherwise reuses the golden's baked `client.keys` (agent id 001,
        `scratchingpost-wazuh.shared`), and two clones cannot both hold that id on the
        manager's remoted — a stale id-001 connection silently refuses the next clone
        and the dispatch tier forwards nothing (the wazuh-dispatch-reliability trap).
        Registering a fresh unique agent per run removes the collision at its root.

        Driven entirely over `exec` with tooling already in the golden (`agent-auth`),
        so no golden rebuild is needed. Reads the manager address from the guest's own
        `ossec.conf` (robust to the manager's DHCP address changing) rather than
        hardcoding it. Best-effort and reversible: the baked key is backed up first, so
        a failed registration restores the shared identity (which still forwards) rather
        than leaving the clone with no key (which would forward nothing)."""
        agent_name = f"scratchingpost-{run_id}"

        rc, out, _err = self.vm.exec(
            vm_name,
            [f"grep -oE '<address>[^<]+' {self.WAZUH_OSSEC_CONF} | head -1 | cut -d'>' -f2"],
        )
        manager = out.strip() if rc == 0 else ""
        if not manager:
            return None  # no manager address -> can't reach authd; keep shared identity

        # Back up the baked key so a failed enrollment degrades to the shared identity,
        # then truncate it: `agent-auth` writes the new key, and starting from an empty
        # file guarantees the agent's ONLY identity is the unique one (so it can't keep
        # connecting as the baked id 001 if agent-auth were to append rather than
        # overwrite — which would defeat the whole point while the verify still passed).
        self.vm.exec(vm_name, [f"cp {self.WAZUH_CLIENT_KEYS} {self.WAZUH_CLIENT_KEYS}.pre-enroll"])
        self.vm.exec(vm_name, [f": > {self.WAZUH_CLIENT_KEYS}"])

        argv = [self.WAZUH_AGENT_AUTH, "-m", manager, "-A", agent_name]
        if self.enrollment_password:
            argv += ["-P", self.enrollment_password]
        rc, _out, _err = self.vm.exec(vm_name, argv)
        if rc != 0:
            self._restore_shared_identity(vm_name)
            return None

        # Reload the agent so it connects under the freshly written unique key, then
        # confirm the new identity actually took before correlating alerts by it.
        self.vm.exec(vm_name, [self.WAZUH_CONTROL, "restart"])
        rc, keys, _err = self.vm.exec(vm_name, ["/bin/cat", self.WAZUH_CLIENT_KEYS])
        if rc == 0 and agent_name in keys:
            return agent_name
        self._restore_shared_identity(vm_name)
        return None

    def _restore_shared_identity(self, vm_name: str) -> None:
        """Put the baked `client.keys` back and reload the agent, so a failed unique
        enrollment leaves the clone forwarding under the shared identity rather than
        with no usable key."""
        self.vm.exec(vm_name, [f"cp {self.WAZUH_CLIENT_KEYS}.pre-enroll {self.WAZUH_CLIENT_KEYS} 2>/dev/null"])
        self.vm.exec(vm_name, [self.WAZUH_CONTROL, "restart"])

    # Max base64 chars per `exec` argv. `prlctl exec` passes the command as process
    # args, so a single huge argv hits ARG_MAX ("Argument list too long"): a Mach-O
    # sample fits in one, but a full detonation's uniform capture does not. Stream the
    # base64 into a guest temp file in bounded chunks, then decode it once.
    PUSH_CHUNK = 100_000

    def _push_file(self, vm_name: str, host_path: str, guest_path: str, append: bool = False) -> None:
        """Copy a host file into the guest over `exec`, base64-encoded (a macOS guest
        has no host->guest shared folder). The base64 is streamed in `PUSH_CHUNK`-sized
        appends to a `.b64` temp in the guest, then decoded once — so an arbitrarily
        large capture never overflows a single `exec` argv.

        Each pipeline is one argv element on purpose: `prlctl exec` joins its trailing
        args with spaces and runs the result under `bash -c` in the guest, so a
        `["/bin/sh", "-c", cmd]` wrapper would be double-wrapped (`bash -c "/bin/sh -c
        cmd"`) and mis-parse the pipeline (verified macOS 26.5.2). `b64encode` emits no
        newlines, so each chunk stays on one line."""
        import base64  # noqa: PLC0415

        b64 = base64.b64encode(Path(host_path).read_bytes()).decode("ascii")
        tmp = f"{guest_path}.b64"
        # First chunk truncates the temp; the rest append. Decoding the whole temp in
        # one pass avoids base64 group-boundary issues from per-chunk decoding.
        for i in range(0, len(b64), self.PUSH_CHUNK):
            redirect = ">" if i == 0 else ">>"
            self.vm.exec(vm_name, [f"printf %s '{b64[i:i + self.PUSH_CHUNK]}' {redirect} '{tmp}'"])
        redirect = ">>" if append else ">"
        self.vm.exec(vm_name, [f"/usr/bin/base64 -D < '{tmp}' {redirect} '{guest_path}'; rm -f '{tmp}'"])

    def _guest_detonate_cmd(self, sample_guest: str, raw_guest: str, timeout: float) -> list[str]:
        """The one-liner run inside the guest (as root) to capture + detonate.

        eslogger is wrapped in `script -q /dev/null` so its stdout gets a PTY and is
        line-buffered — verified on macOS 26.5.2 that without a PTY eslogger
        block-buffers to a file and most events are lost when it is killed. The sample
        runs under a wall-clock cap via a shell background+sleep+kill (macOS has no
        stock `timeout(1)`). A trailing `sleep` after the sample's cap lets eslogger
        flush the sample's final events before it is killed.

        Returned as a single argv element: `prlctl exec` joins trailing args and runs
        them under `bash -c` in the guest, so wrapping in `["/bin/sh", "-c", ...]`
        would be double-wrapped and mis-parsed (verified macOS 26.5.2)."""
        from sensors.eslogger.recorder import DEFAULT_EVENTS  # noqa: PLC0415

        events = " ".join(self.eslogger_events or DEFAULT_EVENTS)
        # Let the ES client finish subscribing before the sample runs, else an instant
        # sample acts before eslogger is listening and its events are missed.
        subscribe = f"sleep {self.eslogger_start_delay:g}; " if self.eslogger_start_delay > 0 else ""
        script = (
            f"script -q /dev/null /usr/bin/eslogger {events} > {raw_guest} 2>/dev/null & ES=$!; "
            f"chmod +x {sample_guest} 2>/dev/null; "
            f"{subscribe}"
            f"( {sample_guest} & SP=$!; sleep {timeout:g}; kill $SP 2>/dev/null ) ; "
            f"sleep 1; kill $ES 2>/dev/null; pkill -f eslogger 2>/dev/null"
        )
        return [script]

    # Guest paths under the macOS Wazuh agent install root.
    WAZUH_CONTROL = "/Library/Ossec/bin/wazuh-control"
    WAZUH_AGENT_AUTH = "/Library/Ossec/bin/agent-auth"
    WAZUH_CLIENT_KEYS = "/Library/Ossec/etc/client.keys"
    WAZUH_OSSEC_CONF = "/Library/Ossec/etc/ossec.conf"

    def _revert_live(self, profile: str) -> None:
        """Delete the per-run clones for this profile; the golden image is untouched,
        so the next detonate re-clones clean (ARCHITECTURE.md §3).

        For dispatch (wazuh) profiles, gracefully stop the in-guest Wazuh agent
        *before* deleting the clone. With per-clone unique enrollment on
        (`unique_enrollment`, the default) each run holds its own agent id, so the
        shared-id-001 collision is gone at its root; the clean stop remains cheap
        hygiene — it closes the run's connection promptly so the manager marks that
        agent Disconnected instead of holding a stale "Active" keepalive. It also
        preserves the fallback path: if enrollment failed and the clone kept the shared
        identity (id 001), stopping before delete still frees 001 for the next run —
        which was the original fix for back-to-back detonations forwarding nothing
        (verified: three rapid runs produced zero alerts while the id stayed "Active"
        from the prior run's dead connection)."""
        if self.vm is None:
            return
        for rec in self._runs.values():
            if rec.profile == profile and rec.vm_name:
                if self.agent_ingest_path:
                    try:
                        self.vm.exec(rec.vm_name, [self.WAZUH_CONTROL, "stop"])
                    except VmError:
                        pass  # best-effort; the clone is being destroyed regardless
                self.vm.delete(rec.vm_name)


def _norm_guest_path(p: str) -> str:
    """Normalize a guest path for comparison. `/tmp` on macOS is a symlink to
    `/private/tmp`, so eslogger reports the sample's exec path as
    `/private/tmp/scratchingpost-<id>/<name>` while the seam pushed it to
    `/tmp/scratchingpost-<id>/<name>`. Strip a leading `/private` so the two
    compare equal — without this the sample's own exec is never matched and
    subtree scoping drops the entire capture (verified: macOS symlinks `/tmp`,
    `/etc`, `/var` under `/private`)."""
    for pref in ("/private/tmp/", "/private/var/", "/private/etc/"):
        if p.startswith(pref):
            return p[len("/private"):]
    return p


def scope_events_to_subtree(
    events: "list[Event]", sample_guest_path: str
) -> "tuple[list[Event], int | None]":
    """Filter a uniform capture to the detonated sample's process subtree.

    The eslogger capture is system-wide, so macOS's own services (e.g.
    `coreservicesd` doing a legitimate `task_for_pid`) trip the dispatch rules as
    false positives (ROADMAP limitation 3). Keep only events whose acting process
    is the sample, a descendant of it, or a process the sample is *responsible*
    for — the macOS "responsible process" attribution (`responsible_pid`), which
    is how a helper the sample launches via launchservices/XPC (parented to
    `launchd`, not the sample) still attributes back to it.

    Seeds on the sample's own exec: the exec event whose acting-process path is the
    pushed sample (normalized for the `/tmp`->`/private/tmp` symlink). One forward
    pass in `seq` order grows the live pid set as forks/execs appear, so a child's
    later events are matched even though it did not exist when the pass began.

    Returns `(scoped_events, root_pid)`. `root_pid` is None when the sample's exec
    is absent from the capture (e.g. dropped under boot-storm load) — the caller
    must then fall back to the full capture rather than forward an empty one."""
    ordered = sorted(events, key=lambda e: e.seq)
    target = _norm_guest_path(sample_guest_path)

    root_pid: int | None = None
    for ev in ordered:
        if (
            ev.event_type == EventType.EXEC
            and ev.process is not None
            and _norm_guest_path(ev.process.path) == target
        ):
            root_pid = ev.pid
            break
    if root_pid is None:
        return [], None

    subtree = {root_pid}
    scoped: list[Event] = []
    for ev in ordered:
        resp = ev.process.responsible_pid if ev.process is not None else -1
        in_tree = (
            ev.pid in subtree
            or (ev.ppid is not None and ev.ppid in subtree)
            or (resp in subtree)
        )
        if not in_tree:
            continue
        subtree.add(ev.pid)
        # A fork/exec child joins the subtree even before its own events appear.
        child = ev.payload.get("child_pid")
        if isinstance(child, int) and child > 0:
            subtree.add(child)
        scoped.append(ev)
    return scoped, root_pid


def _convert_raw_capture(raw_path: Path, uniform_path: Path) -> int:
    """Parse a stock-eslogger raw ES JSONL capture into the uniform Event schema.

    Lives here (not in the recorder) because the live seam is what produces the raw
    file host-side. It is the single lazy orchestrator->sensor touch: the parser is
    pure and depends only on the contracts, so the layering (sensors import from
    orchestrator, not the reverse) is preserved by importing it lazily and not at
    module import time. Returns the number of events written."""
    from sensors.eslogger.parser import parse_line  # noqa: PLC0415

    n = 0
    with open(raw_path, "r", encoding="utf-8") as src, open(uniform_path, "w", encoding="utf-8") as dst:
        for line in src:
            ev = parse_line(line)
            if ev is not None:
                dst.write(json.dumps(ev.to_dict(), separators=(",", ":")))
                dst.write("\n")
                n += 1
    return n


def capture_dir_resolver(mapping: dict[str, str]) -> CaptureResolver:
    """Convenience resolver: profile -> capture-path. Serves the same capture for
    every sample of a profile (handy for dev and tests)."""

    def resolve(_sample: Sample, profile: str) -> str | None:
        path = mapping.get(profile)
        return path if path and Path(path).exists() else None

    return resolve
