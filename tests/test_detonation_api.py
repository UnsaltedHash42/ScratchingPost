"""Detonation seam (ARCHITECTURE.md §8) over the localhost/single-appliance case,
exercised end to end through the replay-backed telemetry path."""

from pathlib import Path

import pytest

from orchestrator.contracts.events import Event, EventType
from orchestrator.contracts.process import ProcessInfo
from orchestrator.contracts.sample import Sample
from orchestrator.detonation import LocalAppliance, VmError, capture_dir_resolver
from orchestrator.detonation.api import scope_events_to_subtree
from orchestrator.pipeline import replay_events, write_capture

from tests.support import ExecWatchModule
from tests.test_pipeline_replay import _scenario

FIX = Path(__file__).parent / "fixtures" / "macho"


def _appliance(tmp_path):
    capture = tmp_path / "apple.jsonl"
    write_capture(capture, _scenario())
    resolver = capture_dir_resolver({"apple": str(capture)})
    return LocalAppliance(capture_resolver=resolver)


def test_detonate_stream_collect_revert(tmp_path):
    app = _appliance(tmp_path)
    sample = Sample.from_path(str(FIX / "thin_arm64"))

    run_id = app.detonate(sample, "apple", timeout=30.0)
    assert run_id

    streamed = list(app.stream_telemetry(run_id))
    assert len(streamed) == 4

    result = app.collect(run_id)
    assert result.profile == "apple"
    assert len(result.events) == 4
    assert result.alerts == []

    # seam -> pipeline: the collected telemetry drives detection modules.
    indicators = replay_events(result.events, [ExecWatchModule()])
    assert any(i.name == "exec-observed" for i in indicators)

    app.revert("apple")
    with pytest.raises(KeyError):
        app.collect(run_id)  # bookkeeping cleared on revert


def test_run_ids_unique_per_detonation(tmp_path):
    app = _appliance(tmp_path)
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    r1 = app.detonate(sample, "apple", timeout=5.0)
    r2 = app.detonate(sample, "apple", timeout=5.0)
    assert r1 != r2


def test_unknown_profile_streams_nothing(tmp_path):
    app = _appliance(tmp_path)
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    run_id = app.detonate(sample, "no-such-profile", timeout=5.0)
    assert list(app.stream_telemetry(run_id)) == []


def test_live_mode_without_provider_is_guarded():
    # live=True with no VmProvider is a configuration error, surfaced clearly.
    app = LocalAppliance(live=True)
    sample = Sample(path="/tmp/x", sha256="00", size=0)
    with pytest.raises(VmError):
        app.detonate(sample, "apple", timeout=5.0)


class FakeVm:
    """Records provider calls and simulates the guest over the exec transport: the
    `cat` of the raw capture returns a canned raw ES JSONL (Parallels macOS guests
    have no shared folder, so transfer is exec-only)."""

    name = "fake"

    def __init__(self, raw_fixture):
        self._raw = Path(raw_fixture).read_text()
        self.calls: list[tuple] = []

    def available(self):
        return True

    def clone(self, base, target):
        self.calls.append(("clone", base, target))

    def boot(self, vm):
        self.calls.append(("boot", vm))

    def suspend(self, vm):
        self.calls.append(("suspend", vm))

    def share_dir(self, vm, host_dir, mount_name):
        self.calls.append(("share_dir", vm, host_dir, mount_name))

    def exec(self, vm, argv):
        argv = list(argv)
        self.calls.append(("exec", vm, argv))
        # Simulate the guest agent answering the boot-readiness whoami poll.
        if argv and "whoami" in argv[0]:
            return (0, "root\n", "")
        # Simulate the guest returning the raw ES capture when it is cat'd back out.
        if argv and argv[0].endswith("cat"):
            return (0, self._raw, "")
        return (0, "", "")

    def ip(self, vm):
        return "10.211.55.7"

    def revert(self, vm, base):
        self.calls.append(("revert", vm, base))

    def delete(self, vm):
        self.calls.append(("delete", vm))


class EnrollFakeVm(FakeVm):
    """FakeVm that also simulates unique-agent enrollment: a manager address in the
    guest ossec.conf and a client.keys that reflects the last `agent-auth -A` name, so
    the dispatch path's unique-enrollment happy path runs end to end over the fake."""

    def __init__(self, raw_fixture, manager="10.0.0.9"):
        super().__init__(raw_fixture)
        self.manager = manager
        self.enrolled_name: str | None = None
        self._restarted = False  # a restart brings the (manager-acked) agent up

    def exec(self, vm, argv):
        argv = list(argv)
        if argv and argv[0] == LocalAppliance.WAZUH_AGENT_AUTH and "-A" in argv:
            self.enrolled_name = argv[argv.index("-A") + 1]
        if argv[:2] == [LocalAppliance.WAZUH_CONTROL, "restart"]:
            self._restarted = True
        # Manager address read from the guest's own ossec.conf (robust to DHCP).
        if argv and argv[0].startswith("grep -oE '<address>"):
            self.calls.append(("exec", vm, argv))
            return (0, self.manager + "\n", "")
        # The post-enrollment wait polls wazuh-agentd.state for a manager ACK; report
        # acked once the agent has been restarted so the unit test never incurs the real
        # connect-wait timeout.
        if argv and "wazuh-agentd.state" in argv[0] and "ACKED" in argv[0]:
            self.calls.append(("exec", vm, argv))
            return (0, ("ACKED\n" if self._restarted else ""), "")
        # The enrollment verify cats client.keys (distinct from the raw-capture cat).
        if argv and argv[0] == "/bin/cat" and argv[-1].endswith("client.keys"):
            self.calls.append(("exec", vm, argv))
            return (0, f"003 {self.enrolled_name or ''} any deadbeefkey\n", "")
        return super().exec(vm, argv)


ESLOGGER_FIX = Path(__file__).parent / "fixtures" / "eslogger" / "sample_capture.jsonl"


def test_live_detonation_drives_provider_and_converts_capture(tmp_path):
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(
        live=True, vm=vm, golden_image="golden-apple", share_root=str(tmp_path / "runs")
    )
    sample = Sample.from_path(str(FIX / "thin_arm64"))

    run_id = app.detonate(sample, "apple", timeout=2.0)

    # Clone the golden image to a per-run clone named "<golden>-<uuid>", boot it,
    # then everything else rides the exec transport.
    assert vm.calls[0][0] == "clone" and vm.calls[0][1] == "golden-apple"
    clone_name = vm.calls[0][2]
    assert clone_name.startswith("golden-apple-") and len(clone_name) > len("golden-apple-")
    assert vm.calls[1] == ("boot", clone_name)
    assert all(c[0] == "exec" for c in vm.calls[2:])  # whoami-poll, mkdir, push, detonate, cat
    assert any(c[2][0].endswith("cat") for c in vm.calls if c[0] == "exec")

    # Raw ES capture was converted to uniform Events the seam can stream/collect.
    events = list(app.stream_telemetry(run_id))
    assert events, "converted capture should yield uniform events"
    assert any(e.event_type.value == "exec" for e in events)

    # Revert deletes the per-run clone; golden image is untouched.
    app.revert("apple")
    assert ("delete", clone_name) in vm.calls


def test_agent_ingest_pushes_uniform_capture_to_guest_localfile(tmp_path):
    # Dispatch (wazuh) profiles: after host-side conversion the seam pushes the
    # UNIFORM capture into the running clone at the agent's <localfile> path, so the
    # in-guest Wazuh agent forwards it and the custom rules (which key on the uniform
    # schema, not stock eslogger's raw ES output) can fire on the manager.
    vm = FakeVm(ESLOGGER_FIX)
    ingest = "/var/log/scratchingpost/events.jsonl"
    app = LocalAppliance(
        live=True,
        vm=vm,
        golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path=ingest,
        agent_ingest_settle=0,  # no real sleep in tests
    )
    sample = Sample.from_path(str(FIX / "thin_arm64"))

    run_id = app.detonate(sample, "wazuh", timeout=1.0)

    execs = [c[2][0] for c in vm.calls if c[0] == "exec"]
    # The ingest dir is ensured, the base64 is streamed to a temp, and decoded with an
    # append into the agent's localfile (chunked so a large capture never overflows argv).
    assert any(c[2] == ["/bin/mkdir", "-p", "/var/log/scratchingpost"] for c in vm.calls if c[0] == "exec")
    decode = [e for e in execs if f">> '{ingest}'" in e and "base64 -D" in e]
    assert decode, "uniform capture should be decoded+appended to the agent localfile path"
    # The base64 streamed to the localfile's .b64 temp is the uniform capture (converted
    # events.jsonl), not the raw ES capture: decode it and confirm uniform-schema lines.
    import base64 as _b64
    chunks = [e.split("printf %s '", 1)[1].split("'", 1)[0]
              for e in execs if f"'{ingest}.b64'" in e and "printf %s" in e]
    pushed = _b64.b64decode("".join(chunks)).decode("utf-8").splitlines()
    assert pushed and all('"event_type"' in ln for ln in pushed if ln.strip())

    # The apple (behavioral) path is unaffected: same appliance would skip ingest when
    # agent_ingest_path is None (covered by the conversion test above).
    events = list(app.stream_telemetry(run_id))
    assert any(e.event_type.value == "exec" for e in events)


def test_dispatch_path_syncs_guest_clock_apple_path_does_not(tmp_path):
    # A fresh clone can boot minutes behind real time; the in-guest Wazuh agent then
    # stamps forwarded alerts outside the module's real-clock query window. The
    # dispatch path sets the guest clock to host UTC (BSD `date` set) after boot; the
    # apple path (no agent_ingest_path) leaves the clock alone.
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(
        live=True, vm=vm, golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path="/var/log/scratchingpost/events.jsonl",
        agent_ingest_settle=0,
    )
    app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "wazuh", timeout=1.0)
    date_calls = [c for c in vm.calls if c[0] == "exec" and c[2][:2] == ["/bin/date", "-u"]]
    assert date_calls, "dispatch path should set the guest clock to host UTC"

    vm2 = FakeVm(ESLOGGER_FIX)
    app2 = LocalAppliance(live=True, vm=vm2, golden_image="golden-apple",
                          share_root=str(tmp_path / "runs2"))
    app2.detonate(Sample.from_path(str(FIX / "thin_arm64")), "apple", timeout=1.0)
    assert not any(c[0] == "exec" and c[2][:1] == ["/bin/date"] for c in vm2.calls)


def test_dispatch_revert_stops_agent_before_deleting_clone(tmp_path):
    # All clones share the golden's agent identity; an abrupt delete leaves the manager
    # holding a stale connection so the next clone can't forward. Revert of a dispatch
    # run must gracefully stop the in-guest agent BEFORE deleting the clone. The apple
    # path has no agent, so it just deletes.
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(
        live=True, vm=vm, golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path="/var/log/scratchingpost/events.jsonl",
        agent_ingest_settle=0,
    )
    app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "wazuh", timeout=1.0)
    clone = [c[2] for c in vm.calls if c[0] == "clone"][0]
    app.revert("wazuh")
    stop_idx = next(i for i, c in enumerate(vm.calls)
                    if c[0] == "exec" and c[2] == ["/Library/Ossec/bin/wazuh-control", "stop"])
    del_idx = next(i for i, c in enumerate(vm.calls) if c == ("delete", clone))
    assert stop_idx < del_idx, "agent must be stopped before the clone is deleted"

    vm2 = FakeVm(ESLOGGER_FIX)
    app2 = LocalAppliance(live=True, vm=vm2, golden_image="golden-apple",
                          share_root=str(tmp_path / "runs2"))
    app2.detonate(Sample.from_path(str(FIX / "thin_arm64")), "apple", timeout=1.0)
    app2.revert("apple")
    assert not any(c[0] == "exec" and "wazuh-control" in c[2][0] for c in vm2.calls)


def test_agent_ingest_default_off_leaves_apple_path_unchanged(tmp_path):
    # Without agent_ingest_path the seam never touches an agent localfile (no mkdir of
    # the ingest dir, no append) — the apple profile stays a pure host-side conversion.
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(live=True, vm=vm, golden_image="golden-apple",
                         share_root=str(tmp_path / "runs"))
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    app.detonate(sample, "apple", timeout=1.0)
    assert not any(">> '" in c[2][0] for c in vm.calls if c[0] == "exec")
    assert not any("scratchingpost/events.jsonl" in c[2][0] for c in vm.calls if c[0] == "exec")


def test_dispatch_unique_enrollment_registers_and_exposes_run_agent(tmp_path):
    # The durable fix for the shared-id-001 collision: each dispatch clone enrolls as
    # its OWN Wazuh agent via agent-auth (manager read from the guest ossec.conf), and
    # the run's unique name is exposed so the dispatch module correlates by it.
    vm = EnrollFakeVm(ESLOGGER_FIX, manager="10.0.0.9")
    app = LocalAppliance(
        live=True, vm=vm, golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path="/var/log/scratchingpost/events.jsonl",
        agent_ingest_settle=0,
        unique_enrollment=True,  # opt-in (off by default; see the NAT-source-IP caveat)
    )
    run_id = app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "wazuh", timeout=1.0)

    # The unique name derives from the CLONE uuid (unique per run), not the deterministic
    # run_id — else repeat runs of a sample request the same name and authd rejects the
    # duplicate. Recover the clone name to compute the expected agent name.
    clone_name = next(c[2] for c in vm.calls if c[0] == "clone")
    expected = f"scratchingpost-{clone_name.rsplit('-', 1)[-1]}"

    auth = [c[2] for c in vm.calls if c[0] == "exec" and c[2][0] == LocalAppliance.WAZUH_AGENT_AUTH]
    assert auth, "dispatch path should register a unique agent via agent-auth"
    a = auth[0]
    assert a[1:3] == ["-m", "10.0.0.9"]                     # manager from the guest ossec.conf
    assert a[3] == "-A" and a[4] == expected               # unique per-run name (clone uuid)
    # The agent is reloaded so it connects under the new key.
    assert ["/Library/Ossec/bin/wazuh-control", "restart"] in [c[2] for c in vm.calls if c[0] == "exec"]
    # ...and the run's name is what the dispatch module will correlate the window by.
    assert app.agent_name_for(run_id) == expected


def test_unique_enrollment_falls_back_to_shared_identity_without_manager(tmp_path):
    # Working-app fallback: if the manager address can't be read (enrollment can't
    # reach authd), the clone keeps the baked shared identity and still forwards —
    # agent_name_for is None (the dispatch module then uses the configured shared name),
    # and no agent-auth is attempted (nothing to restore).
    vm = FakeVm(ESLOGGER_FIX)  # plain fake: grep for the address returns nothing
    app = LocalAppliance(
        live=True, vm=vm, golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path="/var/log/scratchingpost/events.jsonl",
        agent_ingest_settle=0,
        unique_enrollment=True,
    )
    run_id = app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "wazuh", timeout=1.0)
    assert app.agent_name_for(run_id) is None
    assert not any(c[0] == "exec" and c[2][0] == LocalAppliance.WAZUH_AGENT_AUTH for c in vm.calls)


def test_apple_path_never_enrolls(tmp_path):
    # Enrollment is dispatch-only: the apple path runs no Wazuh agent, so it neither
    # reads the manager address nor registers.
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(live=True, vm=vm, golden_image="golden-apple",
                         share_root=str(tmp_path / "runs"),
                         unique_enrollment=True)  # on, but the apple path still must not enroll
    run_id = app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "apple", timeout=1.0)
    assert app.agent_name_for(run_id) is None
    assert not any(
        c[0] == "exec" and (c[2][0] == LocalAppliance.WAZUH_AGENT_AUTH
                            or c[2][0].startswith("grep -oE '<address>"))
        for c in vm.calls
    )


def test_unique_enrollment_opt_out_keeps_shared_identity(tmp_path):
    # unique_enrollment=False restores the pre-fix behavior (shared golden identity),
    # for a caller that deliberately wants it.
    vm = EnrollFakeVm(ESLOGGER_FIX)
    app = LocalAppliance(
        live=True, vm=vm, golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
        agent_ingest_path="/var/log/scratchingpost/events.jsonl",
        agent_ingest_settle=0,
        unique_enrollment=False,
    )
    run_id = app.detonate(Sample.from_path(str(FIX / "thin_arm64")), "wazuh", timeout=1.0)
    assert app.agent_name_for(run_id) is None
    assert not any(c[0] == "exec" and c[2][0] == LocalAppliance.WAZUH_AGENT_AUTH for c in vm.calls)


def test_clone_names_are_unique_per_run(tmp_path):
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(live=True, vm=vm, golden_image="ScratchingPost",
                         share_root=str(tmp_path / "runs"))
    sample = Sample.from_path(str(FIX / "thin_arm64"))
    app.detonate(sample, "apple", timeout=1.0)
    app.detonate(sample, "apple", timeout=1.0)
    clones = [c[2] for c in vm.calls if c[0] == "clone"]
    assert len(clones) == 2 and clones[0] != clones[1]
    assert all(c.startswith("ScratchingPost-") for c in clones)


def _ev(seq, et, pid, ppid, *, path="", responsible_pid=-1, payload=None):
    return Event(
        event_type=et,
        seq=seq,
        time=float(seq),
        pid=pid,
        ppid=ppid,
        process=ProcessInfo(pid=pid, ppid=ppid, path=path, responsible_pid=responsible_pid),
        payload=payload or {},
    )


def test_scope_events_to_subtree_keeps_sample_lineage_drops_system_noise():
    # The seam pushes the sample to /tmp/... but macOS symlinks /tmp -> /private/tmp,
    # so eslogger reports the sample's exec under /private/tmp. Scoping must normalize
    # that or it never finds the root and drops everything (the live-only trap).
    sample_guest = "/tmp/scratchingpost-RID/thin_arm64"
    events = [
        _ev(1, EventType.EXEC, 50, 1, path="/bin/bash"),                       # launcher shell: out
        _ev(2, EventType.EXEC, 100, 50, path="/private/tmp/scratchingpost-RID/thin_arm64"),  # sample: root
        _ev(3, EventType.FORK, 100, 50, payload={"child_pid": 200}),           # sample forks 200
        _ev(4, EventType.EXEC, 200, 100, path="/bin/sh"),                      # child of sample: in
        _ev(5, EventType.GET_TASK, 200, 100),                                  # child injects: in
        _ev(6, EventType.GET_TASK, 999, 1, responsible_pid=999),              # coreservicesd noise: OUT
        _ev(7, EventType.FILE_CREATE, 300, 1, responsible_pid=100,            # launchd helper the sample
             payload={"path": "/Users/x/Library/LaunchAgents/foo.plist"}),   # is responsible for: in
        _ev(8, EventType.FILE_CREATE, 888, 1, responsible_pid=888,           # unrelated system write: OUT
             payload={"path": "/var/db/foo"}),
    ]

    scoped, root_pid = scope_events_to_subtree(events, sample_guest)

    assert root_pid == 100
    kept = {e.seq for e in scoped}
    assert kept == {2, 3, 4, 5, 7}
    # The false positive the whole change targets — coreservicesd's legitimate
    # task_for_pid (rule 100001) — is gone; the sample's own get_task survives.
    assert 6 not in kept and 5 in kept


def test_scope_events_to_subtree_falls_back_when_sample_exec_absent():
    # If the sample's exec was dropped from the capture (boot-storm load), scoping
    # can't seed a root — it returns (empty, None) so the caller forwards the FULL
    # capture rather than an empty one (working-app fallback, not silent data loss).
    events = [_ev(1, EventType.GET_TASK, 999, 1, responsible_pid=999)]
    scoped, root_pid = scope_events_to_subtree(events, "/tmp/scratchingpost-RID/thin_arm64")
    assert root_pid is None and scoped == []


def test_per_profile_golden_map_selects_the_right_image(tmp_path):
    # A dispatch profile clones its own agent-baked golden while another profile
    # (and any profile absent from the map) falls back to the default golden.
    vm = FakeVm(ESLOGGER_FIX)
    app = LocalAppliance(
        live=True,
        vm=vm,
        golden_image="ScratchingPost",
        golden_images={"wazuh": "ScratchingPost-wazuh"},
        share_root=str(tmp_path / "runs"),
    )
    sample = Sample.from_path(str(FIX / "thin_arm64"))

    app.detonate(sample, "wazuh", timeout=1.0)
    app.detonate(sample, "apple", timeout=1.0)

    clones = [c for c in vm.calls if c[0] == "clone"]
    wazuh_clone, apple_clone = clones[0], clones[1]
    # wazuh -> mapped golden; apple -> fallback default. The per-run clone name
    # traces back to the profile's golden, not the default.
    assert wazuh_clone[1] == "ScratchingPost-wazuh"
    assert wazuh_clone[2].startswith("ScratchingPost-wazuh-")
    assert apple_clone[1] == "ScratchingPost"
    assert apple_clone[2].startswith("ScratchingPost-") and "wazuh" not in apple_clone[2]
