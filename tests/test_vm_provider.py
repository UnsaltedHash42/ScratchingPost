"""VmProvider abstraction (orchestrator/detonation/vm.py).

Command construction is tested through an injected CommandRunner that records
argv and returns canned output — no prlctl/tart, runs on any host."""

import pytest

from orchestrator.detonation.vm import (
    ParallelsProvider,
    TartProvider,
    VmError,
    VmProvider,
    get_provider,
)


class RecordingRunner:
    """Records argv and replays a queue of (rc, out, err) results (default 0/"" )."""

    def __init__(self, results=None):
        self.calls: list[list[str]] = []
        self._results = list(results or [])

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self._results.pop(0) if self._results else (0, "", "")


def test_providers_satisfy_protocol():
    assert isinstance(ParallelsProvider(runner=RecordingRunner()), VmProvider)
    assert isinstance(TartProvider(runner=RecordingRunner()), VmProvider)


def test_parallels_clone_is_full_from_stopped_base():
    r = RecordingRunner()
    ParallelsProvider(runner=r).clone("golden", "run-1")
    # Base is stopped first (a running base refuses cloning); the clone is full, not
    # `--linked` — a linked clone regenerates the macvm guest's machine identity and
    # breaks the Parallels Tools handshake so `prlctl exec` never connects.
    assert r.calls == [
        ["prlctl", "stop", "golden"],
        ["prlctl", "clone", "golden", "--name", "run-1"],
    ]


def test_parallels_exec_has_no_dash_separator():
    # prlctl exec rejects `--`; the command follows the VM name directly.
    r = RecordingRunner([(0, "hi\n", "")])
    rc, out, _err = ParallelsProvider(runner=r).exec("run-1", ["echo", "hi"])
    assert rc == 0 and out == "hi\n"
    assert r.calls == [["prlctl", "exec", "run-1", "echo", "hi"]]


def test_parallels_ip_reads_guest_interface():
    r = RecordingRunner([(0, "10.211.55.7\n", "")])
    assert ParallelsProvider(runner=r).ip("run-1") == "10.211.55.7"
    r2 = RecordingRunner([(1, "", "not running")])
    assert ParallelsProvider(runner=r2).ip("run-1") is None


def test_parallels_revert_deletes_then_reclones():
    r = RecordingRunner()
    ParallelsProvider(runner=r).revert("run-1", "golden")
    # stop --kill (best effort) + delete the run clone, then re-clone the golden back
    # to clean (which stops the golden first, then full-clones it).
    assert r.calls == [
        ["prlctl", "stop", "run-1", "--kill"],
        ["prlctl", "delete", "run-1"],
        ["prlctl", "stop", "golden"],
        ["prlctl", "clone", "golden", "--name", "run-1"],
    ]


def test_parallels_share_dir_persistent_folder():
    r = RecordingRunner()
    ParallelsProvider(runner=r).share_dir("run-1", "/host/out", "sppost")
    assert r.calls == [[
        "prlctl", "set", "run-1",
        "--shf-host-add", "sppost", "--path", "/host/out", "--mode", "rw",
    ]]


def test_nonzero_rc_raises_vmerror():
    # First result feeds the (best-effort, ignored) stop; the clone itself fails.
    r = RecordingRunner([(0, "", ""), (1, "", "boom")])
    with pytest.raises(VmError, match="boom"):
        ParallelsProvider(runner=r).clone("golden", "run-1")


def test_tart_clone_and_ip():
    r = RecordingRunner([(0, "", ""), (0, "192.168.64.5\n", "")])
    t = TartProvider(runner=r)
    t.clone("base", "run-1")
    assert t.ip("run-1") == "192.168.64.5"
    assert r.calls[0] == ["tart", "clone", "base", "run-1"]
    assert r.calls[1] == ["tart", "ip", "run-1"]


def test_tart_boot_and_exec_diverge_loudly():
    # tart's model (long-lived `tart run`, SSH-only guest access) doesn't fit the
    # synchronous runner; the provider says so rather than pretending.
    t = TartProvider(runner=RecordingRunner())
    with pytest.raises(VmError, match="long-lived"):
        t.boot("run-1")
    with pytest.raises(VmError, match="no guest-exec"):
        t.exec("run-1", ["echo"])
    with pytest.raises(VmError, match="tart run --dir"):
        t.share_dir("run-1", "/host", "sppost")


def test_get_provider_by_name():
    assert isinstance(get_provider("parallels", runner=RecordingRunner()), ParallelsProvider)
    assert isinstance(get_provider("tart", runner=RecordingRunner()), TartProvider)
    with pytest.raises(VmError, match="unknown VM provider"):
        get_provider("virtualbox")
