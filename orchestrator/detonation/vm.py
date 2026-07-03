"""Hypervisor-agnostic VM providers behind the detonation seam (ARCHITECTURE.md §5, §8).

The detonation seam (`detonation/api.py`) must never shell out to a specific
hypervisor. It drives a `VmProvider`: clone (snapshot-cheap), boot/suspend, share a
host directory in, exec inside the guest, read the guest IP, revert to clean, and
delete. Parallels (`prlctl`) is the first provider because that is the reference
lab; tart is kept as a second so the existing `profiles/*.sh` path still has a home.
A new hypervisor (UTM, raw Virtualization.framework) is a new `VmProvider`
implementation, not an edit to the orchestrator.

Every provider goes through an injected `CommandRunner`, so command construction is
unit-testable on any host with canned output and the live subprocess path is only
touched when a real runner runs — the same boundary pattern as
`code_identity.Runner`.

The providers wrap different tools with genuinely different models. Parallels has a
guest-exec agent (`prlctl exec`, needs Parallels Tools) and persistent shared
folders; tart has neither (guest access is over SSH, sharing is a `tart run` flag,
and `tart run` is a long-lived process, not a one-shot command). Where tart's model
does not fit a synchronous runner, `TartProvider` raises `VmError` with the reason
rather than pretending — that divergence is exactly what the abstraction exists to
absorb. `ParallelsProvider` is the complete one.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Callable, Protocol, Sequence, runtime_checkable

# CommandRunner(argv) -> (returncode, stdout, stderr). Injected in tests; the live
# default shells out. Never invoked at import time.
CommandRunner = Callable[[Sequence[str]], "tuple[int, str, str]"]


class VmError(RuntimeError):
    """A VM control command failed, or the provider is not runnable on this host."""


def subprocess_runner(argv: Sequence[str]) -> tuple[int, str, str]:
    """Default live CommandRunner."""
    p = subprocess.run(list(argv), capture_output=True, text=True, check=False)
    return p.returncode, p.stdout, p.stderr


@runtime_checkable
class VmProvider(Protocol):
    """The narrow VM-control surface the detonation seam depends on.

    Names are host-side VM identifiers (a name or UUID the tool understands).
    `clone` is the snapshot primitive: a fresh, test-ready copy of a golden image.
    `revert` restores a per-run VM to clean; the cheap-and-uniform implementation is
    delete + re-clone the golden (ARCHITECTURE.md §3), which every hypervisor can do.
    """

    name: str

    def available(self) -> bool: ...
    def clone(self, base: str, target: str) -> None: ...
    def boot(self, vm: str) -> None: ...
    def suspend(self, vm: str) -> None: ...
    def share_dir(self, vm: str, host_dir: str, mount_name: str) -> None: ...
    def exec(self, vm: str, argv: Sequence[str]) -> tuple[int, str, str]: ...
    def ip(self, vm: str) -> str | None: ...
    def revert(self, vm: str, base: str) -> None: ...
    def delete(self, vm: str) -> None: ...


class _CliProvider:
    """Shared plumbing for a CLI-backed provider (runner, availability, `_run`)."""

    name = "cli"
    binary = ""

    def __init__(self, runner: CommandRunner | None = None, binary: str | None = None) -> None:
        self._runner = runner
        if binary is not None:
            self.binary = binary

    def available(self) -> bool:
        # A real runner (tests) is always "available"; the live path needs the CLI.
        if self._runner is not None:
            return True
        return (
            platform.system() == "Darwin"
            and platform.machine() == "arm64"
            and shutil.which(self.binary) is not None
        )

    def _run(self, argv: Sequence[str], *, check: bool = True) -> tuple[int, str, str]:
        runner = self._runner or subprocess_runner
        rc, out, err = runner(argv)
        if check and rc != 0:
            raise VmError(f"{' '.join(argv)} failed (rc={rc}): {err.strip() or out.strip()}")
        return rc, out, err


class ParallelsProvider(_CliProvider):
    """Parallels Desktop provider (`prlctl`). The reference lab hypervisor.

    `clone` is a full clone, not `--linked`. On an Apple-silicon macOS guest
    (`.macvm`) a linked clone regenerates the guest machine identity, which breaks
    the Parallels Tools handshake — the clone boots but `prlctl exec` never connects
    (`GuestTools` stays `not_installed`) and the whole detonation channel is dead
    (verified macOS 26.5.2 / Parallels 26.4). A full clone keeps the handshake and is
    still cheap: Parallels backs it with APFS copy-on-write, so a 50 GB golden clones
    in ~3 s, which is what keeps revert-per-run affordable (ARCHITECTURE.md §3). Guest
    exec and IP require Parallels Tools in the guest (`GuestTools: state=installed`);
    without it `prlctl exec` fails and the provider surfaces that as a `VmError`.
    """

    name = "parallels"
    binary = "prlctl"

    def clone(self, base: str, target: str) -> None:
        # The base must be powered off to clone (Parallels refuses "the VM is busy"
        # otherwise). The golden is a template kept stopped; this graceful stop is a
        # safety net for a golden left running and a no-op (ignored) when it is
        # already stopped. Not `--kill`, to avoid leaving the golden disk dirty.
        self._run([self.binary, "stop", base], check=False)
        self._run([self.binary, "clone", base, "--name", target])

    def boot(self, vm: str) -> None:
        self._run([self.binary, "start", vm])

    def suspend(self, vm: str) -> None:
        self._run([self.binary, "suspend", vm])

    def share_dir(self, vm: str, host_dir: str, mount_name: str) -> None:
        # This is the correct prlctl call for Windows/Linux guests. NOTE (verified on
        # macOS 26.5.2): Parallels shared folders do NOT mount inside a **macOS**
        # guest — the command succeeds but nothing appears under /Volumes. For a
        # macOS detonation guest the results-out channel is `exec` instead (write in
        # the guest, `cat` back); see LocalAppliance._detonate_live.
        self._run([
            self.binary, "set", vm,
            "--shf-host-add", mount_name, "--path", host_dir, "--mode", "rw",
        ])

    def exec(self, vm: str, argv: Sequence[str]) -> tuple[int, str, str]:
        # prlctl has no `--` separator; the command follows the VM name directly.
        return self._run([self.binary, "exec", vm, *argv], check=False)

    def ip(self, vm: str) -> str | None:
        # Ask the guest directly; needs Parallels Tools. en0 is the primary
        # interface on a stock macOS guest (verified on macOS 26.5.2).
        rc, out, _err = self.exec(vm, ["ipconfig", "getifaddr", "en0"])
        ip = out.strip()
        return ip if rc == 0 and ip else None

    def revert(self, vm: str, base: str) -> None:
        # Uniform revert: drop the per-run clone and re-clone the golden back to
        # clean. Parallels also has native snapshots (prlctl snapshot-switch); the
        # delete+clone path keeps revert identical across providers and matches the
        # "clone back to golden" model.
        self.delete(vm)
        self.clone(base, vm)

    def delete(self, vm: str) -> None:
        # Stop first (a running VM refuses deletion); ignore stop failures (already
        # stopped), fail loudly only on the delete itself.
        self._run([self.binary, "stop", vm, "--kill"], check=False)
        self._run([self.binary, "delete", vm])


class TartProvider(_CliProvider):
    """tart provider (Cirrus Labs). Second provider, for parity with the existing
    `profiles/*.sh` build path.

    tart's model differs from Parallels in ways the synchronous runner cannot hide:
    `tart run` is a long-lived foreground process (not a one-shot boot command), tart
    has no guest-exec (you reach the guest over SSH), and directory sharing is a
    `tart run --dir` flag rather than persistent VM state. Those methods raise
    `VmError` explaining the divergence; `clone`/`delete`/`suspend`/`ip` map cleanly.
    """

    name = "tart"
    binary = "tart"

    def clone(self, base: str, target: str) -> None:
        self._run([self.binary, "clone", base, target])

    def boot(self, vm: str) -> None:
        raise VmError(
            "tart boot is a long-lived `tart run` process, not a one-shot command; "
            "the appliance manages that process directly (see profiles/build_appliance.sh)"
        )

    def suspend(self, vm: str) -> None:
        self._run([self.binary, "suspend", vm])

    def share_dir(self, vm: str, host_dir: str, mount_name: str) -> None:
        raise VmError(
            "tart shares directories via a `tart run --dir` flag at boot, not as "
            "persistent VM state; pass the share when launching the run process"
        )

    def exec(self, vm: str, argv: Sequence[str]) -> tuple[int, str, str]:
        raise VmError("tart has no guest-exec; reach the guest over SSH (tart ip + ssh)")

    def ip(self, vm: str) -> str | None:
        rc, out, _err = self._run([self.binary, "ip", vm], check=False)
        ip = out.strip()
        return ip if rc == 0 and ip else None

    def revert(self, vm: str, base: str) -> None:
        self.delete(vm)
        self.clone(base, vm)

    def delete(self, vm: str) -> None:
        self._run([self.binary, "delete", vm])


_PROVIDERS: dict[str, type[_CliProvider]] = {
    "parallels": ParallelsProvider,
    "tart": TartProvider,
}


def get_provider(name: str, runner: CommandRunner | None = None) -> VmProvider:
    """Construct a provider by name (`parallels` | `tart`). Keeps the orchestrator
    from importing a concrete provider class."""
    try:
        cls = _PROVIDERS[name]
    except KeyError:
        raise VmError(f"unknown VM provider: {name!r} (have {sorted(_PROVIDERS)})") from None
    return cls(runner=runner)  # type: ignore[return-value]
