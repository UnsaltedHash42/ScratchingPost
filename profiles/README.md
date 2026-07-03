# profiles

Golden-image build scripts, one per detonation profile (`apple`, `wazuh`, `vendor-*`).
Each image is built once with the ESF recorder installed and the SIP-off / entitlement
provisioning baked in. See `docs/ARCHITECTURE.md` §5-§7.

The VM layer is hypervisor-agnostic (a `VmProvider`, `orchestrator/detonation/vm.py`); these
scripts are the host-side build path for each supported hypervisor:

- `build_appliance_parallels.sh` — Parallels (`prlctl`), the reference lab hypervisor.
- `build_appliance.sh` — tart, second provider.
- `provision_guest.sh` — hypervisor-neutral in-guest provisioning (SIP check, sysext
  developer mode, eslogger smoke test); both build scripts run it inside the guest.

Two manual, non-scriptable steps gate every build: disabling SIP from recovery mode, and (on
Parallels) installing Parallels Tools so `prlctl exec` can reach the guest. Both scripts stop
with instructions rather than guessing.
