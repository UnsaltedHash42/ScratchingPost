#!/usr/bin/env bash
#
# build_appliance_parallels.sh — provision a ScratchingPost detonation golden image
# with Parallels (prlctl). Parallels counterpart to build_appliance.sh (tart).
# ARCHITECTURE.md §5-§7, ROADMAP.md Phase 0.
#
# Scriptable steps run here on the HOST (prlctl clone/set/exec). The two steps that
# CANNOT be scripted — disabling SIP from recovery mode, and installing Parallels
# Tools (a guest GUI action, required before `prlctl exec` works) — are documented
# and gated: the script checks for them and stops with instructions rather than
# guessing.
#
# Produces the `apple` profile's golden image: a clean Tahoe guest, SIP-off,
# Parallels Tools + sysext developer mode on, eslogger confirmed emitting JSON. Run
# once per profile; a linked `prlctl clone` then makes revert-per-run cheap.
#
# Usage:
#   profiles/build_appliance_parallels.sh --base BASE_VM [--name VM] [--cpu N] [--mem MB]
#
set -euo pipefail

# --- config (override via flags/env) ----------------------------------------
# TODO(verify-on-guest): confirm the base VM name and the guest's default admin
# credentials at build time.
BASE_VM="${BASE_VM:-macos-tahoe-base}"
VM_NAME="${VM_NAME:-ScratchingPost}"   # golden image; per-run clones are <VM_NAME>-<uuid>
CPU="${CPU:-4}"
MEM_MB="${MEM_MB:-8192}"
GUEST_USER="${GUEST_USER:-admin}"       # TODO(verify-on-guest)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)  BASE_VM="$2";  shift 2;;
    --name)  VM_NAME="$2";  shift 2;;
    --cpu)   CPU="$2";      shift 2;;
    --mem)   MEM_MB="$2";   shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

log()  { printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[stop]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. host prerequisites ---------------------------------------------------
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] \
  || die "Apple Silicon macOS host required (macOS guests only virtualize there)."
command -v prlctl >/dev/null 2>&1 \
  || die "prlctl not found; install Parallels Desktop, then re-run."

# --- 1. linked clone + size the golden image (HOST, scriptable) --------------
if prlctl list -a --info 2>/dev/null | grep -q "Name: $VM_NAME$"; then
  warn "VM '$VM_NAME' already exists; skipping clone. Delete to rebuild: prlctl delete $VM_NAME"
else
  log "linked-cloning $BASE_VM -> $VM_NAME (instant, space-cheap; ARCHITECTURE.md §5)"
  prlctl clone "$BASE_VM" --name "$VM_NAME" --linked
fi
log "sizing $VM_NAME: cpu=$CPU mem=${MEM_MB}MB"
prlctl set "$VM_NAME" --cpu "$CPU" --memory "$MEM_MB"

# =============================================================================
# MANUAL STEP 1 — Disable SIP (cannot be scripted; requires recovery mode).
# =============================================================================
# ESF clients (eslogger included) need SIP off in the lab guest (ARCHITECTURE.md §7).
# There is no host-side command; do it once from the guest's recovery environment:
#   1. prlctl start "$VM_NAME"
#   2. Boot the guest into macOS recovery.
#   3. In recovery: Utilities -> Terminal -> `csrutil disable` -> reboot.
#   4. Verify in the running guest: `csrutil status` -> "... disabled".
# Do this ONLY in the disposable VM, never on a host you care about.
#
# MANUAL STEP 2 — Install Parallels Tools (guest GUI action).
# =============================================================================
# `prlctl exec` needs Parallels Tools in the guest (GuestTools: state=installed).
# In the running guest: Parallels menu -> "Install Parallels Tools", run the
# installer, reboot. Until then the provisioning exec below cannot reach the guest.
# =============================================================================

HERE="$(cd "$(dirname "$0")" && pwd)"

# --- 2. gate on Parallels Tools before attempting guest exec -----------------
if ! prlctl exec "$VM_NAME" true >/dev/null 2>&1; then
  cat <<EOF

Host-side clone/size done, but the guest is not reachable via 'prlctl exec' yet.
Complete MANUAL STEP 1 (SIP off) and MANUAL STEP 2 (Parallels Tools), then re-run
this script to finish provisioning — or run it by hand:

  # share provision_guest.sh into the guest and run it as root
  prlctl set "$VM_NAME" --shf-host-add sppost --path "$HERE" --mode rw
  prlctl exec "$VM_NAME" -- sudo bash "/Volumes/sppost/provision_guest.sh"

When provision_guest.sh reports the eslogger smoke test passing, the golden image
is ready; per-run detonation clones it to "$VM_NAME"-<uuid> (see LocalAppliance).
EOF
  exit 0
fi

# --- 3. in-guest provisioning over prlctl exec (Tools present) ---------------
log "guest reachable; running in-guest provisioning (SIP check + sysext dev mode + eslogger smoke test)"
prlctl set "$VM_NAME" --shf-host-add sppost --path "$HERE" --mode rw
# TODO(verify-on-guest): confirm the shared-folder mount point on the Tahoe guest.
prlctl exec "$VM_NAME" -- sudo bash "/Volumes/sppost/provision_guest.sh"
log "golden image provisioning complete."
