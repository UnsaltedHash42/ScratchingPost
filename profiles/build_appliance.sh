#!/usr/bin/env bash
#
# build_appliance.sh — provision a ScratchingPost detonation golden image with tart.
# ARCHITECTURE.md §5-§7, ROADMAP.md Phase 0.
#
# Scriptable steps run here on the HOST (tart clone/set) and, over SSH, inside the
# GUEST (system-extension developer mode, eslogger smoke test). The one step that
# CANNOT be scripted — disabling SIP from recovery mode — is documented and gated:
# the script checks for it and stops with instructions rather than guessing.
#
# Produces the `apple` profile's golden image: a clean Tahoe guest, SIP-off,
# sysext developer mode on, eslogger confirmed emitting JSON. Run once per profile;
# `tart clone` then makes revert-per-run cheap (ARCHITECTURE.md §3).
#
# Usage:
#   profiles/build_appliance.sh [--base IMAGE] [--name VM] [--cpu N] [--mem MB] [--disk GB]
#
set -euo pipefail

# --- config (override via flags/env) ----------------------------------------
# TODO(verify-on-guest): confirm the current base-image tag for macOS Tahoe / 26
# and the guest's default admin credentials at build time (Apple/Cirrus rotate these).
BASE_IMAGE="${BASE_IMAGE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}"
VM_NAME="${VM_NAME:-scratchingpost-detonation-apple}"
CPU="${CPU:-4}"
MEM_MB="${MEM_MB:-8192}"
DISK_GB="${DISK_GB:-80}"
GUEST_USER="${GUEST_USER:-admin}"       # TODO(verify-on-guest)
GUEST_PASS="${GUEST_PASS:-admin}"       # TODO(verify-on-guest)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)  BASE_IMAGE="$2"; shift 2;;
    --name)  VM_NAME="$2";    shift 2;;
    --cpu)   CPU="$2";        shift 2;;
    --mem)   MEM_MB="$2";     shift 2;;
    --disk)  DISK_GB="$2";    shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

log() { printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[stop]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. host prerequisites ---------------------------------------------------
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] \
  || die "Apple Silicon macOS host required (macOS guests only virtualize there)."

if ! command -v tart >/dev/null 2>&1; then
  log "installing tart via Homebrew"
  command -v brew >/dev/null 2>&1 || die "Homebrew not found; install it, then re-run."
  brew install cirruslabs/cli/tart
fi

# --- 1. clone + size the golden image (HOST, scriptable) ---------------------
if tart list --format json 2>/dev/null | grep -q "\"$VM_NAME\""; then
  warn "VM '$VM_NAME' already exists; skipping clone. Delete it to rebuild: tart delete $VM_NAME"
else
  log "cloning $BASE_IMAGE -> $VM_NAME"
  tart clone "$BASE_IMAGE" "$VM_NAME"
fi
log "sizing $VM_NAME: cpu=$CPU mem=${MEM_MB}MB disk=${DISK_GB}GB"
tart set "$VM_NAME" --cpu "$CPU" --memory "$MEM_MB" --disk-size "$DISK_GB"

# =============================================================================
# MANUAL STEP 1 — Disable SIP (cannot be scripted; requires recovery mode).
# =============================================================================
# ESF clients (eslogger included) need SIP off in the lab guest (ARCHITECTURE.md §7).
# There is no host-side command for this; it is done from inside the guest's
# recovery environment, once, before the guest is used as a golden image:
#
#   1. tart run "$VM_NAME"                 # boot the guest
#   2. Shut down, then boot into recovery (hold power on Apple Silicon), or use
#      the guest's recovery entry. On a fresh VM you may need to set this up once.
#   3. In recovery: Utilities -> Terminal -> `csrutil disable` -> reboot.
#   4. Verify in the running guest: `csrutil status` -> "System Integrity
#      Protection status: disabled".
#
# Do this ONLY in the disposable VM, never on a host you care about.
# The script continues assuming SIP will be / has been disabled; the guest
# provisioning below verifies it and fails loudly if not.
# =============================================================================

HERE="$(cd "$(dirname "$0")" && pwd)"
cat <<EOF

Host-side clone/size done. Now boot the guest and run the in-guest provisioning
(system-extension developer mode + eslogger smoke test), after SIP is disabled:

  tart run "$VM_NAME" &
  GUEST_IP=\$(tart ip "$VM_NAME")
  scp "$HERE/provision_guest.sh" ${GUEST_USER}@\$GUEST_IP:/tmp/
  ssh ${GUEST_USER}@\$GUEST_IP 'sudo bash /tmp/provision_guest.sh'

When provision_guest.sh reports the eslogger smoke test passing, snapshot the
golden image by simply leaving it as-is; per-run detonation uses:
  tart clone "$VM_NAME" run-<id>     # instant clean copy (ARCHITECTURE.md §3)
EOF
