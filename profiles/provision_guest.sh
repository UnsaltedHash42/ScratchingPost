#!/usr/bin/env bash
#
# provision_guest.sh — in-guest provisioning for a ScratchingPost golden image.
# Runs INSIDE the disposable macOS guest, as root (sudo). ARCHITECTURE.md §7.
#
# Scriptable guest steps: verify SIP is off, enable system-extension developer
# mode, and smoke-test that eslogger emits JSON. Disabling SIP itself is the one
# manual, recovery-mode step (see build_appliance.sh) — this script verifies it
# rather than attempting it.
#
set -euo pipefail

log() { printf '\033[1;36m[guest]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[stop]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "run this inside the macOS guest"
[[ "$(id -u)" == "0" ]] || die "run as root (sudo): ES clients must be privileged"

# --- 1. SIP must already be disabled (manual recovery-mode step) -------------
if csrutil status 2>/dev/null | grep -qi 'disabled'; then
  log "SIP is disabled — good."
else
  die "SIP is still enabled. Disable it from recovery ('csrutil disable'), reboot, re-run.
       See MANUAL STEP 1 in build_appliance.sh."
fi

# --- 2. system-extension developer mode (for the Phase 2 custom sysext) ------
# Harmless for the Phase 1 eslogger-only profile; bake it in so the image is
# ready for the custom ESF client without a rebuild.
log "enabling system-extension developer mode"
systemextensionsctl developer on || die "systemextensionsctl developer on failed"

# --- 3. eslogger smoke test --------------------------------------------------
# Phase 0 exit criterion: eslogger emits JSON. Capture a couple of seconds of
# exec events while generating a little activity, and confirm valid JSON lines.
# TODO(verify-on-guest): confirm eslogger event names via `eslogger --list-events`;
# the recorder's DEFAULT_EVENTS (sensors/eslogger/recorder.py) must match.
[[ -x /usr/bin/eslogger ]] || die "/usr/bin/eslogger missing (unexpected on a stock macOS guest)"

SMOKE=/tmp/eslogger_smoke.jsonl
log "running eslogger exec smoke test (~3s)"
( /usr/bin/eslogger exec > "$SMOKE" 2>/dev/null & ESL_PID=$!
  sleep 1; /bin/ls >/dev/null; /usr/bin/true; sleep 2
  kill "$ESL_PID" 2>/dev/null || true ) || true

LINES=$(wc -l < "$SMOKE" | tr -d ' ')
[[ "$LINES" -gt 0 ]] || die "eslogger produced no output; check SIP + root + entitlement provisioning"
if command -v python3 >/dev/null 2>&1; then
  head -n1 "$SMOKE" | python3 -c 'import sys,json; json.loads(sys.stdin.readline()); print("first line is valid JSON")' \
    || die "eslogger output is not valid JSON"
fi
log "eslogger smoke test passed ($LINES event lines captured)"
log "golden image provisioning complete."
