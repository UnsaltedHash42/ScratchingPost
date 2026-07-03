#!/bin/sh
# Build the self-acting behavior demo samples (adhoc-signed arm64 Mach-O).
# These prove ScratchingPost catches malicious *behavior* on a live detonation,
# not just that an unsigned binary ran. Run on an Apple-Silicon macOS host with
# the Xcode command-line tools.
set -eu
cd "$(dirname "$0")"

build() {
  name="$1"
  entitlements="${2:-}"
  clang -arch arm64 -O2 -o "$name" "$name.c"
  if [ -n "$entitlements" ]; then
    codesign -s - --entitlements "$entitlements" "$name"   # adhoc + entitlements
  else
    codesign -s - "$name"                                  # adhoc signature
  fi
  echo "built + adhoc-signed: $name"
}

build persist_launchagent

# inject_taskport signs itself with get-task-allow so task_for_pid on its own
# forked child succeeds even off the SIP-disabled guest (belt-and-suspenders;
# the guest runs it as root with SIP off, where it is unrestricted anyway).
cat > get-task-allow.entitlements <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.get-task-allow</key><true/>
</dict></plist>
EOF
build inject_taskport get-task-allow.entitlements
rm -f get-task-allow.entitlements   # transient; the heredoc above is the source of truth
