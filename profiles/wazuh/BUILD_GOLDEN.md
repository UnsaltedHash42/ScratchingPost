# Build the `wazuh` detonation golden — manual runbook (GUI session)

The last open Wazuh piece (ARCHITECTURE.md §6, Light model §3): install the Wazuh **agent**
into a detonation golden and confirm it survives a **full** clone and checks in to the manager.
This is interactive (agent install + a GUI boot), so it's a hands-on session. Everything
upstream — `LiveWazuhBackend`, the MITRE rules, conductor wiring — is already live-verified.

Values captured 2026-07-01 (re-check if the machine changed):
- Host LAN IP (agent → manager): **10.0.0.9** (Docker publishes `1514`/`1515` on `0.0.0.0`).
  This is a DHCP address — if it moved, get it again with `ipconfig getifaddr en0`. For a stable
  lab, reserve it or use the Parallels shared-network host address instead.
- Manager container: `single-node-wazuh.manager-1`. Agent pkg:
  `https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.6-1.arm64.pkg` (verified, ~7.6 MB).

## 0. Prereqs
```sh
# manager up?
docker compose -f ~/tools/wazuh-docker/single-node/docker-compose.yml ps   # or: (cd there && docker compose up -d)
curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health | grep -o '"status":"[a-z]*"'
# base golden stopped?
prlctl list -a          # ScratchingPost should be 'stopped'
```

## 1. Make the wazuh golden (full clone of the base — keep as a template)
```sh
prlctl clone ScratchingPost --name ScratchingPost-wazuh   # full clone; NO --linked
prlctl start ScratchingPost-wazuh
```
Watch the desktop come up (GUI session).

## 2. Inside the guest — verify reachability, then install the agent
Open Terminal in the guest:
```sh
# a) can the guest reach the host's manager? (enrollment port)
nc -vz 10.0.0.9 1515            # should connect. If not, the guest can't route to 10.0.0.9 —
                               #   find the Parallels host address: route -n get default | grep gateway
                               #   (host is usually .2 on that subnet, e.g. 10.211.55.2) and nc -vz <that> 1515
# b) install the agent pointed at the manager (macOS pkg reads /tmp/wazuh_envs)
curl -o /tmp/wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.6-1.arm64.pkg
echo "WAZUH_MANAGER='10.0.0.9'" | sudo tee /tmp/wazuh_envs
sudo installer -pkg /tmp/wazuh-agent.pkg -target /
sudo /Library/Ossec/bin/wazuh-control start
sudo /Library/Ossec/bin/wazuh-control status            # all processes running
grep '<address>' /Library/Ossec/etc/ossec.conf          # -> 10.0.0.9
```

## 3. Confirm it checks in (from the HOST terminal, wait ~30-60s)
```sh
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# expect a new agent (name = guest hostname) with status Active
```

## 4. The gate: does the agent survive a FULL clone?
```sh
prlctl stop ScratchingPost-wazuh
prlctl clone ScratchingPost-wazuh --name ScratchingPost-wazuh-run1
prlctl start ScratchingPost-wazuh-run1
# wait ~60s, then on the host:
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```
**Interpretation.** A full clone copies the guest filesystem including
`/Library/Ossec/etc/client.keys`, so the clone reports as the **same agent identity** (same
name/ID, new IP). That is EXPECTED and FINE here: detonations are serial (one clone at a time —
Apple's 2-VM cap, §4) and reverted, so identity reuse is a non-issue — alerts are correlated by
the detonation **time window** + agent name, which is exactly what `LiveWazuhBackend.alerts_since`
does. What you're verifying: the clone comes up **Active** (connects + keepalive) — i.e. a full
clone doesn't break enrollment. Active → **gate passed**.
(If you later want each clone to be a distinct agent — not needed for serial detonation — drop
`client.keys` from the golden and rely on authd auto-enrollment, or a first-boot enroll script.)

## 5. (Optional, ideal) End-to-end: detonate in the clone, see alerts land
Run a sample in `ScratchingPost-wazuh-run1`, then on the host:
```sh
curl -sk -u admin:SecretPassword 'https://localhost:9200/wazuh-alerts*/_search?size=5' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-10m"}}},"sort":[{"@timestamp":"desc"}]}' \
  | python3 -m json.tool | head -40
```
Or drive it through code: `LiveWazuhBackend` → `WazuhModule` → conductor (path already verified).

## 6. Cleanup — leave the lab clean
```sh
prlctl stop ScratchingPost-wazuh-run1 --kill && prlctl delete ScratchingPost-wazuh-run1
prlctl stop ScratchingPost-wazuh          # keep as the wazuh golden template, STOPPED
prlctl list -a                            # ScratchingPost + ScratchingPost-wazuh, both stopped, no run clones
# optional: remove test agents from the manager (interactive):
# docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/manage_agents
```

## Code follow-up (after the golden exists)
The `wazuh` profile must clone `ScratchingPost-wazuh`, not the `apple` golden. Today
`LocalAppliance.golden_image` is a single value — add a small **per-profile golden map** (e.g.
`{"apple": "ScratchingPost", "wazuh": "ScratchingPost-wazuh"}`) so `detonate(sample, "wazuh")`
clones the right image. Small, behind the existing seam; add a test alongside.
