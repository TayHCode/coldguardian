#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    exec unshare --mount --propagation private --net -- bash "$0" --isolated
fi
[[ $(ip -o link show | cut -d: -f2) == ' lo' && -z $(ip route show table all) ]]
repo=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d -p "$repo" overlay.XXXXXXXX)
peer=cg-overlay-$$
cleanup() {
    if [[ -n ${server:-} ]]; then
        kill "$server" 2>/dev/null || true
        wait "$server" 2>/dev/null || true
    fi
    ip netns delete "$peer" 2>/dev/null || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
ip netns add "$peer"
ip link add lab0 type veth peer name lab1 netns "$peer"
ip link set lo up
ip link set lab0 up
ip -n "$peer" link set lab1 up
ip addr add 10.77.0.1/30 dev lab0
ip -n "$peer" addr add 10.77.0.2/30 dev lab1
for range in 100.90.12.0/29 10.73.24.0/29 10.73.25.0/30; do
    ip route add "$range" dev lab0 src 10.77.0.1
done
for address in 100.90.12.{2,4,5,6} 10.73.24.{2,3,4} 10.73.25.2; do
    ip -n "$peer" addr add "$address/32" dev lab1
done
[[ -z $(ip route show default) && -z $(ip -n "$peer" route show default) ]]
cd "$scratch"
mkdir bin
cat > bin/tailscale <<'SH'
#!/bin/sh
test "$*" = 'status --json' && cat peers.json
SH
cat > bin/ip <<'SH'
#!/bin/sh
test "$*" = '-j addr' && cat interfaces.json
SH
cat > bin/nmap <<'PY'
#!/usr/bin/env python3
import json, subprocess, sys

args = sys.argv[1:]
targets = sys.stdin.buffer.read() if '-iL' in args else b''
with open('nmap.jsonl', 'a') as log:
    print(json.dumps([args, targets.decode()]), file=log)
raise SystemExit(subprocess.run(['/usr/bin/nmap', *args], input=targets).returncode)
PY
chmod +x bin/*
ip netns exec "$peer" python3 -m http.server 31337 --bind 0.0.0.0 >server.log 2>&1 &
server=$!
for attempt in {1..50}; do
    if curl --noproxy '*' --silent --fail --max-time 1 'http://10.77.0.2:31337/' >/dev/null; then
        break
    fi
    sleep 0.1
done
(( attempt < 50 ))
chown -R nobody "$scratch"
runuser -u nobody -- env -i PATH="$scratch/bin:/usr/bin:/bin" HOME="$scratch" PYTHONPATH="$repo" python3 - "$repo" <<'PY'
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

fixtures = Path(sys.argv[1]) / 'tests' / 'fixtures'
peers = json.loads((fixtures / 'tailscale-status.json').read_text())
peers['Peer']['nodekey:unapproved'] = {'TailscaleIPs': ['100.90.12.6']}
Path('peers.json').write_text(json.dumps(peers))
interfaces = json.loads((fixtures / 'ip-addr.json').read_text())
wireguard = next(interface for interface in interfaces if interface['ifname'] == 'wg0')
wireguard['addr_info'] = [dict(wireguard['addr_info'][0], local='10.73.24.1', prefixlen=29)]
Path('interfaces.json').write_text(json.dumps(interfaces))
Path('config.json').write_text(json.dumps(dict(
    deep_exclusions=[], lan_cidr='10.77.0.0/30', hosts={'scanner': '10.77.0.1'},
    tailscale_peers=['100.90.12.2', '100.90.12.3'], wireguard_subnets=['10.73.24.0/30', '10.73.25.0/30'],
    ports='31337', auth_paths=[], output_dir=str(Path('state').resolve()), ntfy=None,
)))
cli = [sys.executable, '-m', 'coldguardian.cli', '--config', 'config.json']
scan = subprocess.run([*cli, 'scan', '--deep', '--json'], capture_output=True, text=True, timeout=240)
report = json.loads(scan.stdout)
findings = report['findings']
visited = {f['ip'] for f in findings if f['category'] == 'service' and f['port'] == 31337}
missed = {f['ip'] for f in findings if f['check'] == 'host_offline'}
targets = set()
for line in Path('nmap.jsonl').read_text().splitlines():
    args, stdin = json.loads(line)
    specs = stdin.split() if stdin else args[args.index('-oX') + 2:]
    for spec in specs:
        if spec == '10.77.0.0/30':
            targets.update(map(str, ipaddress.ip_network(spec)))
        else:
            targets.add(spec)
    if '-sT' in args:
        assert args[args.index('-p') + 1] == '31337', args
allowed = {'10.77.0.0', '10.77.0.1', '10.77.0.2', '10.77.0.3',
           '100.90.12.2', '100.90.12.3', '10.73.24.1', '10.73.24.2'}
evidence = dict(visited=sorted(visited), missed=sorted(missed), unexpected_targets=sorted(targets - allowed))
print(json.dumps(evidence), flush=True)
assert evidence == dict(visited=['10.73.24.2', '10.77.0.2', '100.90.12.2'],
                        missed=['100.90.12.3'], unexpected_targets=[]), evidence
assert {'100.90.12.2', '100.90.12.3', '10.73.24.2'} <= targets
assert {f['check'] for f in findings if f['category'] == 'coverage'} == {
    'host_offline', 'wireguard_discovery',
}, findings
assert '100.90.12.3' in (Path('state') / 'latest.md').read_text()
PY
