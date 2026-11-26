#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    repo=$(cd "$(dirname "$0")/.." && pwd)
    exec sudo --preserve-env=LAB_WHEELHOUSE unshare --mount --propagation private --net -- bash "$0" --isolated "$repo" "$(id -un)"
fi
repo=$2
lab_user=$3
[[ $(ip -o link show | cut -d: -f2) == ' lo' && -z $(ip route show table all) ]]
[[ $lab_user != root ]]
mkdir -p "$repo/state"
scratch=$(mktemp -d -p "$repo" state/lab.XXXXXXXX)
peer=cg-peer-$$
pids=()
cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    ip netns delete "$peer"
    rm -rf -- "$scratch"
}
trap cleanup EXIT

if [[ ! -d /run/netns ]]; then
    mkdir /run/netns
fi
mount -t tmpfs tmpfs /run/netns
ip netns add "$peer"
ip link add lab0 type veth peer name lab1 netns "$peer"
ip link set lo up
ip link set lab0 up
ip addr add 10.77.0.1/24 dev lab0
ip -n "$peer" link set lo up
ip -n "$peer" link set lab1 up
for i in {2..30}; do ip -n "$peer" addr add "10.77.0.$i/24" dev lab1; done
ip -n "$peer" addr add 100.64.0.2/32 dev lab1
ip route add 100.64.0.2/32 dev lab0 src 10.77.0.1
[[ -z $(ip route show default) && -z $(ip -n "$peer" route show default) ]]

chown "$lab_user" "$scratch"
cd "$scratch"
mkdir -p site/v1 baseline-site
printf '%s\n' '{"object":"list","data":[{"id":"lab-model","object":"model"}]}' > site/v1/models
printf '%s\n' 'listen-http: "127.0.0.1:2586"' 'cache-file: "ntfy.db"' > ntfy.yml
ntfy serve --config ntfy.yml > ntfy.log 2>&1 &
pids+=("$!")
ip netns exec "$peer" python3 -m http.server 80 --bind 10.77.0.2 --directory baseline-site > http.log 2>&1 &
pids+=("$!")

cat > model.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Model(BaseHTTPRequestHandler):
    def do_POST(self):
        print('model POST received', flush=True)
        assert self.path == '/v1/chat/completions'
        request = json.loads(
            self.rfile.read(int(self.headers['Content-Length']))
        )
        evidence = json.loads(request['messages'][1]['content'])['untrusted_evidence']
        explanation = dict(label='benign', reason='Synthetic benign verdict.',
                           evidence_ids=list(evidence), missing=[])
        message = dict(role='assistant', content=json.dumps(explanation))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(dict(choices=[dict(message=message, finish_reason='stop')])).encode())

HTTPServer(('127.0.0.1', 2587), Model).serve_forever()
PY
python3 model.py > model.log 2>&1 &
pids+=("$!")

cat > journey.py <<'PY'
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

repo = Path(sys.argv[1])
phase = sys.argv[2]
home = Path.home()
config = home / '.config/coldguardian/config.json'
state = home / '.local/state/coldguardian'
ntfy = dict(server='http://127.0.0.1:2586', topic='cg-lab-test')
sink = ntfy['server'] + '/' + ntfy['topic'] + '/json?poll=1&since=all'

def run(*command, expected=0, answers=None):
    result = subprocess.run(command, text=True, input=answers, capture_output=True, timeout=480)
    if result.returncode != expected:
        raise RuntimeError(f'{command[-3:]}: expected {expected}, got {result.returncode}\n'
                           f'{result.stdout}\n{result.stderr}')
    return result.stdout

def pages():
    with urlopen(sink, timeout=5) as response:
        return [item['message'] for line in response if (item := json.loads(line)).get('priority') == 4]

def model_calls():
    return Path('model.log').read_text().splitlines().count('model POST received')

def scan(profile, expected):
    probe = """
import json, resource, runpy, sys, time
start = time.monotonic()
try:
    runpy.run_path(sys.argv.pop(1), run_name='__main__')
finally:
    print(json.dumps(dict(elapsed_s=round(time.monotonic()-start, 3),
                          scanner_peak_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                          nmap_child_wait_peak_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)))
"""
    output = run(str(cli.parent.parent / 'venvs/coldguardian/bin/python'), '-c', probe, str(cli),
                 'scan', '--' + profile, '--json', expected=expected)
    report, metrics = map(json.loads, output.splitlines())
    assert report['profile'] == profile and report['exit_code'] == expected
    timestamp = datetime.strptime(report['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
    stamp = timestamp.strftime('%Y%m%dT%H%M%S.%fZ')
    for index, item in enumerate(report['findings'], start=1):
        assert item['evidence_id'] == f'E{index}', item
        assert item['finding_id'] == f'{stamp}:E{index}', item
    peak = report.get('scanner_peak_rss_kib')
    assert type(peak) is int and 0 < peak <= metrics['scanner_peak_kib'], (profile, peak, metrics)
    assert f'Scanner peak RSS: {peak} KiB' in (state / 'latest.md').read_text().splitlines()
    metrics['report_peak_rss_kib'] = peak
    return report['findings'], metrics

def save(settings):
    config.write_text(json.dumps(settings))

def seed():
    run(str(cli), 'scan', '--quick', '--json', expected=2)
    run(str(cli), '--approve-baseline')

cli = home / 'pipx/bin/coldguardian'
if phase == 'quick':
    for attempt in range(50):
        try:
            assert pages() == []
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError('Isolated ntfy did not start')
    setup = run('bash', '-ec', 'cd "$1" && pipx install . && "$PIPX_BIN_DIR/coldguardian" setup',
                'lab-setup', str(repo), answers='y\nmedium\nnone\nhttp://127.0.0.1:2586 cg-lab-test\ny\n')
    assert 'LAN: 10.77.0.0/24' in setup
    prompts = ('Approve this scope?', 'Level (low, medium, high)', 'Local model URL',
               'ntfy server URL and topic', 'Approve this scan as the baseline?')
    assert all(setup.count(prompt) == 1 for prompt in prompts)
    assert (state / 'baseline.json').is_file() and list(state.glob('*.md'))
    assert pages() == []
    print(json.dumps(dict(setup_questions=len(prompts), setup_report=True)), flush=True)
    settings = json.loads(config.read_text())
    settings.pop('tailscale_peers', None)
    settings.update(ntfy=None, auth_paths=[], ports='80',
                    hosts=dict(scanner='10.77.0.1', **{f'lab-{i}': f'10.77.0.{i}' for i in range(2, 31)}))
    save(settings)
    seed()
    findings, metrics = scan('quick', 0)
    assert findings[0]['host_count'] == 30 and findings[0]['network_complete']
    assert json.loads((state / 'baseline.json').read_text())['hosts']['10.77.0.2'] == [80]
    assert not any(f['category'] == 'coverage' for f in findings)
    assert metrics['elapsed_s'] <= 60 and metrics['scanner_peak_kib'] * 1024 < 150_000_000
    print(json.dumps(dict(quick=metrics, inventoried_addresses=30, baseline_ports=[80])), flush=True)
elif phase == 'seed':
    settings = json.loads(config.read_text())
    Path('dns.log').write_text('')
    settings.update(ports='1-65535',
                    hosts=dict(scanner='10.77.0.1', lan='10.77.0.2', offline='10.77.0.31',
                               peer='100.64.0.2'),
                    dns_paths=[str(Path('dns.log').resolve())],
                    feed=dict(path=str(repo / 'tests/fixtures/feeds/tweetfeed.csv')))
    save(settings)
    run(str(cli), 'feeds', 'update', '--config', str(config))
    seed()
elif phase == 'deep':
    settings = json.loads(config.read_text())
    original = (state / 'state.json').read_bytes()
    baseline = (state / 'baseline.json').read_bytes()
    results = []
    finding_ids = []
    assert model_calls() == 0
    for model_url in ('http://127.0.0.1:2587', None):
        (state / 'state.json').write_bytes(original)
        settings.update(ntfy=ntfy, model_url=model_url)
        save(settings)
        calls_before_scan = model_calls()
        findings, metrics = scan('deep', 1)
        scan_model_calls = model_calls() - calls_before_scan
        assert scan_model_calls == 0, scan_model_calls
        risks = [f for f in findings if f['category'] == 'risky_service']
        assert {(f['ip'], f['port'], f['rule']) for f in risks} == {
            ('10.77.0.2', 31337, 'model-server'), ('100.64.0.2', 31337, 'model-server'),
        }, findings
        dns, = [f for f in findings if f['category'] == 'dns_feed_match']
        assert dns['count'] == 1
        assert [f.get('component') for f in findings if f['category'] == 'coverage'] == ['host_offline']
        assert any(f.get('host') == 'offline' and f.get('component') == 'host_offline' for f in findings)
        assert {(f['ip'], f['port']) for f in findings if f['category'] == 'service'} >= {
            ('10.77.0.2', 80), ('10.77.0.2', 31337), ('100.64.0.2', 31337),
        }
        report = (state / 'latest.md').read_text()
        for risk in risks:
            assert f"[model-server, {risk['evidence_id']}]" in report, risk
        assert 'Model label:' not in report
        assert 'Local model unavailable' not in report
        observed_pages = pages()
        assert len(observed_pages) == len(results) + 1
        assert all(item in observed_pages[-1] for item in (
            'DNS queries matched the local feed', '10.77.0.2:31337 (model-server)', '100.64.0.2:31337 (model-server)',
        )), observed_pages[-1]
        assert 'bad-dns.example' not in observed_pages[-1].lower()
        selected = risks[0]
        if model_url:
            result = json.loads(run(str(cli), 'explain', selected['finding_id'], '--json', expected=1))
            assert result == dict(command='explain', status='bad', exit_code=1,
                                  finding_id=selected['finding_id'],
                                  explanation=dict(label='benign', reason='Synthetic benign verdict.',
                                                   evidence_ids=[selected['evidence_id']], missing=[])), result
            assert model_calls() == 1
            assert pages() == observed_pages
            assert (state / 'latest.md').read_text() == report
            print(json.dumps(dict(explicit_model_calls=model_calls(), explained_finding_id=result['finding_id'],
                                  explanation=result['explanation'])), flush=True)
        finding_ids.append({f['finding_id'] for f in findings})
        stable_findings = [{k: v for k, v in f.items() if k != 'finding_id'} for f in findings]
        results.append((stable_findings, observed_pages[-1]))
        print(json.dumps(dict(mode='model_configured' if model_url else 'no_model',
                              scan_model_calls=scan_model_calls, risk_finding_id=selected['finding_id'],
                              metrics=metrics, risky_services=len(risks), feed_queries=dns['count'],
                              offline_hosts=1, isolated_pages=1)), flush=True)
    assert results[0] == results[1]
    assert finding_ids[0].isdisjoint(finding_ids[1]), finding_ids
    assert (state / 'baseline.json').read_bytes() == baseline
    run(str(cli), 'uninstall')
    run('pipx', 'uninstall', 'coldguardian')
    assert not any(path.exists() for path in (config.parent, state, cli, home / 'pipx/venvs/coldguardian'))
    assert not list(home.glob('.config/systemd/user/coldguardian-*'))
    print(json.dumps(dict(identical_finding_content_and_pages=True, distinct_finding_ids=True, uninstall=True)))
PY

lab() {
    runuser -u "$lab_user" -- env -i PATH=/usr/sbin:/usr/bin:/bin HOME="$scratch" \
        PIPX_HOME="$scratch/pipx" PIPX_BIN_DIR="$scratch/pipx/bin" PIP_NO_INDEX=1 \
        PIP_FIND_LINKS="${LAB_WHEELHOUSE:?Set LAB_WHEELHOUSE to an offline setuptools wheel directory}" \
        PIPX_DISABLE_SHARED_LIBS_AUTO_UPGRADE=1 python3 "$scratch/journey.py" "$repo" "$1"
}

ip -Version
nmap --version | head -2
nproc
cat /proc/loadavg
lab quick
for i in {3..30}; do ip -n "$peer" addr del "10.77.0.$i/24" dev lab1; done
lab seed

for address in 10.77.0.2 100.64.0.2; do
    ip netns exec "$peer" python3 -m http.server 31337 --bind "$address" --directory site > "http-$address.log" 2>&1 &
    pids+=("$!")
    for attempt in {1..50}; do
        if curl --noproxy '*' --silent --fail --max-time 1 "http://$address:31337/v1/models" >/dev/null; then
            break
        fi
        sleep 0.1
    done
    (( attempt < 50 ))
done
printf '%s\n' 'Jan  1 00:00:00 dnsmasq[1234]: query[A] bad-dns.example from 10.77.0.2' > dns.log

snapshot() {
    ip -j addr
    ip -j route show table all
    ip -n "$peer" -j addr
    ip -n "$peer" -j route show table all
    sha256sum dns.log site/v1/models
}
snapshot > before
lab deep
snapshot | diff - before
cd "$repo"
cleanup
trap - EXIT
[[ ! -e /run/netns/$peer && ! -e $scratch && $(ip -o link show | wc -l) == 1 ]]
printf '%s\n' '{"network_and_fixtures_unchanged":true,"lab_processes_and_namespace_removed":true}'
