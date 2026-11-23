"""Read-only observations on the Linux machine running the scan."""
import fnmatch
import hashlib
import os
from pathlib import Path
import re
import stat

from .scan import SCAN_ERRORS, command, finding


ROOT = Path('/')
SCOPE = 'this machine only'
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
OWNER = re.compile(r'\("([^"\r\n]+)",pid=([1-9][0-9]{0,9}),fd=[0-9]+\)')
GAPS = {
    'host_listeners': 'Listener attribution on this machine only is incomplete. Check access to ss and /proc.',
    'host_persistence': 'Persistence coverage on this machine only is incomplete. Check access to the watched files.',
    'host_baseline': 'Persistence on this machine only has no approved reference. Review the scan and approve the baseline.',
}


def listeners():
    rows = []
    complete = True
    try:
        output = command(['ss', '-H', '-tulpn'], 10).decode()
    except SCAN_ERRORS:
        return rows, False
    for line in output.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 6 or tuple(fields[:2]) not in {('tcp', 'LISTEN'), ('udp', 'UNCONN')}:
            complete = False
            continue
        address, _, port = fields[4].rpartition(':')
        if not address or not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            complete = False
            continue
        item = finding('host_listener', protocol=fields[0], address=address, port=int(port))
        owners = []
        if len(fields) == 7 and fields[6].startswith('users:(') and fields[6].endswith(')'):
            payload = fields[6][7:-1]
            owners = list(OWNER.finditer(payload))
            if ','.join(m.group() for m in owners) != payload:
                complete = False
                owners = []
        if not owners:
            rows.append(item)
            complete = False
        for owner in owners:
            name, pid = owner.groups()
            row = dict(item, process=name, pid=int(pid))
            try:
                binary = os.readlink(ROOT / 'proc' / pid / 'exe')
                if not os.path.isabs(binary):
                    raise ValueError()
                row['binary'] = binary
            except (OSError, ValueError):
                complete = False
            rows.append(row)
    return rows, complete


def file_hash(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise ValueError()
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ValueError()
            digest.update(chunk)
            remaining -= len(chunk)
        if os.fstat(fd).st_ctime_ns != info.st_ctime_ns:
            raise ValueError()
        return digest.hexdigest()


def persistence():
    hashes = {}
    links = {}
    complete = True

    def visit(directory, parent, parts):
        nonlocal complete
        pattern, *rest = parts
        wildcard = '*' in pattern
        names = os.listdir(directory) if wildcard else [pattern]
        for name in names:
            if parent == '/var/spool/cron' and wildcard and name == 'crontabs':
                continue
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            path = parent + '/' + name
            observed = wildcard
            try:
                if rest:
                    fd = os.open(name, DIR_FLAGS, dir_fd=directory)
                    try:
                        visit(fd, path, rest)
                    finally:
                        os.close(fd)
                else:
                    mode = os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode
                    observed = True
                    if stat.S_ISLNK(mode):
                        target = os.readlink(name, dir_fd=directory)
                        links[path] = os.path.normpath(os.path.join(parent, target))
                        hashes[path] = hashlib.sha256(b'link\0' + os.fsencode(target)).hexdigest()
                    elif stat.S_ISREG(mode):
                        hashes[path] = file_hash(directory, name)
                    else:
                        complete = False
            except FileNotFoundError:
                if observed:
                    complete = False
            except (OSError, ValueError):
                complete = False

    patterns = ['etc/crontab', 'etc/anacrontab', 'var/spool/cron/*', 'var/spool/cron/crontabs/*',
                'root/.ssh/authorized_keys', 'home/*/.ssh/authorized_keys']
    for suffix in ('d', 'hourly', 'daily', 'weekly', 'monthly', 'yearly'):
        patterns.append(f'etc/cron.{suffix}/*')
    units = ('etc/systemd/system', 'usr/lib/systemd/system', 'usr/local/lib/systemd/system',
             'etc/systemd/user', 'usr/lib/systemd/user', 'root/.config/systemd/user',
             'home/*/.config/systemd/user')
    merged_lib = os.path.realpath(ROOT / 'lib') == str(ROOT / 'usr/lib')
    if not merged_lib:
        units += ('lib/systemd/system', 'lib/systemd/user')
    for base in units:
        for kind in ('service', 'timer'):
            patterns.extend(f'{base}/{suffix}' for suffix in (
                f'*.{kind}', f'*.wants/*.{kind}', f'*.requires/*.{kind}', f'*.{kind}.d/*.conf'))
    root = os.open(ROOT, DIR_FLAGS)
    try:
        for pattern in patterns:
            visit(root, '', pattern.split('/'))
    finally:
        os.close(root)
    for path in links:
        seen = {path}
        target = links[path]
        while True:
            if merged_lib and target.startswith('/lib/systemd/'):
                target = '/usr' + target
            if target in seen or (target != '/dev/null' and target not in hashes):
                complete = False
                break
            if target not in links:
                break
            seen.add(target)
            target = links[target]
    return hashes, complete


def collect(c, approved):
    host = c['local_host']
    rows, attributed = listeners()
    hashes, readable = persistence()
    baseline = (approved or {}).get('persistence')
    for component, ok in (('host_listeners', attributed), ('host_persistence', readable),
                          ('host_baseline', baseline is not None)):
        if not ok:
            rows.append(finding('coverage', component=component))
    if baseline is not None:
        for path, digest in sorted(hashes.items()):
            if baseline.get(path) != digest:
                rows.append(finding('persistence_drift', path=path, sha256=digest,
                                    change='changed' if path in baseline else 'added'))
    status = 'ok' if attributed and readable and baseline is not None else 'partial'
    rows.append(finding('source_summary', status=status))
    for row in rows:
        row.update(scope=SCOPE, host=host, ip=c['hosts'][host])
    return rows, hashes, status
