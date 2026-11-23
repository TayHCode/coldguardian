from importlib.resources import files
import json
import os
from pathlib import Path
import subprocess
import sys

from .levels import LEVELS
from .report import atomic_text, load_json


PROFILES = ('quick', 'deep')


def _unit_directory():
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'systemd/user'


def _systemctl(*args):
    timeout = None if args[0] == 'start' else 30
    subprocess.run(['systemctl', '--user', *args], check=True, timeout=timeout, stdout=subprocess.DEVNULL)


def check_user_manager():
    _systemctl('show', '--property=Version')


def write_scan_timers(directory: Path, level: str, *, enabled: bool = False) -> tuple[Path, ...]:
    if not enabled:
        return ()
    policy = LEVELS[level]
    paths = []
    for profile, calendar in (('quick', policy.quick_calendar), ('deep', policy.deep_calendar)):
        if calendar is not None:
            name = f'coldguardian-{profile}'
            path = directory / f'{name}.timer'
            atomic_text(path, (
                '[Timer]\n'
                f'OnCalendar={calendar}\n'
                'Persistent=true\n'
                f'Unit={name}.service\n\n'
                '[Install]\n'
                'WantedBy=timers.target\n'
            ))
            paths.append(path)
    return tuple(paths)


def _completed_scan_timestamp(state_path):
    state = load_json(state_path, {})
    snapshot = state.get('snapshot') if isinstance(state, dict) else None
    if isinstance(snapshot, dict) and snapshot.get('complete') is True:
        return state.get('report_timestamp')


def install_scan_timers(level, output_dir):
    directory = _unit_directory()
    directory.mkdir(parents=True, exist_ok=True)
    template = files('coldguardian').joinpath('coldguardian.service').read_text()
    python = json.dumps(':' + sys.executable.replace('%', '%%'), ensure_ascii=False)
    timers = write_scan_timers(directory, level, enabled=True)
    for timer in timers:
        profile = timer.stem.removeprefix('coldguardian-')
        atomic_text(timer.with_suffix('.service'), template.format(python=python, profile=profile))
    _systemctl('daemon-reload')
    state_path = Path(output_dir) / 'state.json'
    previous = _completed_scan_timestamp(state_path)
    for timer in timers:
        service = timer.with_suffix('.service').name
        print(f'Checking {service}...', flush=True)
        try:
            _systemctl('start', service)
        except subprocess.CalledProcessError as error:
            raise ValueError(f'{service} failed to start or finish. Inspect journalctl --user -u {service}.') from error
        completed = _completed_scan_timestamp(state_path)
        if not completed or completed == previous:
            raise ValueError(f'{service} did not record a new complete network scan. Inspect journalctl --user -u {service}.')
        previous = completed
    _systemctl('enable', '--now', *(timer.name for timer in timers))
    print('Enabled ' + ', '.join(timer.name for timer in timers))


def remove_scan_timers():
    directory = _unit_directory()
    timers = [directory / f'coldguardian-{profile}.timer' for profile in PROFILES]
    services = [timer.with_suffix('.service') for timer in timers]
    timers = [path for path in timers if path.exists() or path.is_symlink()]
    services = [path for path in services if path.exists() or path.is_symlink()]
    if timers:
        _systemctl('disable', '--now', *(path.name for path in timers))
        _systemctl('clean', '--what=state', *(path.name for path in timers))
    if services:
        _systemctl('stop', *(path.name for path in services))
    for path in timers + services:
        path.unlink()
        yield path
    if timers or services:
        _systemctl('daemon-reload')
