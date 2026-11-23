import ast
from collections import defaultdict
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coldguardian import scan, timers


ALLOWLIST = {'nmap', 'ip', 'tailscale', 'ss'}
READ_ONLY = {('ss', '-H', '-tulpn'), ('ip', '-j', 'addr'), ('ip', '-j', 'route'), ('tailscale', 'status', '--json'),
                 ('tailscale', 'funnel', 'status', '--json')}
LIFECYCLE_CALLERS = {'check_user_manager': 'setup', 'install_scan_timers': 'setup', 'remove_scan_timers': 'uninstall'}
USER_SYSTEMCTL = {
    'check_user_manager': [('show', '--property=Version')],
    'install_scan_timers': [
        ('daemon-reload',),
        ('start', 'service'),
        ('enable', '--now', '*(timer.name for timer in timers)'),
    ],
    'remove_scan_timers': [
        ('disable', '--now', '*(path.name for path in timers)'),
        ('clean', '--what=state', '*(path.name for path in timers)'),
        ('stop', '*(path.name for path in services)'),
        ('daemon-reload',),
    ],
}
PACKAGE = Path(scan.__file__).parent


class SubprocessTests(unittest.TestCase):
    def test_inventory_of_subprocesses(self):
        programs = set()
        launches, read_commands = [], set()
        lifecycle_calls, systemctl_calls = set(), defaultdict(list)
        for path in sorted(PACKAGE.rglob('*.py')):
            tree = ast.parse(path.read_text(), filename=str(path))
            scopes = {node: fn.name for fn in tree.body if isinstance(fn, ast.FunctionDef) for node in ast.walk(fn)}
            for node in ast.walk(tree):
                with self.subTest(file=path.name, line=getattr(node, 'lineno', None)):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(alias.name, {'pty', '_posixsubprocess'})
                            if alias.name == 'subprocess':
                                self.assertIsNone(alias.asname)
                    if isinstance(node, ast.ImportFrom):
                        self.assertNotIn(node.module, {'subprocess', 'pty', '_posixsubprocess'})
                        if node.module in {'os', 'asyncio'}:
                            self.assertFalse(any(self.process_api(alias.name) for alias in node.names))
                    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'subprocess':
                        self.assertIn(node.attr, {'run', 'PIPE', 'DEVNULL', 'CalledProcessError', 'SubprocessError'})
                    if isinstance(node, ast.Attribute):
                        self.assertFalse(self.process_api(node.attr), ast.unparse(node))
                    if not isinstance(node, ast.Call):
                        continue
                    call = ast.unparse(node.func)
                    if call == 'subprocess.run':
                        self.assertTrue(all(kw.arg not in {None, 'shell', 'executable'} for kw in node.keywords))
                        launches.append((path.name, scopes.get(node)))
                        if path.name == 'timers.py':
                            self.assertEqual(ast.unparse(node.args[0]), "['systemctl', '--user', *args]")
                        else:
                            self.assertEqual(ast.unparse(node.args[0]), 'args')
                    elif call == '_systemctl':
                        self.assertEqual(path.name, 'timers.py')
                        self.assertFalse(node.keywords)
                        systemctl_calls[scopes.get(node)].append(tuple(
                            ast.unparse(arg) if isinstance(arg, (ast.Starred, ast.Name)) else ast.literal_eval(arg)
                            for arg in node.args
                        ))
                    elif call.rpartition('.')[2] in LIFECYCLE_CALLERS:
                        lifecycle_calls.add((path.name, scopes.get(node), call.rpartition('.')[2]))
                    elif call.rpartition('.')[2] in {'command', '_read_json'}:
                        argv = node.args[0]
                        if (
                            isinstance(argv, ast.Name) and argv.id == 'args'
                            and path.name == 'wizard.py' and scopes.get(node) == '_read_json'
                        ):
                            continue
                        if isinstance(argv, ast.BinOp) and isinstance(argv.left, ast.Name) and argv.left.id == 'DISCOVERY':
                            argv = next(statement.value for statement in tree.body if isinstance(statement, ast.Assign)
                                        and any(isinstance(target, ast.Name) and target.id == 'DISCOVERY' for target in statement.targets))
                        self.assertIsInstance(argv, ast.List, ast.unparse(argv))
                        program = ast.literal_eval(argv.elts[0])
                        self.assertIn(program, ALLOWLIST)
                        programs.add(program)
                        if program != 'nmap':
                            read_commands.add(tuple(ast.literal_eval(argv)))
        self.assertCountEqual(launches, [('scan.py', 'command'), ('timers.py', '_systemctl')])
        self.assertEqual(programs, ALLOWLIST, f'Coldguardian subprocesses: {", ".join(sorted(programs))}')
        self.assertEqual(read_commands, READ_ONLY)
        self.assertEqual(scan.READ_COMMANDS, READ_ONLY)
        self.assertEqual(lifecycle_calls, {('wizard.py', scope, name) for name, scope in LIFECYCLE_CALLERS.items()})
        self.assertEqual(set(systemctl_calls), set(USER_SYSTEMCTL))
        for scope, args in USER_SYSTEMCTL.items():
            self.assertCountEqual(systemctl_calls[scope], args)
        for level, profiles in (('low', ('quick',)), ('medium', ('quick', 'deep')), ('high', ('quick', 'deep'))):
            with (self.subTest(level=level), tempfile.TemporaryDirectory() as directory,
                  patch.object(timers, '_unit_directory', return_value=Path(directory)),
                  patch.object(timers, '_completed_scan_timestamp', side_effect=[None, 'quick', 'deep']),
                  patch.object(timers.subprocess, 'run') as launch, contextlib.redirect_stdout(io.StringIO())):
                timers.check_user_manager()
                timers.install_scan_timers(level, directory)
                list(timers.remove_scan_timers())
                timer_units = [f'coldguardian-{profile}.timer' for profile in profiles]
                service_units = [f'coldguardian-{profile}.service' for profile in profiles]
                self.assertEqual([call.args[0] for call in launch.call_args_list], [
                    ['systemctl', '--user', 'show', '--property=Version'],
                    ['systemctl', '--user', 'daemon-reload'],
                    *(['systemctl', '--user', 'start', service] for service in service_units),
                    ['systemctl', '--user', 'enable', '--now', *timer_units],
                    ['systemctl', '--user', 'disable', '--now', *timer_units],
                    ['systemctl', '--user', 'clean', '--what=state', *timer_units],
                    ['systemctl', '--user', 'stop', *service_units],
                    ['systemctl', '--user', 'daemon-reload'],
                ])
        for script in PACKAGE.rglob('*.nse'):
            self.assertNotRegex(script.read_text(), r'\b(?:os\.execute|io\.popen)\b')

    @staticmethod
    def process_api(name):
        return (
            name in {'*', 'system', 'popen', 'Popen', 'fork', 'fork_exec', 'forkpty'}
            or (name != 'executable' and name.startswith(('spawn', 'exec', 'posix_spawn', 'create_subprocess')))
        )

    def test_command_rejects_other_executables_before_launch(self):
        with patch('coldguardian.scan.subprocess.run') as launch:
            for args in (['ss'], ['ss', '-K'], ['ss', '-H', '-tulpn', '-a'], ['ssh'], ['sh'], ['/bin/nmap'], ['ip', 'link', 'set'], ['tailscale', 'down'],
                         ['tailscale', 'funnel', '443'], ['tailscale', 'funnel', 'reset']):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    scan.command(args, 1)
            launch.assert_not_called()
