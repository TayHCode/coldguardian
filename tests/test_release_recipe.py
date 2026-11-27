import json
from pathlib import Path
import shlex
import tomllib
import unittest


class ReleaseRecipeTests(unittest.TestCase):
    def test_readme_quickstart_matches_release_commands(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'release-check.json').read_text())
        readme = (root / 'README.md').read_text().splitlines()
        commands = [
            ['python3', '-m', 'pip', 'install', '--no-input', '.'],
            ['coldguardian', '--help'],
            ['coldguardian', 'demo'],
        ]
        self.assertEqual([item['argv'] for item in manifest['quickstart']], commands)
        for item, argv in zip(manifest['quickstart'], commands):
            self.assertEqual(item['file'], 'README.md')
            self.assertIn(item['line'], range(1, len(readme) + 1))
            self.assertEqual(shlex.split(readme[item['line'] - 1]), argv)
        self.assertIn(
            {'role': 'tests', 'argv': ['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v']},
            manifest['checks'],
        )

    def test_build_backend_has_a_hash_pinned_wheel(self):
        root = Path(__file__).resolve().parents[1]
        lock = tomllib.loads((root / 'pylock.toml').read_text())
        backend, = (p for p in lock['packages'] if p['name'] == 'setuptools')
        self.assertTrue(backend['version'])
        self.assertTrue(backend['wheels'])
        for wheel in backend['wheels']:
            self.assertRegex(wheel['hashes']['sha256'], r'^[0-9a-f]{64}$')
