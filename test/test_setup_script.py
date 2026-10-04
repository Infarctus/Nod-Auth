"""Exercise host preparation without Docker or real authentication state."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import unittest


@unittest.skipIf(os.getuid() == 0, 'Host preparation expects a non-root account')
class SetupScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy(Path(__file__).resolve().parents[1] / 'setup.sh', self.root)
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        docker = bin_dir / 'docker'
        docker.write_text(f'#!{sys.executable}\n' + r'''import json
import os
import sys
args = sys.argv[1:]
with open(os.environ['DOCKER_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
is_preflight = ('setup' in args and
                args[args.index('setup') + 1:][:1] == ['python'])
if is_preflight and os.environ.get('FAIL_PREFLIGHT') == '1':
    sys.exit(1)
''')
        docker.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}',
                        DOCKER_LOG=str(self.root / 'docker.log'))
        self.env.pop('SUDO_UID', None)
        self.env.pop('SUDO_GID', None)

    def docker_calls(self):
        return [json.loads(line) for line in
                (self.root / 'docker.log').read_text().splitlines()]

    def run_setup(self, **env):
        # Invocation outside the project must still prepare the project itself.
        return subprocess.run(['bash', str(self.root / 'setup.sh')], cwd='/tmp',
                              env=dict(self.env, **env), text=True,
                              capture_output=True)

    def test_missing_apk_prepares_private_directories_and_persists_ids(self):
        result = self.run_setup(LOCAL_UID='9999', LOCAL_GID='9999')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Place the Microsoft Authenticator APK', result.stderr)
        self.assertEqual((self.root / 'data').stat().st_mode & 0o777, 0o700)
        env = self.root / '.env'
        self.assertEqual(env.stat().st_mode & 0o777, 0o600)
        self.assertIn(f'LOCAL_UID={os.getuid()}\n', env.read_text())
        self.assertNotIn(['compose', 'build'], self.docker_calls())

    def test_rerun_preserves_state_and_other_env_settings(self):
        data = self.root / 'data'
        data.mkdir()
        saved = data / 'apk_config.json'
        saved.write_text('{"saved": true}')
        saved.chmod(0o644)
        (self.root / '.env').write_text(
            '# Custom config\nAUTH_CONFIG_FILE=./config.local.toml\n'
            'export LOCAL_UID=99\nLOCAL_GID = 99\n')
        for _ in range(2):
            result = self.run_setup()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(saved.read_text(), '{"saved": true}')
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        env = (self.root / '.env').read_text()
        self.assertIn('# Custom config\nAUTH_CONFIG_FILE=./config.local.toml\n', env)
        self.assertEqual(env.count('LOCAL_UID='), 1)
        self.assertEqual(env.count('LOCAL_GID='), 1)
        calls = self.docker_calls()
        self.assertEqual(calls.count(['compose', 'run', '--rm', '--no-deps',
                                      '-e', 'AUTH_APK_PATH=', 'setup']), 2)

    def test_container_access_failure_does_not_start_wizard(self):
        (self.root / 'apk').mkdir()
        (self.root / 'apk/msauth.apk').write_bytes(b'apk placeholder')
        result = self.run_setup(FAIL_PREFLIGHT='1')
        self.assertNotEqual(result.returncode, 0)
        calls = self.docker_calls()
        preflight = [call for call in calls if 'python' in call]
        self.assertEqual(len(preflight), 1)
        self.assertIn('-T', preflight[0])
        self.assertIn('AUTH_APK_PATH=/apk/msauth.apk', preflight[0])
        self.assertFalse(any(call[-1] == 'setup' for call in calls))

    def test_symlink_rejected_without_changing_target(self):
        target = self.root / 'outside'
        target.write_text('preserve')
        target.chmod(0o644)
        (self.root / 'data').mkdir()
        (self.root / 'data/linked').symlink_to(target)
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Remove symlinks', result.stderr)
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertEqual(target.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
