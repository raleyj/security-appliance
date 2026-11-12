import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'provisioning'))
import console_recovery as recovery


class ConsoleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        salt = b'0123456789abcdef'
        password = 'Disposable-Recovery-Password-12345'
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
        (self.root / 'recovery.json').write_text(json.dumps({'salt': salt.hex(), 'hash': digest.hex()}))
        self.password = password

    def test_success_resets_persistent_throttle(self):
        self.assertTrue(recovery.verify_password(self.password, self.root, now=1000))
        self.assertEqual(json.loads((self.root / 'recovery-attempts.json').read_text()), {'failures': 0, 'notBefore': 0})

    def test_failed_attempt_throttles_after_process_restart(self):
        self.assertFalse(recovery.verify_password('incorrect-password-value', self.root, now=1000))
        with self.assertRaisesRegex(ValueError, 'temporarily locked'):
            recovery.begin_attempt(self.root, now=1001)
        self.assertEqual(json.loads((self.root / 'recovery-attempts.json').read_text())['failures'], 1)

    def test_interrupted_prompt_remains_throttled(self):
        recovery.begin_attempt(self.root, now=1000)
        with self.assertRaisesRegex(ValueError, 'temporarily locked'):
            recovery.begin_attempt(self.root, now=1001)

    def test_reset_uses_no_network_and_restarts_management(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs)); return Mock(returncode=0)
        result = recovery.reset_web_administrator('admin', 'Different-Password-123456', runner)
        self.assertTrue(result['sessionsInvalidated'])
        self.assertEqual(calls[0][0], ['docker', 'stop', 'security-management'])
        self.assertIn('--network', calls[1][0]); self.assertIn('none', calls[1][0])
        self.assertEqual(calls[-1][0], ['docker', 'start', 'security-management'])
        self.assertNotIn('keycloak', str(calls).lower())

    def test_reset_failure_and_restart_failure_are_reported(self):
        count = 0
        def rejected(command, **kwargs):
            nonlocal count; count += 1
            if count == 2: raise RuntimeError('policy rejected')
            return Mock(returncode=0)
        with self.assertRaisesRegex(ValueError, 'administrator name or password policy'):
            recovery.reset_web_administrator('missing', 'bad', rejected)
        count = 0
        def restart_fails(command, **kwargs):
            nonlocal count; count += 1
            if count == 3: raise RuntimeError('restart failed')
            return Mock(returncode=0)
        with self.assertRaisesRegex(RuntimeError, 'did not restart'):
            recovery.reset_web_administrator('admin', 'Different-Password-123456', restart_fails)


if __name__ == '__main__': unittest.main()
