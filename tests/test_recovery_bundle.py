import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'provisioning'))
import recovery_bundle


class RecoveryBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root / 'source'; self.source.mkdir()
        (self.source / 'config.json').write_text('{"hostname":"security"}')
        keys = self.source / 'kmip'; keys.mkdir(); (keys / 'key.db').write_bytes(b'disposable-key-state')
        self.bundle = self.root / 'recovery.sarb'; self.password = 'Disposable-Recovery-Bundle-Password-12345'

    def test_authenticated_round_trip(self):
        link = self.source / 'current'
        try: link.symlink_to('kmip', target_is_directory=True)
        except OSError: link = None
        created = recovery_bundle.create_bundle([self.source], self.bundle, self.password)
        self.assertTrue(created['created']); destination = self.root / 'restored'
        restored = recovery_bundle.restore_bundle(self.bundle, destination, self.password)
        self.assertTrue(restored['restored'])
        relative = self.source.resolve().as_posix().lstrip('/')
        self.assertEqual((destination / relative / 'kmip/key.db').read_bytes(), b'disposable-key-state')
        if link:
            self.assertEqual((destination / relative / 'current/key.db').read_bytes(), b'disposable-key-state')
            self.assertFalse((destination / relative / 'current').is_symlink())

    def test_wrong_password_and_tampering_are_rejected(self):
        recovery_bundle.create_bundle([self.source], self.bundle, self.password)
        with self.assertRaisesRegex(ValueError, 'authentication failed'):
            recovery_bundle.restore_bundle(self.bundle, self.root / 'wrong', 'Different-Recovery-Password-12345')
        with zipfile.ZipFile(self.bundle) as source:
            records = {name: source.read(name) for name in source.namelist()}
        payload = bytearray(records['payload.bin']); payload[len(payload) // 2] ^= 1
        with zipfile.ZipFile(self.bundle, 'w', zipfile.ZIP_STORED) as target:
            target.writestr('metadata.json', records['metadata.json'])
            target.writestr('payload.bin', payload)
            target.writestr('payload.hmac', records['payload.hmac'])
        with self.assertRaises(ValueError):
            recovery_bundle.restore_bundle(self.bundle, self.root / 'tampered', self.password)


if __name__ == '__main__': unittest.main()
