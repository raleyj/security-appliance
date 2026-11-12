import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import trust_inventory


class TrustInventoryTests(unittest.TestCase):
    def test_only_public_ca_chain_can_be_downloaded(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);tls=root/'tls';tls.mkdir();kmip=root/'kmip';kmip.mkdir()
            (tls/'ca.pem').write_text('-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n')
            (kmip/'ca.pem').write_text('-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n')
            with patch.object(trust_inventory,'TLS',tls),patch.object(trust_inventory,'KMIP',kmip):
                self.assertIn('BEGIN CERTIFICATE',trust_inventory.public_chain('management')['pem'])
                self.assertIn('BEGIN CERTIFICATE',trust_inventory.public_chain('kmip')['pem'])
                with self.assertRaises(ValueError):trust_inventory.public_chain('server-key')
                (tls/'ca.pem').write_text('-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n-----BEGIN ' + 'PRIVATE KEY-----\nSECRET\n')
                with self.assertRaises(ValueError):trust_inventory.public_chain('management')


if __name__=='__main__':unittest.main()
