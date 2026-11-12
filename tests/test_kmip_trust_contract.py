import unittest
from pathlib import Path


ROOT=Path(__file__).resolve().parents[1]


class KmipTrustContractTests(unittest.TestCase):
    def test_first_boot_uses_durable_hierarchy(self):
        source=(ROOT/'provisioning/kmip_trust.py').read_text()
        prepare=(ROOT/'provisioning/prepare_services.py').read_text()
        self.assertIn("'-days','3650'",source)
        self.assertIn("'-days','1825'",source)
        self.assertIn("days='825'",source)
        self.assertIn("days='397'",source)
        self.assertIn('pathlen:1',source)
        self.assertIn('pathlen:0',source)
        self.assertIn("initialize(km,cfg['kmip_fqdn'])",prepare)
        self.assertNotIn("'-days','30'",prepare)


if __name__=='__main__':unittest.main()
