import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "provisioning"))
import host_control


class HostPowerTests(unittest.TestCase):
    def test_shutdown_is_queued_with_fixed_argument_vector(self):
        with patch.object(host_control, "run", return_value="") as run:
            result = host_control.perform({"action": "appliance-shutdown"})
        self.assertTrue(result["queued"])
        run.assert_called_once_with(
            "systemd-run",
            "--unit=security-appliance-shutdown",
            "--on-active=3s",
            "/usr/bin/systemctl",
            "poweroff",
        )


if __name__ == "__main__":
    unittest.main()
