import sys,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'provisioning'))
import host_control

class TimezoneHostControlTests(unittest.TestCase):
 def test_status_reads_system_timezone(self):
  with patch.object(host_control,'run',return_value='America/New_York\n') as run:
   self.assertEqual(host_control.perform({'action':'timezone-status'}),{'timezone':'America/New_York'})
   run.assert_called_once_with('timedatectl','show','--property=Timezone','--value')
 def test_apply_uses_argument_vector_and_allowlist(self):
  with patch.object(host_control,'run',return_value='') as run:
   result=host_control.perform({'action':'timezone-apply','timezone':'America/New_York'})
   self.assertEqual(result['timezone'],'America/New_York')
   self.assertEqual(run.call_args_list[0].args,('timedatectl','set-timezone','America/New_York'))
  with self.assertRaises(ValueError):host_control.perform({'action':'timezone-apply','timezone':'../../tmp'})

if __name__=='__main__':unittest.main()
