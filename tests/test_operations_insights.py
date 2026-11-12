import sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import operations_insights as insights

class OperationsInsightsTests(unittest.TestCase):
 def test_storage_categories_thresholds_and_growth(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(insights,'SAMPLES',Path(folder)/'samples.json'),patch.object(insights.os,'statvfs',return_value=SimpleNamespace(f_blocks=100,f_bavail=12,f_frsize=100),create=True),patch.object(insights,'directory_bytes',return_value=100),patch.object(insights,'log_bytes',return_value=25):
   result=insights.storage_report()
   self.assertEqual(result['status'],'warning');self.assertEqual(result['usedPercent'],88)
   self.assertEqual([r['name'] for r in result['categories']][-2:],['Container logs','Support bundles'])
   self.assertEqual(result['categories'][3]['bytes'],0)
   self.assertFalse(result['growthAvailable'])
   self.assertTrue(insights.SAMPLES.exists())
 def test_diagnostics_are_fixed_and_sanitized(self):
  health={'dnsHealthy':True,'ntpHealthy':True,'certificate':{'enrolled':True,'daysRemaining':100},'firewallActive':True,'servicesHealthy':True}
  with patch.object(insights,'oidc_probe',return_value=True):result=insights.diagnostics(health,lambda service:service!='kmip',lambda kind:True)
  self.assertEqual(len(result['checks']),9);self.assertEqual(result['attention'],1)
  self.assertEqual(next(row for row in result['checks'] if row['code']=='kmip')['state'],'attention')
