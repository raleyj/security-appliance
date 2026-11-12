import sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import forward_proxy as f

class ForwardProxyTests(unittest.TestCase):
 def test_disabled_default_denies_all(self):
  text=f.render({'enabled':False,'client_cidrs':[],'allowed_domains':[]})
  self.assertIn('http_access deny all',text);self.assertNotIn('http_access allow allowed_clients',text)
 def test_requires_explicit_source(self):
  for cidrs in ([],['0.0.0.0/0'],['192.0.2.1/24']):
   with self.assertRaises(ValueError):f.validate({'enabled':True,'client_cidrs':cidrs,'allowed_domains':[]})
 def test_connect_and_destination_policy(self):
  value=f.validate({'enabled':True,'client_cidrs':['192.0.2.0/24'],'allowed_domains':['Example.COM']})
  text=f.render(value)
  self.assertIn('http_access deny CONNECT !SSL_ports',text)
  self.assertIn('acl blocked_destination dst',text)
  self.assertIn('192.0.2.0/12',text)
  self.assertIn('acl allowed_domains dstdomain .example.com',text)
  self.assertLess(text.index('http_access deny blocked_destination'),text.index('http_access allow allowed_clients'))
 def test_apply_validates_before_host_changes(self):
  with patch.object(f,'run') as run:
   with self.assertRaises(ValueError):f.apply({'enabled':True,'client_cidrs':[],'allowed_domains':[]})
   run.assert_not_called()
if __name__=='__main__':unittest.main()
