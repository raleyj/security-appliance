import json, runpy, tempfile, unittest
from pathlib import Path
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]


class ProxyRouteTests(unittest.TestCase):
 def test_routes_management_and_identity_by_hostname(self):
  with tempfile.TemporaryDirectory() as tmp:
   config=Path(tmp)
   (config/'config.json').write_text(json.dumps({
    'hostname':'security','domain':'example.local','sso_fqdn':'sso.example.local','kmip_fqdn':'kmip.example.local','admin_cidrs':['192.0.2.64/27']
   }))
   with patch.dict('os.environ',{'SECURITY_CONFIG':str(config)}):
    runpy.run_path(str(ROOT/'provisioning/render_proxy.py'),run_name='__main__')
   text=(config/'nginx.conf').read_text()
   self.assertIn('server_name security.example.local;',text)
   self.assertIn('server_name sso.example.local;',text)
   self.assertIn('return 302 /identity/;',text)
   self.assertIn('location = /oidc-test/callback { return 410; }',text)
   self.assertIn('listen 443 ssl default_server;',text)
   self.assertIn('server_tokens off;',text)
   self.assertEqual(text.count('add_header Strict-Transport-Security "max-age=31536000" always;'),3)
   self.assertEqual(text.count('ssl_protocols TLSv1.2 TLSv1.3;'),3)


if __name__=='__main__':unittest.main()
