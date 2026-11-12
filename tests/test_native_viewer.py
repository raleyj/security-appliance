import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import update_bundle
from unittest.mock import patch
import test_management as base
server=base.server

class NativeViewer(unittest.TestCase):
 setUp=base.ManagementTests.setUp
 login=base.ManagementTests.login
 def create_viewer(self):
  csrf=self.login()
  r=self.c.post('/admin/api/accounts',json={'operation':'create','username':'mcp-reader','role':'viewer','new_password':'Viewer-Test-Password-12345','password':'Disposable-Test-Password-01234'},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
  self.assertEqual(r.status_code,200)
  viewer=server.app.test_client()
  login=viewer.post('/admin/api/login',json={'username':'mcp-reader','password':'Viewer-Test-Password-12345'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost')
  self.assertEqual(login.status_code,200);self.assertEqual(login.json['role'],'viewer')
  return viewer,login.json['csrf']
 def test_viewer_read_routes_and_denied_writes(self):
  viewer,csrf=self.create_viewer()
  with patch.object(server,'host_request',return_value={'services':[]}) as host:
   for route in ('services','operations/status','certificates','storage'):
    self.assertEqual(viewer.get('/admin/api/'+route,base_url='https://localhost').status_code,200,route)
   host.reset_mock()
   for route in ('config','accounts','updates','diagnostics','support-bundle','trust-inventory'):
    self.assertEqual(viewer.get('/admin/api/'+route,base_url='https://localhost').status_code,403,route)
   for route in ('services','accounts','setup/save','appliance/power','certificates','forward-proxy','account/password'):
    self.assertEqual(viewer.post('/admin/api/'+route,json={},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,403,route)
   host.assert_not_called()
  self.assertEqual(viewer.get('/admin/api/auth',base_url='https://localhost').json['role'],'viewer')
  self.assertEqual(viewer.post('/admin/api/logout',json={},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,200)
 def test_legacy_admin_and_invalid_role(self):
  csrf=self.login()
  self.assertEqual(self.c.get('/admin/api/auth',base_url='https://localhost').json['role'],'administrator')
  r=self.c.post('/admin/api/accounts',json={'operation':'create','username':'bad-role','role':'root','new_password':'Viewer-Test-Password-12345','password':'Disposable-Test-Password-01234'},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
  self.assertEqual(r.status_code,400)
 def test_legacy_rollback_cannot_promote_viewer(self):
  self.create_viewer()
  with patch.object(update_bundle,'MANAGEMENT_DB',server.ROOT/'management.sqlite'):
   with self.assertRaisesRegex(ValueError,'Disable viewer'):
    update_bundle.require_viewer_compatible([('app/server.py',b'legacy administrator only app')])
   update_bundle.require_viewer_compatible([('app/server.py',b'NATIVE_VIEWER_ROLES=True')])
   with server.db() as c:c.execute("UPDATE account_state SET enabled=0 WHERE name='mcp-reader'")
   update_bundle.require_viewer_compatible([('app/server.py',b'legacy administrator only app')])

if __name__=='__main__':unittest.main()
