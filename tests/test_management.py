import io, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
os.environ['SECURITY_STATE']=tempfile.mkdtemp()
import server
import json,time
from unittest.mock import patch
from configuration import validate_config,validate_timezone

CFG=dict(hostname='security-test',domain='example.test',network_mode='dhcp',ip='',prefix='',gateway='',dns=[],ntp=['ntp.example.test'],admin_cidrs=['192.0.2.10/32'],kmip_client_cidrs=[],sso_fqdn='sso.example.test',kmip_fqdn='kmip.example.test')
class ManagementTests(unittest.TestCase):
 def setUp(self):
  server.ROOT=Path(tempfile.mkdtemp());server.initialize('admin','Disposable-Test-Password-01234',CFG);self.c=server.app.test_client()
  os.environ.pop('SECURITY_BUILD_AUTH_BYPASS',None)
 def login(self):
  r=self.c.post('/admin/api/login',json={'username':'admin','password':'Disposable-Test-Password-01234'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost')
  self.assertEqual(r.status_code,200);self.assertIn('Secure',r.headers['Set-Cookie']);return r.json['csrf']
 def test_unauthorized(self):self.assertEqual(self.c.get('/admin/api/config').status_code,401)
 def test_build_auto_login_is_bounded_and_keeps_sensitive_reauthentication(self):
  os.environ['SECURITY_BUILD_AUTH_BYPASS']='1';self.addCleanup(os.environ.pop,'SECURITY_BUILD_AUTH_BYPASS',None)
  marker={'username':'admin','csrf':'x'*48,'expires':time.time()+3600,'allowed_cidrs':['192.0.2.10/32']}
  path=server.ROOT/'build-auth-bypass.json';path.write_text(json.dumps(marker));os.chmod(path,0o600)
  approved={'X-Forwarded-For':'192.0.2.10'}
  auth=self.c.get('/admin/api/auth',headers=approved,base_url='https://localhost').json
  self.assertTrue(auth['authenticated']);self.assertTrue(auth['buildMode']);self.assertEqual(auth['username'],'admin')
  self.assertEqual(self.c.get('/admin/api/config',headers=approved,base_url='https://localhost').status_code,200)
  self.assertEqual(self.c.post('/admin/api/setup/save',json={'config':CFG,'revision':1},headers=approved,base_url='https://localhost').status_code,403)
  headers={**approved,'X-CSRF-Token':auth['csrf']}
  self.assertEqual(self.c.post('/admin/api/timezone',json={'timezone':'Etc/UTC'},headers=headers,base_url='https://localhost').status_code,400)
  denied={'X-Forwarded-For':'192.0.2.11'}
  self.assertFalse(self.c.get('/admin/api/auth',headers=denied,base_url='https://localhost').json['authenticated'])
  self.assertEqual(self.c.get('/admin/api/config',headers=denied,base_url='https://localhost').status_code,401)
 def test_logout_ends_the_current_session(self):
  csrf=self.login()
  r=self.c.post('/admin/api/logout',json={},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
  self.assertEqual(r.status_code,200)
  self.assertEqual(self.c.get('/admin/api/auth',base_url='https://localhost').json['authenticated'],False)
  self.assertIn('security_session=;',r.headers['Set-Cookie'])
 def test_csrf_and_persistence(self):
  csrf=self.login()
  self.assertEqual(self.c.post('/admin/api/setup/save',json={'config':CFG,'revision':1},base_url='https://localhost').status_code,403)
  self.assertEqual(self.c.post('/admin/api/setup/save',json={'config':CFG,'revision':1},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,200)
  self.assertEqual(self.c.post('/admin/api/setup/save',json={'config':CFG,'revision':1},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,409)
  self.assertEqual(self.c.get('/admin/api/config',base_url='https://localhost').json['revision'],2)
 def test_recovery_invalidates_sessions(self):
  self.login();server.reset_password('admin','Different-Test-Password-01234')
  self.assertEqual(self.c.get('/admin/api/config',base_url='https://localhost').status_code,401)
 def test_reinitialization_refused(self):
  with self.assertRaises(ValueError):server.initialize('admin','Disposable-Test-Password-01234',CFG)
 def test_fifteen_character_web_password_boundary(self):
  self.assertEqual(len('Aa1!23456789012'),15);server.password_policy('Aa1!23456789012')
  with self.assertRaises(ValueError):server.password_policy('Aa1!2345678901')
 def test_login_throttled(self):
  args=dict(json={'username':'admin','password':'bad'},headers={'X-Requested-With':'SecurityAppliance'})
  self.assertEqual(self.c.post('/admin/api/login',**args).status_code,401);self.assertEqual(self.c.post('/admin/api/login',**args).status_code,429)
 def test_network_guards(self):
  for patch in [{'ip':'192.0.2.2'},{'hostname':'bad;command'},{'admin_cidrs':['0.0.0.0/0']},{'kmip_client_cidrs':['0.0.0.0/0']},{'kmip_client_cidrs':['192.0.2.10/24']},{'network_mode':'static','ip':'192.0.2.0','prefix':24,'gateway':'192.0.2.1','dns':['192.0.2.1']}]:
   with self.assertRaises(ValueError):validate_config({**CFG,**patch})
  with self.assertRaises(ValueError):validate_timezone('Invalid/Timezone')
 def test_timezone_status_and_apply_require_reauthentication(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  with patch.object(server,'host_request',side_effect=[{'timezone':'Etc/UTC'},{'timezone':'America/New_York','notice':'Appliance timezone updated.'}]) as host:
   self.assertEqual(self.c.get('/admin/api/timezone',base_url='https://localhost').json['timezone'],'Etc/UTC')
   body={'timezone':'America/New_York','password':'Disposable-Test-Password-01234'}
   r=self.c.post('/admin/api/timezone',json=body,headers=headers,base_url='https://localhost')
   self.assertEqual(r.status_code,200);self.assertEqual(r.json['timezone'],'America/New_York')
   self.assertEqual(host.call_args_list[-1].args[0],{'action':'timezone-apply','timezone':'America/New_York'})
 def test_completed_appliance_can_save_day_two_configuration(self):
  csrf=self.login()
  with server.db() as c:c.execute('UPDATE settings SET completed=1 WHERE id=1')
  r=self.c.post('/admin/api/setup/save',json={'config':CFG,'revision':1},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
  self.assertEqual(r.status_code,200);self.assertEqual(r.json['revision'],2)
 def test_completion_requires_explicit_acknowledgment(self):
  csrf=self.login()
  with patch.object(server,'host_request') as host:
   r=self.c.post('/admin/api/setup/complete',json={'acknowledged':False},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
   self.assertEqual(r.status_code,400);host.assert_not_called()
 def test_password_change_invalidates_all_sessions(self):
  csrf=self.login();other=server.app.test_client()
  other.post('/admin/api/login',json={'username':'admin','password':'Disposable-Test-Password-01234'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost')
  r=self.c.post('/admin/api/account/password',json={'password':'Disposable-Test-Password-01234','new_password':'Changed-Test-Password-123456'},headers={'X-CSRF-Token':csrf},base_url='https://localhost')
  self.assertEqual(r.status_code,200)
  for client in (self.c,other):self.assertEqual(client.get('/admin/api/config',base_url='https://localhost').status_code,401)
  r=self.c.post('/admin/api/login',json={'username':'admin','password':'Changed-Test-Password-123456'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost');self.assertEqual(r.status_code,200)
 def test_administrator_lifecycle(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  create={'operation':'create','username':'second-admin','new_password':'Second-Admin-Password-12345','password':'Disposable-Test-Password-01234'}
  self.assertEqual(self.c.post('/admin/api/accounts',json=create,headers=headers,base_url='https://localhost').status_code,200)
  accounts=self.c.get('/admin/api/accounts',base_url='https://localhost').json['accounts'];self.assertEqual([x['username'] for x in accounts],['admin','second-admin'])
  self.assertEqual(self.c.post('/admin/api/accounts',json={'operation':'delete','username':'admin','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost').status_code,409)
  self.assertEqual(self.c.post('/admin/api/accounts',json={'operation':'delete','username':'second-admin','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost').status_code,200)
 def test_disabled_administrator_cannot_sign_in_and_sessions_are_revoked(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  self.c.post('/admin/api/accounts',json={'operation':'create','username':'second-admin','new_password':'Second-Admin-Password-12345','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost')
  other=server.app.test_client();login=other.post('/admin/api/login',json={'username':'second-admin','password':'Second-Admin-Password-12345'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost')
  self.assertEqual(login.status_code,200)
  accounts=self.c.get('/admin/api/accounts',base_url='https://localhost').json['accounts']
  second=next(row for row in accounts if row['username']=='second-admin')
  self.assertEqual(second['activeSessions'],1);self.assertTrue(second['lastSuccessfulLogin'])
  disabled=self.c.post('/admin/api/accounts',json={'operation':'disable','username':'second-admin','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost')
  self.assertEqual(disabled.status_code,200)
  self.assertEqual(other.get('/admin/api/config',base_url='https://localhost').status_code,401)
  self.assertEqual(other.post('/admin/api/login',json={'username':'second-admin','password':'Second-Admin-Password-12345'},headers={'X-Requested-With':'SecurityAppliance'},base_url='https://localhost').status_code,401)
  self.assertEqual(self.c.post('/admin/api/accounts',json={'operation':'disable','username':'admin','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost').status_code,409)
 def test_idle_timeout_policy_is_bounded_and_audited(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  self.assertEqual(self.c.get('/admin/api/session-policy',base_url='https://localhost').json['idleSeconds'],900)
  bad=self.c.post('/admin/api/session-policy',json={'idleSeconds':60,'password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost')
  self.assertEqual(bad.status_code,400)
  good=self.c.post('/admin/api/session-policy',json={'idleSeconds':600,'password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost')
  self.assertEqual(good.status_code,200)
  self.assertEqual(self.c.get('/admin/api/session-policy',base_url='https://localhost').json['idleSeconds'],600)
  self.assertTrue(any(row['action']=='session-idle-policy' for row in self.c.get('/admin/api/audit',base_url='https://localhost').json['events']))
 def test_preflight_blocks_required_failures_and_keeps_optional_enrollment_as_warning(self):
  self.login()
  healthy={'dnsHealthy':True,'ntpHealthy':True,'certificate':{'enrolled':True,'daysRemaining':700},'firewallActive':True,'servicesHealthy':True}
  service={'identityInitialized':True,'testedServices':['keycloak'],'oidcQualificationPassed':True,'services':[{'service':'keycloak','ready':True},{'service':'kmip','ready':True},{'service':'proxy','ready':True}]}
  empty_trust={'certificates':[]}
  with patch.object(server,'host_request',side_effect=[healthy,service,empty_trust]):
   result=self.c.get('/admin/api/setup/preflight',base_url='https://localhost').json
  self.assertTrue(result['readyToComplete']);self.assertEqual(result['warnings'],1)
  with patch.object(server,'host_request',side_effect=[{**healthy,'firewallActive':False},service,empty_trust]):
   result=self.c.get('/admin/api/setup/preflight',base_url='https://localhost').json
  self.assertFalse(result['readyToComplete']);self.assertTrue(any(row['code']=='firewall' and row['state']=='blocked' for row in result['checks']))
  with server.db() as c:c.execute('UPDATE settings SET config=? WHERE id=1',(json.dumps({**CFG,'kmip_client_cidrs':['192.0.2.10/32']}),))
  with patch.object(server,'host_request',side_effect=[healthy,service,empty_trust]):
   result=self.c.get('/admin/api/setup/preflight',base_url='https://localhost').json
  self.assertEqual(next(row for row in result['checks'] if row['code']=='kmip')['state'],'warning')
  enrolled={'certificates':[{'role':'KMIP client','available':True,'trustStatus':'trusted','daysRemaining':90}]}
  with patch.object(server,'host_request',side_effect=[healthy,service,enrolled]):
   result=self.c.get('/admin/api/setup/preflight',base_url='https://localhost').json
  self.assertEqual(next(row for row in result['checks'] if row['code']=='kmip')['state'],'pass')
 def test_prior_release_restore_requires_reauthentication_and_confirmation(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  with patch.object(server,'host_request',return_value={'restored':True,'version':'1.0'}) as host:
   self.assertEqual(self.c.post('/admin/api/updates/restore',json={'confirmed':True},headers=headers,base_url='https://localhost').status_code,400)
   self.assertEqual(self.c.post('/admin/api/updates/restore',json={'confirmed':False,'password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost').status_code,400)
   self.assertEqual(self.c.post('/admin/api/updates/restore',json={'confirmed':True,'password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost').status_code,202)
   host.assert_called_once_with({'action':'update-restore'})
 def test_operational_status_and_reboot_guards(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  with patch.object(server,'host_request',return_value={'firewallActive':True}) as host:
   self.assertEqual(self.c.get('/admin/api/operations/status',base_url='https://localhost').status_code,200)
   host.assert_called_once_with({'action':'appliance-status'})
  self.assertEqual(self.c.post('/admin/api/operations/reboot',json={'confirmed':True},base_url='https://localhost').status_code,403)
 def test_bounded_storage_diagnostics_and_help_require_sign_in(self):
  for path in ('storage','diagnostics','help.md'):
   self.assertEqual(self.c.get('/admin/api/'+path).status_code,401)
  self.login()
  with patch.object(server,'host_request',return_value={'checkedAt':1,'checks':[],'categories':[]}):
   self.assertEqual(self.c.get('/admin/api/storage',base_url='https://localhost').status_code,200)
   self.assertEqual(self.c.get('/admin/api/diagnostics',base_url='https://localhost').status_code,200)
  with patch.object(server,'host_request',return_value={'version':'1.2'}):
   response=self.c.get('/admin/api/help.md',base_url='https://localhost')
  self.assertEqual(response.status_code,200);self.assertIn(b'Installed release: 1.2',response.data)
 def test_alert_delivery_test_requires_reauthentication_and_is_audited(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  self.assertEqual(self.c.post('/admin/api/alert-delivery',json={'operation':'test'},headers=headers,base_url='https://localhost').status_code,400)
  with patch.object(server,'host_request',return_value={'lastResult':'delivered','lastAttemptAt':1}) as host:
   response=self.c.post('/admin/api/alert-delivery',json={'operation':'test','password':'Disposable-Test-Password-01234'},headers=headers,base_url='https://localhost')
  self.assertEqual(response.status_code,200);host.assert_called_once_with({'action':'alert-delivery-test'})
  self.assertTrue(any(row['action']=='alert-delivery-test' and row['outcome']=='success' for row in self.c.get('/admin/api/audit',base_url='https://localhost').json['events']))
 def test_signed_update_requires_reauthentication_and_stages_an_opaque_name(self):
  self.assertEqual(self.c.get('/admin/api/updates').status_code,401)
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  with patch.object(server,'host_request',side_effect=[{'version':'build-candidate','signatureVerification':True},{'installed':True,'version':'test-1','files':1}]) as host:
   status=self.c.get('/admin/api/updates',base_url='https://localhost')
   self.assertEqual(status.status_code,200);self.assertTrue(status.json['signatureVerification'])
   rejected=self.c.post('/admin/api/updates',data={'password':'Wrong-Password-123456789','bundle':(io.BytesIO(b'bad'),'bad.sau')},headers=headers,base_url='https://localhost')
   self.assertEqual(rejected.status_code,400)
   with server.db() as c:c.execute('DELETE FROM attempts')
   accepted=self.c.post('/admin/api/updates',data={'password':'Disposable-Test-Password-01234','bundle':(io.BytesIO(b'signed-bundle'),'release.sau')},headers=headers,base_url='https://localhost')
   self.assertEqual(accepted.status_code,202);self.assertTrue(accepted.json['installed'])
   request=host.call_args_list[-1].args[0]
   self.assertEqual(request['action'],'update-install');self.assertRegex(request['name'],r'^[0-9a-f]{32}\.sau$')
   self.assertFalse((server.ROOT/'update-staging'/request['name']).exists())
  events=self.c.get('/admin/api/audit',base_url='https://localhost').json['events']
  self.assertTrue(any(row['action']=='appliance-update' and row['outcome']=='success' for row in events))
 def test_shutdown_requires_reauthentication_and_queues_host_action(self):
  csrf=self.login();headers={'X-CSRF-Token':csrf}
  with patch.object(server,'host_request',return_value={'queued':True,'notice':'Appliance shutdown queued.'}) as host:
   body={'confirmed':True,'password':'Disposable-Test-Password-01234'}
   r=self.c.post('/admin/api/operations/shutdown',json=body,headers=headers,base_url='https://localhost')
   self.assertEqual(r.status_code,202)
   host.assert_called_once_with({'action':'appliance-shutdown'})
  events=self.c.get('/admin/api/audit',base_url='https://localhost').json['events']
  self.assertEqual(events[0]['action'],'appliance-shutdown')
 def test_forward_proxy_requires_auth_and_reauthentication(self):
  self.assertEqual(self.c.get('/admin/api/forward-proxy').status_code,401)
  csrf=self.login()
  with patch.object(server,'host_request',return_value={'enabled':False,'client_cidrs':[],'allowed_domains':[]}) as host:
   self.assertEqual(self.c.get('/admin/api/forward-proxy',base_url='https://localhost').status_code,200)
   body={'enabled':True,'client_cidrs':['192.0.2.0/24'],'allowed_domains':[]}
   self.assertEqual(self.c.post('/admin/api/forward-proxy',json=body,headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,400)
   body['password']='Disposable-Test-Password-01234'
   self.assertEqual(self.c.post('/admin/api/forward-proxy',json=body,headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,200)
   self.assertEqual(host.call_args_list[-1].args[0]['action'],'forward-proxy-apply')
 def test_service_activity_requires_a_supported_service_filter(self):
  self.login()
  with patch.object(server,'host_request',return_value={'service':'kmip','lines':['accepted connection']}) as host:
   self.assertEqual(self.c.get('/admin/api/connections?service=unknown',base_url='https://localhost').status_code,400)
   host.assert_not_called()
   r=self.c.get('/admin/api/connections?service=kmip',base_url='https://localhost')
   self.assertEqual(r.status_code,200);self.assertEqual(r.json['service'],'kmip')
   host.assert_called_once_with({'action':'connection-logs','service':'kmip'})
 def test_certificate_requires_auth_csrf_and_reauthentication(self):
  self.assertEqual(self.c.get('/admin/api/certificates').status_code,401)
  csrf=self.login()
  with patch.object(server,'host_request',return_value={'csr':'PUBLIC CSR'}) as host:
   self.assertEqual(self.c.post('/admin/api/certificates',json={'operation':'csr'},base_url='https://localhost').status_code,403)
   self.assertEqual(self.c.post('/admin/api/certificates',json={'operation':'csr','password':'Wrong-Password-123456789'},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,400)
   host.assert_not_called()
   # Failed reauthentication is durable and throttles even a subsequent correct attempt.
   self.assertEqual(self.c.post('/admin/api/certificates',json={'operation':'csr','password':'Disposable-Test-Password-01234'},headers={'X-CSRF-Token':csrf},base_url='https://localhost').status_code,400)
   with server.db() as c:c.execute('DELETE FROM attempts')
   r=self.c.post('/admin/api/certificates',json={'operation':'csr','password':'Disposable-Test-Password-01234'},headers={'X-CSRF-Token':csrf},base_url='https://localhost');self.assertEqual(r.status_code,200)
   host.assert_called_once_with({'action':'certificate-csr'})
  events=self.c.get('/admin/api/audit',base_url='https://localhost').json['events']
  self.assertTrue(any(v['action']=='certificate-csr' for v in events));self.assertNotIn('Disposable-Test-Password',str(events))
 def test_kmip_client_certificate_requires_authentication(self):
  self.assertEqual(self.c.get('/admin/api/kmip/client-certificate').status_code,401)
  self.login()
  (server.ROOT/'vcenter-kmip-client.pem').write_text('-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n')
  r=self.c.get('/admin/api/kmip/client-certificate',base_url='https://localhost')
  self.assertEqual(r.status_code,200)
  self.assertTrue(r.json['certificate'].startswith('-----BEGIN CERTIFICATE-----'))
if __name__=='__main__':unittest.main()
