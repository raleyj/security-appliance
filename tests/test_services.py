import json,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
if os.name=='nt':sys.modules.setdefault('fcntl',SimpleNamespace(flock=lambda *args:None,LOCK_EX=1,LOCK_UN=8))
import service_control as s
class ServicesTests(unittest.TestCase):
 def test_no_arbitrary_service_or_operation(self):
  for name,operation in [('postgres;id','restart'),('postgres','exec'),('management','stop'),('proxy','stop'),('forward-proxy','stop')]:
   with self.assertRaises(ValueError):s.validate(name,operation)
 def test_database_dependency(self):
  with patch.object(s,'inspect',return_value={'Running':True}):
   for operation in ['stop','restart']:
    with self.assertRaises(ValueError):s.validate('postgres',operation)
 def test_keycloak_requires_database(self):
  with patch.object(s,'readiness',return_value=False):
   with self.assertRaises(ValueError):s.validate('keycloak','start')
 def test_start_job_has_fixed_command(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(s,'ROOT',Path(tmp)),patch.object(s,'run',return_value='') as run:
   result=s.stage('kmip','start');args=run.call_args.args
   self.assertEqual(args[-3:],('/opt/security-appliance/provisioning/service_control.py','--job',result['id']));self.assertEqual(result['state'],'queued')
   with self.assertRaises(ValueError):s.stage('kmip','start')
 def test_successful_functional_test_records_review(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(s,'ROOT',Path(tmp)),patch.object(s,'validate'),patch.object(s,'test_service',return_value='Functional check passed.'):
   task={'id':'fixed','service':'kmip','operation':'test','state':'queued','at':time.time()}
   (Path(tmp)/'service-job.json').write_text(json.dumps(task));s.job('fixed')
   reviewed=json.loads((Path(tmp)/'services-tested.json').read_text())
   self.assertEqual(reviewed['services'],['kmip'])
   history=s.test_history();self.assertEqual(len(history),1);self.assertEqual(history[0]['result'],'passed');self.assertEqual(history[0]['service'],'kmip')
 def test_test_history_is_bounded_and_sanitizes_failure(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(s,'ROOT',Path(tmp)):
   task={'service':'keycloak','state':'failed','finishedAt':time.time(),'result':'OIDC qualification client failed: token=secret'}
   for _ in range(50):s.record_test(task)
   history=s.test_history();self.assertEqual(len(history),48)
   self.assertNotIn('secret',json.dumps(history));self.assertEqual(history[-1]['reason'],'OIDC qualification client failed')
 def test_keycloak_qualification_uses_disposable_private_network_client(self):
  result=json.dumps({'login':True,'pkceInvalidVerifierRejected':True,'roleClaimEnforced':True,'logoutRevokedRefreshToken':True,'temporaryRealmRemoved':True})
  completed=__import__('subprocess').CompletedProcess([],0,stdout=result,stderr='')
  with tempfile.TemporaryDirectory() as tmp,patch.object(s,'ROOT',Path(tmp)),patch.object(s,'initialize_identity'),patch.object(s,'readiness',return_value=True),patch.object(s,'address',return_value='172.30.0.9'),patch.object(s.subprocess,'run',return_value=completed) as run:
   (Path(tmp)/'service-credentials.json').write_text('{}')
   self.assertEqual(s.test_service('keycloak'),'Functional check passed.')
   args=run.call_args.args[0]
   self.assertEqual(args[:5],['docker','run','--rm','--network','security-identity'])
   self.assertIn('--read-only',args);self.assertIn('ALL',args);self.assertIn('no-new-privileges:true',args)
   self.assertIn('KEYCLOAK_BASE=http://172.30.0.9:8080/identity',args)
   self.assertNotIn('--publish',args)
   evidence=json.loads((Path(tmp)/'oidc-qualification.json').read_text())
   self.assertTrue(evidence['pkceInvalidVerifierRejected'])
 def test_service_address_uses_network_membership(self):
  network=[{'Containers':{'abc':{'Name':'security-keycloak','IPv4Address':'172.30.0.9/16'}}}]
  with patch.object(s,'run',return_value=json.dumps(network)):
   self.assertEqual(s.address('keycloak','security-identity'),'172.30.0.9')
if __name__=='__main__':unittest.main()
