import json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import certificates as c

class CertificateTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);c.ROOT=self.root
  (self.root/'tls').mkdir();(self.root/'config.json').write_text(json.dumps({'hostname':'security','domain':'example.test','sso_fqdn':'sso.example.test','kmip_fqdn':'kmip.example.test'}))
  (self.root/'nginx.conf').write_text('ssl_certificate /certs/server.crt; ssl_certificate_key /certs/server.key;')
  c.run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.root/'tls/server.key'),'-out',str(self.root/'tls/server.crt'),'-days','3','-subj','/CN=bootstrap')
  c.run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.root/'ca.key'),'-out',str(self.root/'ca.crt'),'-days','3','-subj','/CN=Disposable Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
  c.migrate()
 def signed(self,name='security.example.test',names=None):
  c.csr();names=names or [name,'sso.example.test','kmip.example.test'];ext=self.root/'extensions';ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+','.join('DNS:'+value for value in names)+'\n')
  c.run('openssl','x509','-req','-in',str(self.root/'tls/request/server.csr'),'-CA',str(self.root/'ca.crt'),'-CAkey',str(self.root/'ca.key'),'-CAcreateserial','-out',str(self.root/'signed.crt'),'-days','2','-sha256','-extfile',str(ext))
  return {'certificate':(self.root/'signed.crt').read_text(),'ca':(self.root/'ca.crt').read_text()}
 def test_csr_resume_and_private_key_permissions(self):
  first=c.csr();self.assertEqual(first,c.csr());self.assertEqual(first['dnsNames'],['security.example.test','sso.example.test','kmip.example.test']);self.assertNotIn('PRIVATE',str(first));self.assertEqual(os.stat(self.root/'tls/request/server.key').st_mode&0o777,0o600)
 def test_valid_import(self):
  result=c.activate(self.signed(),reload=lambda:None);self.assertTrue(result['enrolled']);self.assertFalse(result['csrPending']);self.assertFalse((self.root/'tls-transaction.json').exists())
 def test_wrong_hostname_rejected(self):
  with self.assertRaises(ValueError):c.activate(self.signed('wrong.example.test',['wrong.example.test','sso.example.test','kmip.example.test']),reload=lambda:None)
  self.assertEqual(os.readlink(self.root/'tls/current'),'initial')
 def test_missing_service_identity_rejected(self):
  with self.assertRaises(ValueError):c.activate(self.signed(names=['security.example.test','sso.example.test']),reload=lambda:None)
 def test_mismatched_key_rejected(self):
  data=self.signed();data['certificate']=(self.root/'tls/server.crt').read_text()
  with self.assertRaises(ValueError):c.activate(data,reload=lambda:None)
 def test_private_key_upload_rejected(self):
  data=self.signed();data['ca']=(self.root/'ca.key').read_text()
  with self.assertRaises(ValueError):c.activate(data,reload=lambda:None)
 def test_failed_reload_restores_previous(self):
  calls=[]
  def reload():
   calls.append(1)
   if len(calls)==1:raise ValueError('Injected reload failure')
  with self.assertRaises(ValueError):c.activate(self.signed(),reload=reload)
  self.assertEqual(os.readlink(self.root/'tls/current'),'initial');self.assertEqual(len(calls),2);self.assertTrue((self.root/'tls/request').exists())
 def test_interrupted_activation_recovers(self):
  (self.root/'tls-transaction.json').write_text(json.dumps({'previous':'initial'}));c.recover();self.assertEqual(os.readlink(self.root/'tls/current'),'initial');self.assertFalse((self.root/'tls-transaction.json').exists())
 def test_unknown_ca_rejected(self):
  data=self.signed();data['ca']=(self.root/'tls/server.crt').read_text()
  with self.assertRaises(ValueError):c.activate(data,reload=lambda:None)
 def test_leaf_cannot_be_used_as_trust_anchor(self):
  data=self.signed();data['ca']=data['certificate']
  with self.assertRaises(ValueError):c.activate(data,reload=lambda:None)

if __name__=='__main__':unittest.main()
