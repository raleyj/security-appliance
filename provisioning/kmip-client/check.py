import json
from pathlib import Path
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
root=Path('/qualification');results=Path('/results')
def client(identity='client',host='security-kmip'):
 selected=identity or 'client'
 c=ProxyKmipClient(hostname=host,port=5696,cert=str(root/(selected+'.pem')),key=str(root/(selected+'.key')),ca=str(root/'ca.pem'),ssl_version='PROTOCOL_TLSv1_2')
 if identity is None:c.proxy.certfile=None;c.proxy.keyfile=None
 return c
with client() as c:
 path=results/'key-id.txt'
 if path.exists():uid=path.read_text()
 else:
  uid=c.create(enums.CryptographicAlgorithm.AES,256);c.activate(uid);path.write_text(uid)
 c.get(uid)
with client(host='security-proxy') as c:c.get(uid)
for identity in ['other-client',None]:
 connection=client(identity)
 try:
  with connection as c:
   if identity:c.get(uid)
   else:c.create(enums.CryptographicAlgorithm.AES,256)
 except Exception:continue
 raise RuntimeError('Unauthorized KMIP access was accepted.')
result={'get':True,'persistentKeyId':uid,'proxyGet':True,'otherClientDenied':True,'noCertificateDenied':True}
(results/'result.json').write_text(json.dumps(result));print(json.dumps(result))
