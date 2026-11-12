import json,ssl,sys
from pathlib import Path
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
root=Path('/qualification')
def client(identity='client'):
 return ProxyKmipClient(hostname='localhost',port=5696,cert=str(root/(identity+'.pem')),key=str(root/(identity+'.key')),ca=str(root/'ca.pem'),ssl_version='PROTOCOL_TLSv1_2')
out={'scope':'isolated binary KMIP 1.x with disposable keys; not vCenter qualification'}
with client() as c:
 if '--read' in sys.argv:
  uid=(root/'key-id.txt').read_text(); key=c.get(uid);out.update(uid=uid,retrieved_after_restart=True)
 else:
  uid=c.create(enums.CryptographicAlgorithm.AES,256);(root/'key-id.txt').write_text(uid)
  c.activate(uid);key=c.get(uid);out.update(create=True,activate=True,get=True,uid=uid)
  try:
   with client('other-client') as other:other.get(uid)
   out['other_client_denied']=False
  except Exception:out['other_client_denied']=True
print(json.dumps(out))
(root/('read-result.json' if '--read' in sys.argv else 'result.json')).write_text(json.dumps(out,indent=2))

