import json
from pathlib import Path
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
c=ProxyKmipClient(hostname='localhost',port=5696,cert='/qualification/client.pem',key='/qualification/client.key',ca='/qualification/ca.pem',ssl_version='PROTOCOL_TLSv1_2')
c.proxy.certfile=None;c.proxy.keyfile=None
rejected=False
try:
 with c:c.create(enums.CryptographicAlgorithm.AES,256)
except (OSError,EOFError,ValueError) as e:
 rejected=True
print(json.dumps({'noClientCertificateOperationRejected':rejected}))
assert rejected,'Unauthenticated key creation was not rejected.'
Path('/qualification/no-certificate-result.json').write_text(json.dumps({'noClientCertificateOperationRejected':True}))
