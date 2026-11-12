from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets, sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

root=Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
now=datetime.now(timezone.utc)
for generation in ('generation-1','generation-2'):
 out=root/generation;out.mkdir()
 ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
 ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable KMIP '+generation)])
 ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(ca_key,hashes.SHA256())
 (out/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
 for identity in ('server','client'):
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  cert=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,identity)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if identity=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(ca_key,hashes.SHA256())
  (out/(identity+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
  (out/(identity+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
  if identity=='server':
   password=secrets.token_urlsafe(32)
   (out/'server.p12').write_bytes(pkcs12.serialize_key_and_certificates(b'kms',key,cert,[ca],serialization.BestAvailableEncryption(password.encode())))
   (out/'kms.toml').write_text('[tls]\ntls_p12_file="/qualification/server.p12"\ntls_p12_password="'+password+'"\nclients_ca_cert_file="/qualification/ca.pem"\n[socket_server]\nsocket_server_start=true\nsocket_server_port=5696\nsocket_server_hostname="0.0.0.0"\n[http]\nhostname="127.0.0.1"\nport=9998\n[db]\ndatabase_type="sqlite"\nsqlite_path="/data"\n')
print(root)
