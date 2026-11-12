from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import secrets,json
root=Path(__file__).resolve().parents[1]/'build/kmip-qualification'
root.mkdir(parents=True,exist_ok=True)
if (root/'server.p12').exists():raise SystemExit('Qualification material already exists; refusing to replace it.')
now=datetime.now(timezone.utc)
ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable security qualification CA')])
ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(ca_key,hashes.SHA256())
(root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
for kind in ['server','client','other-client']:
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 subj=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,kind)])
 cert=x509.CertificateBuilder().subject_name(subj).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=7)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.DNSName('security-kmip-qualification')]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if kind=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(ca_key,hashes.SHA256())
 (root/(kind+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (root/(kind+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 if kind=='server':
  password=secrets.token_urlsafe(32)
  (root/'server.p12').write_bytes(pkcs12.serialize_key_and_certificates(b'kms',key,cert,[ca],serialization.BestAvailableEncryption(password.encode())))
  config=f'''[tls]\ntls_p12_file = "/qualification/server.p12"\ntls_p12_password = "{password}"\nclients_ca_cert_file = "/qualification/ca.pem"\n[socket_server]\nsocket_server_start = true\nsocket_server_port = 5696\nsocket_server_hostname = "0.0.0.0"\n[http]\nhostname = "127.0.0.1"\nport = 9998\n[db]\ndatabase_type = "sqlite"\nsqlite_path = "/data"\n'''
  (root/'kms.toml').write_text(config)
print('Disposable KMIP test certificates and private configuration generated.')
