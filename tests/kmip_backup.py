import io,tarfile,secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
root=Path('/qualification')
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w') as t:t.add('/source',arcname='data')
key=secrets.token_bytes(32);nonce=secrets.token_bytes(12)
encrypted=nonce+AESGCM(key).encrypt(nonce,buf.getvalue(),b'lab-security-kmip-qualification')
(root/'backup.aesgcm').write_bytes(encrypted)
(root/'backup.key').write_bytes(key)
decoded=AESGCM(key).decrypt(encrypted[:12],encrypted[12:],b'lab-security-kmip-qualification')
with tarfile.open(fileobj=io.BytesIO(decoded)) as t:
 for member in t.getmembers():
  if member.name.startswith('/') or '..' in Path(member.name).parts or member.issym() or member.islnk():raise ValueError('Unsafe archive')
 t.extractall('/restore',filter='data')
print('Stopped-source backup encrypted and restored into a separate disposable volume.')
