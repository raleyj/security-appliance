"""Create first-boot auth state from precomputed deployment password verifiers."""
import json,os,secrets,sqlite3,sys
from pathlib import Path
sys.path.insert(0,'/app')
import server
from configuration import validate_config
p=Path('/bootstrap/auth.json');data=json.loads(p.read_text())
server.initialize(data['username'],secrets.token_urlsafe(48),validate_config(data['config']))
with server.db() as c:c.execute('UPDATE users SET salt=?,hash=? WHERE name=?',(bytes.fromhex(data['web']['salt']),bytes.fromhex(data['web']['hash']),data['username']))
print('Deployment authentication state initialized; no passwords logged.')
