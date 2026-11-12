"""Local appliance management. Auth state is independent of Keycloak."""
import hashlib, hmac, ipaddress, json, os, re, secrets, sqlite3, stat, time
import socket
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, Response
from configuration import validate_config, validate_timezone

ROOT=Path(os.environ.get('SECURITY_STATE','/var/lib/security-appliance/management'))
NATIVE_VIEWER_ROLES=True
app=Flask(__name__,static_folder=None)
app.config['MAX_CONTENT_LENGTH']=32*1024*1024

def db():
    c=sqlite3.connect(ROOT/'management.sqlite',timeout=10);c.row_factory=sqlite3.Row
    return c

def ensure_policy_schema():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS user_roles(name TEXT PRIMARY KEY,role TEXT NOT NULL CHECK(role IN ('administrator','viewer')))")
        c.execute('CREATE TABLE IF NOT EXISTS account_state(name TEXT PRIMARY KEY,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)))')
        c.execute('CREATE TABLE IF NOT EXISTS session_policy(id INTEGER PRIMARY KEY CHECK(id=1),idle_seconds INTEGER NOT NULL)')
        c.execute('INSERT OR IGNORE INTO session_policy VALUES(1,900)')

def idle_seconds(c):
    row=c.execute('SELECT idle_seconds FROM session_policy WHERE id=1').fetchone()
    return row['idle_seconds'] if row else 900

def user_enabled(c,username):
    row=c.execute('SELECT enabled FROM account_state WHERE name=?',(username,)).fetchone()
    return row is None or bool(row['enabled'])

def account_role(c,username):
    row=c.execute('SELECT role FROM user_roles WHERE name=?',(username,)).fetchone()
    return row['role'] if row else 'administrator'

VIEWER_READ_PATHS=frozenset(('/admin/api/auth','/admin/api/health','/admin/api/services',
                           '/admin/api/operations/status','/admin/api/certificates','/admin/api/storage'))

def viewer_allowed(method,path):
    return (method=='GET' and path in VIEWER_READ_PATHS) or (method=='POST' and path=='/admin/api/logout')

def pw_hash(password,salt):return hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=64)
def password_policy(password):
    if not isinstance(password,str) or not 15<=len(password)<=256 or any(ord(x)<32 or ord(x)==127 for x in password):raise ValueError('Password must be 15–256 characters without control characters.')

def initialize(username,password,config):
    password_policy(password)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',username):raise ValueError('Invalid administrator username.')
    config=validate_config(config)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with db() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,salt BLOB,hash BLOB);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,username TEXT,csrf TEXT,created REAL,last REAL);
        CREATE TABLE IF NOT EXISTS attempts(source TEXT PRIMARY KEY,failures INTEGER,not_before REAL);
        CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT,revision INTEGER,completed INTEGER);
        CREATE TABLE IF NOT EXISTS audit(at REAL,actor TEXT,action TEXT,outcome TEXT);''')
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]:raise ValueError('Already initialized; use console recovery.')
        salt=secrets.token_bytes(16);c.execute('INSERT INTO users VALUES(?,?,?)',(username,salt,pw_hash(password,salt)))
        c.execute('INSERT INTO settings VALUES(1,?,1,0)',(json.dumps(config),))
    os.chmod(ROOT/'management.sqlite',0o600)
    ensure_policy_schema()

def audit(c,actor,action,outcome):c.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),actor,action,outcome))

def build_auth_context():
    """Return a bounded build-only login context for an approved source, or None."""
    if os.environ.get('SECURITY_BUILD_AUTH_BYPASS')!='1':return None
    marker=ROOT/'build-auth-bypass.json'
    try:
        if os.name!='nt' and marker.stat().st_mode&(stat.S_IWGRP|stat.S_IWOTH):return None
        value=json.loads(marker.read_text())
        username=value['username'];csrf=value['csrf'];expires=float(value['expires'])
        allowed=[ipaddress.IPv4Network(row,strict=True) for row in value['allowed_cidrs']]
        source_text=request.headers.get('X-Forwarded-For',request.remote_addr or '').strip()
        if ',' in source_text:return None
        source=ipaddress.IPv4Address(source_text)
        if expires<=time.time() or not 32<=len(csrf)<=256:return None
        if not allowed or any(network.prefixlen==0 for network in allowed):return None
        with db() as c:
            cfg=json.loads(c.execute('SELECT config FROM settings WHERE id=1').fetchone()['config'])
            users={row['name'] for row in c.execute('SELECT name FROM users')}
            enabled=user_enabled(c,username) and account_role(c,username)=='administrator'
        admins=[ipaddress.IPv4Network(row,strict=True) for row in cfg['admin_cidrs']]
        if username not in users or not enabled or any(not any(network.subnet_of(admin) for admin in admins) for network in allowed):return None
        if not any(source in network for network in allowed):return None
        return {'username':username,'csrf':csrf,'expires':expires}
    except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError):return None

@app.before_request
def guard():
    if not (ROOT/'management.sqlite').exists():return jsonify(error='Appliance bootstrap is incomplete.'),503
    ensure_policy_schema()
    if request.path.startswith('/admin/api/') and request.path not in ('/admin/api/login','/admin/api/auth'):
        build=build_auth_context()
        if build:
            if request.method!='GET' and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),build['csrf']):return jsonify(error='Request verification failed.'),403
            request.appliance_user=build['username'];request.appliance_token='';request.appliance_build_auth=True
            return None
        token=hashlib.sha256(request.cookies.get('security_session','').encode()).hexdigest()
        with db() as c:
            s=c.execute('SELECT * FROM sessions WHERE token=?',(token,)).fetchone()
            if not s or not user_enabled(c,s['username']) or time.time()-s['last']>idle_seconds(c) or time.time()-s['created']>28800:
                c.execute('DELETE FROM sessions WHERE token=?',(token,));return jsonify(error='Sign in required.'),401
            if request.method!='GET' and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),s['csrf']):return jsonify(error='Request verification failed.'),403
            role=account_role(c,s['username'])
            if role=='viewer' and not viewer_allowed(request.method,request.path):return jsonify(error='Viewer access does not permit this operation.'),403
            request.appliance_role=role
            request.appliance_user=s['username'];request.appliance_token=token
            c.execute('UPDATE sessions SET last=? WHERE token=?',(time.time(),token))

@app.after_request
def headers(response):
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'Referrer-Policy':'no-referrer'})
    return response

@app.errorhandler(ValueError)
def invalid(error):return jsonify(error=str(error)),400
@app.errorhandler(400)
def bad(error):return jsonify(error='Invalid request.'),400

@app.get('/admin/api/auth')
def auth():
    build=build_auth_context()
    if build:return jsonify(authenticated=True,username=build['username'],csrf=build['csrf'],buildMode=True,expiresAt=build['expires'])
    token=hashlib.sha256(request.cookies.get('security_session','').encode()).hexdigest()
    with db() as c:
        s=c.execute('SELECT * FROM sessions WHERE token=?',(token,)).fetchone()
        if not s or not user_enabled(c,s['username']) or time.time()-s['last']>idle_seconds(c) or time.time()-s['created']>28800:return jsonify(authenticated=False)
        return jsonify(authenticated=True,username=s['username'],csrf=s['csrf'],role=account_role(c,s['username']))

@app.post('/admin/api/login')
def login():
    if request.headers.get('X-Requested-With')!='SecurityAppliance':return jsonify(error='Request verification failed.'),403
    data=request.get_json(); username=data.get('username','');password=data.get('password','')
    if not isinstance(username,str) or not isinstance(password,str) or len(username)>64 or len(password)>256:raise ValueError('Invalid credentials.')
    source=request.remote_addr;now=time.time()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        a=c.execute('SELECT * FROM attempts WHERE source=?',(source,)).fetchone()
        if a and a['not_before']>now:return jsonify(error='Try again later.'),429
        u=c.execute('SELECT * FROM users WHERE name=?',(username,)).fetchone()
        candidate=pw_hash(password,u['salt'] if u else b'0'*16)
        if not u or not user_enabled(c,username) or not hmac.compare_digest(candidate,u['hash']):
            failures=min((a['failures'] if a else 0)+1,10)
            c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)',(source,failures,now+min(300,2**failures)))
            audit(c,username,'login','failed');return jsonify(error='Invalid credentials.'),401
        c.execute('DELETE FROM attempts WHERE source=?',(source,));token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
        c.execute('DELETE FROM sessions WHERE last<? OR created<?',(now-idle_seconds(c),now-28800))
        c.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),username,csrf,now,now));audit(c,username,'login','success')
    with db() as c:role=account_role(c,username)
    response=jsonify(authenticated=True,csrf=csrf,username=username,role=role)
    response.set_cookie('security_session',token,secure=True,httponly=True,samesite='Strict',path='/admin/',max_age=28800)
    return response

@app.post('/admin/api/logout')
def logout():
    if request.appliance_token:
        with db() as c:c.execute('DELETE FROM sessions WHERE token=?',(request.appliance_token,))
    r=jsonify(ok=True);r.delete_cookie('security_session',path='/admin/');return r

@app.get('/admin/api/config')
def config():
    with db() as c:s=c.execute('SELECT * FROM settings WHERE id=1').fetchone()
    return jsonify(config=json.loads(s['config']),revision=s['revision'],completed=bool(s['completed']))

@app.post('/admin/api/setup/preview')
def preview():
    candidate=dict(request.get_json()['config'])
    with db() as c:current=json.loads(c.execute('SELECT config FROM settings WHERE id=1').fetchone()['config'])
    if 'kmip_client_cidrs' not in candidate:candidate['kmip_client_cidrs']=current.get('kmip_client_cidrs',[])
    return jsonify(config=validate_config(candidate),notice='Review only. Network changes require the host transaction helper; no host changes have been applied.')

@app.post('/admin/api/setup/save')
def save():
    body=request.get_json();candidate=dict(body['config'])
    with db() as c:
        c.execute('BEGIN IMMEDIATE');s=c.execute('SELECT * FROM settings WHERE id=1').fetchone()
        if body.get('revision')!=s['revision']:return jsonify(error='Configuration changed; reload before saving.'),409
        if 'kmip_client_cidrs' not in candidate:candidate['kmip_client_cidrs']=json.loads(s['config']).get('kmip_client_cidrs',[])
        cfg=validate_config(candidate)
        c.execute('UPDATE settings SET config=?,revision=revision+1 WHERE id=1',(json.dumps(cfg),));audit(c,request.appliance_user,'setup-draft','saved')
        revision=s['revision']+1
    return jsonify(ok=True,revision=revision,applied=False,notice='Configuration saved. Apply it to begin the protected network transaction.')

@app.route('/admin/api/timezone',methods=['GET','POST'])
def timezone():
    if request.method=='GET':
        try:return jsonify(host_request({'action':'timezone-status'}))
        except (OSError,ValueError):return jsonify(error='Appliance timezone is temporarily unavailable.'),503
    body=request.get_json() or {};reauthenticate(body);zone=validate_timezone(body.get('timezone'))
    result=host_request({'action':'timezone-apply','timezone':zone})
    with db() as c:audit(c,request.appliance_user,'timezone-apply','success')
    return jsonify(result)

def reauthenticate(body):
    password=body.get('password','')
    password_policy(password)
    key='reauth:'+request.appliance_user;now=time.time()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        attempt=c.execute('SELECT * FROM attempts WHERE source=?',(key,)).fetchone()
        if attempt and attempt['not_before']>now:raise ValueError('Try administrator verification again later.')
        u=c.execute('SELECT * FROM users WHERE name=?',(request.appliance_user,)).fetchone()
        valid=bool(u and user_enabled(c,request.appliance_user) and hmac.compare_digest(pw_hash(password,u['salt']),u['hash']))
        if valid:c.execute('DELETE FROM attempts WHERE source=?',(key,))
        else:
            failures=min((attempt['failures'] if attempt else 0)+1,10)
            c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)',(key,failures,now+min(300,2**failures)))
            audit(c,request.appliance_user,'reauthentication','failed')
    if not valid:raise ValueError('Administrator password verification failed.')

@app.get('/admin/api/audit')
def audit_history():
    with db() as c:rows=c.execute('SELECT at,actor,action,outcome FROM audit ORDER BY rowid DESC LIMIT 100').fetchall()
    return jsonify(events=[dict(row) for row in rows])

@app.post('/admin/api/account/password')
def change_password():
    body=request.get_json();reauthenticate(body)
    new=body.get('new_password','');password_policy(new)
    if new==body['password']:raise ValueError('Choose a different password.')
    reset_password(request.appliance_user,new,actor=request.appliance_user)
    response=jsonify(changed=True,notice='Password changed. All sessions have been signed out.')
    response.delete_cookie('security_session',path='/admin/');return response

@app.route('/admin/api/accounts',methods=['GET','POST'])
def accounts():
    if request.method=='GET':
        now=time.time()
        with db() as c:
            rows=c.execute('SELECT name FROM users ORDER BY name').fetchall()
            accounts=[]
            for row in rows:
                name=row['name']
                last=c.execute("SELECT MAX(at) AS at FROM audit WHERE actor=? AND action='login' AND outcome='success'",(name,)).fetchone()['at']
                active=c.execute('SELECT COUNT(*) AS count FROM sessions WHERE username=? AND last>? AND created>?',(name,now-idle_seconds(c),now-28800)).fetchone()['count']
                accounts.append({'username':name,'current':name==request.appliance_user,'enabled':user_enabled(c,name),'role':account_role(c,name),'lastSuccessfulLogin':last,'activeSessions':active})
        return jsonify(accounts=accounts)
    body=request.get_json() or {};reauthenticate(body);operation=body.get('operation');username=body.get('username','')
    if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',username):raise ValueError('Invalid administrator username.')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if operation=='create':
            new_password=body.get('new_password','');password_policy(new_password)
            role=body.get('role','administrator')
            if role not in ('administrator','viewer'):raise ValueError('Invalid management role.')
            if c.execute('SELECT 1 FROM users WHERE name=?',(username,)).fetchone():return jsonify(error='Administrator already exists.'),409
            salt=secrets.token_bytes(16);c.execute('INSERT INTO users VALUES(?,?,?)',(username,salt,pw_hash(new_password,salt)));c.execute('INSERT INTO account_state VALUES(?,1)',(username,));audit(c,request.appliance_user,'administrator-create','success')
            c.execute('INSERT INTO user_roles VALUES(?,?)',(username,role))
        elif operation=='delete':
            if username==request.appliance_user:return jsonify(error='The signed-in administrator cannot be removed.'),409
            if account_role(c,username)=='administrator' and sum(account_role(c,r['name'])=='administrator' and user_enabled(c,r['name']) for r in c.execute('SELECT name FROM users'))<=1:return jsonify(error='The final administrator cannot be removed.'),409
            if not c.execute('DELETE FROM users WHERE name=?',(username,)).rowcount:return jsonify(error='Administrator does not exist.'),404
            c.execute('DELETE FROM sessions WHERE username=?',(username,));c.execute('DELETE FROM account_state WHERE name=?',(username,));audit(c,request.appliance_user,'administrator-delete','success')
            c.execute('DELETE FROM user_roles WHERE name=?',(username,))
        elif operation in ('enable','disable'):
            if not c.execute('SELECT 1 FROM users WHERE name=?',(username,)).fetchone():return jsonify(error='Administrator does not exist.'),404
            if operation=='disable':
                if username==request.appliance_user:return jsonify(error='The signed-in administrator cannot be disabled.'),409
                enabled_count=sum(user_enabled(c,row['name']) and account_role(c,row['name'])=='administrator' for row in c.execute('SELECT name FROM users'))
                if account_role(c,username)=='administrator' and enabled_count<=1:return jsonify(error='The final enabled administrator cannot be disabled.'),409
            c.execute('INSERT INTO account_state(name,enabled) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled',(username,int(operation=='enable')))
            if operation=='disable':c.execute('DELETE FROM sessions WHERE username=?',(username,))
            audit(c,request.appliance_user,'administrator-'+operation,'success')
        elif operation=='revoke-sessions':
            if not c.execute('SELECT 1 FROM users WHERE name=?',(username,)).fetchone():return jsonify(error='Administrator does not exist.'),404
            c.execute('DELETE FROM sessions WHERE username=?',(username,));audit(c,request.appliance_user,'administrator-sessions-revoked','success')
        else:raise ValueError('Unsupported administrator operation.')
    return jsonify(ok=True)

@app.route('/admin/api/session-policy',methods=['GET','POST'])
def session_policy():
    if request.method=='GET':
        with db() as c:return jsonify(idleSeconds=idle_seconds(c),minIdleSeconds=300,maxIdleSeconds=3600,absoluteSeconds=28800)
    body=request.get_json() or {};reauthenticate(body)
    value=body.get('idleSeconds')
    if type(value) is not int or not 300<=value<=3600:raise ValueError('Idle timeout must be between 5 and 60 minutes.')
    with db() as c:
        c.execute('UPDATE session_policy SET idle_seconds=? WHERE id=1',(value,))
        audit(c,request.appliance_user,'session-idle-policy','success')
    return jsonify(idleSeconds=value,minIdleSeconds=300,maxIdleSeconds=3600,absoluteSeconds=28800)

@app.get('/admin/api/operations/status')
def operations_status():
    try:return jsonify(host_request({'action':'appliance-status'}))
    except (OSError,ValueError):return jsonify(error='Appliance status is temporarily unavailable.'),503

@app.get('/admin/api/storage')
def storage_report():
    try:return jsonify(host_request({'action':'storage-report'}))
    except (OSError,ValueError):return jsonify(error='Storage reporting is temporarily unavailable.'),503

@app.get('/admin/api/diagnostics')
def diagnostics():
    try:return jsonify(host_request({'action':'diagnostics'}))
    except (OSError,ValueError):return jsonify(error='Appliance diagnostics are temporarily unavailable.'),503

@app.get('/admin/api/help.md')
def help_markdown():
    try:version=host_request({'action':'update-status'}).get('version','unknown')
    except (OSError,ValueError):version='unknown'
    content=(Path(__file__).parent/'help.md').read_text().replace('{{VERSION}}',str(version)[:64])
    return Response(content,mimetype='text/markdown',headers={'Content-Disposition':'attachment; filename="security-appliance-help.md"'})

@app.post('/admin/api/operations/reboot')
def operations_reboot():
    body=request.get_json() or {};reauthenticate(body)
    if body.get('confirmed') is not True:raise ValueError('Confirm the appliance restart.')
    result=host_request({'action':'appliance-reboot'})
    with db() as c:audit(c,request.appliance_user,'appliance-reboot','queued')
    return jsonify(result),202

@app.post('/admin/api/operations/shutdown')
def operations_shutdown():
    body=request.get_json() or {};reauthenticate(body)
    if body.get('confirmed') is not True:raise ValueError('Confirm the appliance shutdown.')
    result=host_request({'action':'appliance-shutdown'})
    with db() as c:audit(c,request.appliance_user,'appliance-shutdown','queued')
    return jsonify(result),202

@app.get('/admin/api/support-bundle')
def support_bundle():
    bundle={'generatedAt':time.time(),'appliance':'Lab Security Appliance'}
    try:bundle['operations']=host_request({'action':'appliance-status'})
    except (OSError,ValueError):bundle['operations']={'available':False}
    try:bundle['services']=host_request({'action':'services-status'})
    except (OSError,ValueError):bundle['services']={'available':False}
    bundle['serviceActivity']={}
    for service in ('management','proxy','forward-proxy','postgres','keycloak','kmip'):
        try:bundle['serviceActivity'][service]=host_request({'action':'connection-logs','service':service})
        except (OSError,ValueError):bundle['serviceActivity'][service]={'available':False}
    with db() as c:bundle['audit']=[dict(row) for row in c.execute('SELECT at,actor,action,outcome FROM audit ORDER BY rowid DESC LIMIT 100').fetchall()]
    payload=json.dumps(bundle,indent=2)+'\n'
    return Response(payload,mimetype='application/json',headers={'Content-Disposition':'attachment; filename="security-appliance-support.json"'})

@app.route('/admin/api/updates',methods=['GET','POST'])
def appliance_updates():
    if request.method=='GET':
        try:return jsonify(host_request({'action':'update-status'}))
        except (OSError,ValueError):return jsonify(error='Appliance update status is temporarily unavailable.'),503
    reauthenticate(request.form)
    upload=request.files.get('bundle')
    if not upload or not upload.filename.lower().endswith('.sau'):
        raise ValueError('Select a signed appliance update bundle.')
    staging=ROOT/'update-staging';staging.mkdir(parents=True,exist_ok=True,mode=0o700)
    name=secrets.token_hex(16)+'.sau';path=staging/name
    try:
        upload.save(path);os.chmod(path,0o600)
        if path.stat().st_size>32*1024*1024:raise ValueError('Appliance update bundle is too large.')
        result=host_request({'action':'update-install','name':name})
    except (OSError,ValueError):
        with db() as c:audit(c,request.appliance_user,'appliance-update','failed')
        return jsonify(error='The signed update was rejected or rolled back.'),400
    finally:path.unlink(missing_ok=True)
    with db() as c:audit(c,request.appliance_user,'appliance-update','success')
    return jsonify(result),202

@app.post('/admin/api/updates/restore')
def appliance_restore():
    body=request.get_json() or {};reauthenticate(body)
    if body.get('confirmed') is not True:raise ValueError('Confirm restoration of the prior signed release.')
    try:result=host_request({'action':'update-restore'})
    except (OSError,ValueError):
        with db() as c:audit(c,request.appliance_user,'appliance-restore','failed')
        return jsonify(error='Prior release restoration failed; review appliance health.'),409
    with db() as c:audit(c,request.appliance_user,'appliance-restore','success')
    return jsonify(result),202

@app.route('/admin/api/alert-delivery',methods=['GET','POST'])
def alert_delivery():
    if request.method=='GET':
        try:return jsonify(host_request({'action':'alert-delivery-status'}))
        except (OSError,ValueError):return jsonify(error='Alert delivery status is unavailable.'),503
    body=request.get_json() or {};reauthenticate(body)
    if body.get('operation')=='test':
        try:result=host_request({'action':'alert-delivery-test'})
        except (OSError,ValueError):return jsonify(error='The test alert could not be delivered.'),502
        with db() as c:audit(c,request.appliance_user,'alert-delivery-test','success' if result.get('lastResult')!='delivery failed' else 'failed')
        return jsonify(result),200 if result.get('lastResult')!='delivery failed' else 502
    try:result=host_request({'action':'alert-delivery-apply','config':body.get('config')})
    except (OSError,ValueError):return jsonify(error='Alert destination was rejected.'),400
    with db() as c:audit(c,request.appliance_user,'alert-delivery-config','success')
    return jsonify(result)

@app.route('/admin/api/certificates',methods=['GET','POST'])
def certificates():
    if request.method=='GET':data={'action':'certificate-status'}
    else:
        body=request.get_json();reauthenticate(body)
        operation=body.get('operation')
        if operation not in ('csr','import','discard'):raise ValueError('Unsupported certificate operation.')
        data={'action':'certificate-'+operation}
        if operation=='import':
            data.update({k:body.get(k,'') for k in ('certificate','ca','intermediates')})
    try:result=host_request(data)
    except (OSError,ValueError):
        if request.method=='POST':
            with db() as c:audit(c,request.appliance_user,data['action'],'failed')
        return jsonify(error='Certificate operation failed. Check the applied hostname, CSR, certificate chain and host status.'),400
    if request.method=='POST':
        with db() as c:audit(c,request.appliance_user,data['action'],'success')
    return jsonify(result)

@app.get('/admin/api/trust-inventory')
def trust_inventory():
    try:return jsonify(host_request({'action':'trust-inventory'}))
    except (OSError,ValueError):return jsonify(error='Certificate inventory is temporarily unavailable.'),503

@app.get('/admin/api/trust-chain/<kind>')
def trust_chain(kind):
    if kind not in ('management','kmip'):raise ValueError('Unsupported public chain.')
    try:result=host_request({'action':'public-certificate-chain','kind':kind})
    except (OSError,ValueError):return jsonify(error='Public certificate chain is unavailable.'),503
    return Response(result['pem'],mimetype='application/x-pem-file',headers={'Content-Disposition':f'attachment; filename="security-{kind}-chain.pem"'})

@app.get('/admin/api/kmip/client-certificate')
def kmip_client_certificate():
    try:value=(ROOT/'vcenter-kmip-client.pem').read_text()
    except OSError:return jsonify(error='The enrolled KMIP client certificate is unavailable.'),404
    if len(value)>8192 or not value.startswith('-----BEGIN CERTIFICATE-----') or not value.rstrip().endswith('-----END CERTIFICATE-----'):return jsonify(error='The enrolled KMIP client certificate is unavailable.'),404
    return jsonify(certificate=value)

@app.get('/admin/api/kmip/trust')
def kmip_trust_public():
    try:return jsonify(host_request({'action':'kmip-trust-public'}))
    except (OSError,ValueError):return jsonify(error='KMIP public trust material is unavailable.'),503

@app.post('/admin/api/kmip/sign-client')
def kmip_sign_client():
    body=request.get_json() or {};reauthenticate(body)
    data={'action':'kmip-sign-client','csr':body.get('csr'),'clientName':body.get('clientName')}
    try:result=host_request(data)
    except (OSError,ValueError):
        with db() as c:audit(c,request.appliance_user,'kmip-client-enrollment','failed')
        return jsonify(error='KMIP client CSR was rejected or signing failed.'),400
    with db() as c:audit(c,request.appliance_user,'kmip-client-enrollment','success')
    return jsonify(result)

def host_request(data):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(100);s.connect('/run/security-appliance/control.sock');s.sendall((json.dumps(data)+'\n').encode());raw=b''
        while not raw.endswith(b'\n') and len(raw)<32768:
            part=s.recv(4096)
            if not part:break
            raw+=part
    result=json.loads(raw)
    if not result['ok']:raise ValueError(result['error'])
    return result['result']

@app.post('/admin/api/setup/apply')
def apply_network():
    body=request.get_json();reauthenticate(body)
    with db() as c:row=c.execute('SELECT * FROM settings WHERE id=1').fetchone()
    if body.get('revision')!=row['revision']:return jsonify(error='Configuration changed; reload.'),409
    cfg=validate_config(json.loads(row['config']))
    source=request.headers.get('X-Forwarded-For','')
    try:result=host_request({'action':'apply','config':cfg,'source':source})
    except OSError:return jsonify(error='Host control is unavailable; nothing has been confirmed.'),503
    with db() as c:audit(c,request.appliance_user,'network-apply','pending-confirmation')
    return jsonify(result)

@app.post('/admin/api/setup/confirm')
def confirm_network():
    body=request.get_json();reauthenticate(body)
    result=host_request({'action':'confirm','token':body.get('token','')})
    with db() as c:audit(c,request.appliance_user,'network-confirm','success')
    return jsonify(result)

@app.get('/admin/api/setup/network-status')
def network_status():
    try:return jsonify(host_request({'action':'status'}))
    except OSError:return jsonify(error='Host control unavailable.'),503

def preflight_result():
    health=host_request({'action':'appliance-status'})
    service_state=host_request({'action':'services-status'})
    trust=host_request({'action':'trust-inventory'})
    with db() as c:
        config=json.loads(c.execute('SELECT config FROM settings WHERE id=1').fetchone()['config'])
    cert=health.get('certificate') or {}
    rows={item.get('service'):item for item in service_state.get('services',[])}
    enrolled_clients=any(row.get('role')=='KMIP client' and row.get('available') and row.get('trustStatus')=='trusted' and (row.get('daysRemaining') or 0)>0 for row in trust.get('certificates',[]))
    def item(code,label,passed,required,page,detail):
        return {'code':code,'label':label,'state':'pass' if passed else ('blocked' if required else 'warning'),'required':required,'page':page,'detail':detail}
    checks=[
        item('dns','Appliance DNS',health.get('dnsHealthy'),True,'configform','Resolve every configured appliance name using the active DNS servers.'),
        item('ntp','Time synchronization',health.get('ntpHealthy'),True,'configform','Synchronize with an approved NTP source.'),
        item('tls','Management HTTPS trust',cert.get('enrolled') and (cert.get('daysRemaining') or 0)>=30,True,'certificate-panel','Install a trusted certificate with at least 30 days remaining.'),
        item('firewall','Firewall enforcement',health.get('firewallActive'),True,'overview-panel','The appliance firewall must be active.'),
        item('services','Service readiness',health.get('servicesHealthy'),True,'overview-panel','All required containers must be ready.'),
        item('oidc','Generic OIDC qualification',service_state.get('identityInitialized') and rows.get('keycloak',{}).get('ready') and service_state.get('oidcQualificationPassed'),True,'keycloak-panel','Pass login, PKCE rejection, role enforcement, logout and temporary-realm cleanup.'),
        item('kmip','KMIP consumer enrollment',rows.get('kmip',{}).get('ready') and bool(config.get('kmip_client_cidrs')) and enrolled_clients,False,'kmip-panel','Enroll a valid, trusted mutual-TLS client certificate and approve its source network before client access.'),
        item('proxy','Reverse-proxy policy',rows.get('proxy',{}).get('ready'),True,'proxy-panel','The proxy must be ready; optional external routes can be configured later.'),
    ]
    return {'checkedAt':time.time(),'checks':checks,'blocked':sum(row['state']=='blocked' for row in checks),'warnings':sum(row['state']=='warning' for row in checks),'readyToComplete':not any(row['state']=='blocked' for row in checks)}

@app.get('/admin/api/setup/preflight')
def setup_preflight():
    try:return jsonify(preflight_result())
    except (OSError,ValueError):return jsonify(error='Preflight status is temporarily unavailable.'),503

@app.post('/admin/api/setup/complete')
def complete_setup():
    body=request.get_json() or {}
    if body.get('acknowledged') is not True:return jsonify(error='Confirm that first deployment setup is complete.'),400
    with db() as c:row=c.execute('SELECT * FROM settings WHERE id=1').fetchone()
    cfg=validate_config(json.loads(row['config']))
    status=host_request({'action':'status'})
    digest=hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()
    if status['pending'] or not status['confirmed'] or status['confirmed']['digest']!=digest:return jsonify(error='Apply and confirm the current settings first.'),409
    # Refresh the host-owned readiness evidence before evaluating completion.
    try:host_request({'action':'integration-readiness'})
    except (OSError,ValueError):return jsonify(error='Integration readiness is temporarily unavailable.'),503
    # Full setup remains gated by host-verified service and TLS integration.
    readiness=ROOT/'integration-ready.json'
    if not readiness.exists():return jsonify(error='Network settings are confirmed. Certificate enrollment and service readiness checks remain pending.'),409
    ready=json.loads(readiness.read_text())
    if ready.get('configDigest')!=digest or not ready.get('trustedManagementTls') or not ready.get('servicesReviewed'):return jsonify(error='Integration readiness has not been verified for these settings.'),409
    if not preflight_result()['readyToComplete']:return jsonify(error='Resolve the blocked first-deployment preflight checks before completion.'),409
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        current=c.execute('SELECT revision FROM settings WHERE id=1').fetchone()[0]
        if current!=row['revision']:return jsonify(error='Configuration changed; review again.'),409
        c.execute('UPDATE settings SET completed=1 WHERE id=1');audit(c,request.appliance_user,'setup-complete','success')
    return jsonify(completed=True)

@app.get('/admin/api/health')
def health():
    # Guest facts are written by a narrow host collector, not generated by the web app.
    facts=ROOT/'host-health.json'
    try:value=json.loads(facts.read_text())
    except (OSError,ValueError):value={'ready':False,'reason':'Host health is unavailable'}
    try:states=host_request({'action':'services-status'});services={r['service']:('ready' if r['ready'] else r['state']) for r in states['services']}
    except (OSError,ValueError):services={'keycloak':'status unavailable','kmip':'status unavailable'}
    return jsonify(management='ready',host=value,services=services)

@app.route('/admin/api/services',methods=['GET','POST'])
def manage_services():
    if request.method=='GET':return jsonify(host_request({'action':'services-status'}))
    body=request.get_json();reauthenticate(body)
    if body.get('service') not in ('management','proxy','forward-proxy','postgres','keycloak','kmip') or body.get('operation') not in ('start','stop','restart','test'):raise ValueError('Unsupported service operation.')
    result=host_request({'action':'services-action','service':body['service'],'operation':body['operation']})
    with db() as c:audit(c,request.appliance_user,'service-'+body['service']+'-'+body['operation'],'queued')
    return jsonify(result),202

@app.route('/admin/api/forward-proxy',methods=['GET','POST'])
def forward_proxy():
    if request.method=='GET':return jsonify(host_request({'action':'forward-proxy-status'}))
    body=request.get_json() or {};reauthenticate(body)
    config={k:body.get(k) for k in ('enabled','client_cidrs','allowed_domains')}
    try:result=host_request({'action':'forward-proxy-apply','config':config})
    except (OSError,ValueError):
        with db() as c:audit(c,request.appliance_user,'forward-proxy-apply','failed')
        return jsonify(error='Forward proxy policy was rejected or could not be applied.'),400
    with db() as c:audit(c,request.appliance_user,'forward-proxy-apply','success')
    return jsonify(result)

@app.get('/admin/api/connections')
def connections():
    service=request.args.get('service','')
    if service not in ('management','proxy','forward-proxy','postgres','keycloak','kmip'):return jsonify(error='Select a supported appliance service.'),400
    try:return jsonify(host_request({'action':'connection-logs','service':service}))
    except (OSError,ValueError):return jsonify(error='Service activity is temporarily unavailable.'),503

@app.get('/admin/')
@app.get('/admin/setup/')
def index():return send_from_directory(Path(__file__).parent/'static','index.html')
@app.get('/admin/assets/<path:name>')
def assets(name):return send_from_directory(Path(__file__).parent/'static',name)

def reset_password(username,password,actor='console'):
    password_policy(password)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('SELECT name FROM users WHERE name=?',(username,)).fetchone():raise ValueError('Select an existing administrator.')
        salt=secrets.token_bytes(16);c.execute('UPDATE users SET salt=?,hash=? WHERE name=?',(salt,pw_hash(password,salt),username))
        c.execute('DELETE FROM sessions');audit(c,actor,'administrator-password-recovery' if actor=='console' else 'administrator-password-change','success')
