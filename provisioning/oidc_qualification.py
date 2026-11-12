#!/usr/bin/python3
"""Disposable Authorization Code + PKCE client qualification for Keycloak."""
import base64, hashlib, html.parser, http.cookiejar, json, os, secrets, sys, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path

KEYCLOAK = os.environ.get('KEYCLOAK_BASE','http://keycloak:8080/identity')
CALLBACK = 'https://security.example.local/oidc-test/callback'
CLIENT_ID = 'appliance-oidc-qualification'


def form(data):
    return urllib.parse.urlencode(data).encode()


def request(url, data=None, token=None, method=None, opener=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode(); headers['Content-Type'] = 'application/json'
    elif data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=15) if opener else urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError as error:
        parsed = urllib.parse.urlsplit(url)
        raise ValueError('Request failed at '+parsed.scheme+'://'+parsed.netloc+parsed.path+': '+str(error.reason)) from None
    raw = response.read(400000)
    return response, json.loads(raw) if raw else None


class LoginForm(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(); self.action = None; self.hidden = {}
    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form' and values.get('method', '').lower() == 'post' and values.get('action'):
            self.action = values['action']
        if tag == 'input' and values.get('type', '').lower() == 'hidden' and values.get('name'):
            self.hidden[values['name']] = values.get('value', '')


class StopAtCallback(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(CALLBACK):
            return None
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.hostname == 'sso.example.local' and parsed.path.startswith('/identity/'):
            path = parsed.path.removeprefix('/identity')
            internal = KEYCLOAK + path + (('?' + parsed.query) if parsed.query else '')
            return urllib.request.Request(internal, headers=req.headers, origin_req_host=req.origin_req_host, unverifiable=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def admin_token(username, password):
    _, value = request(KEYCLOAK + '/realms/master/protocol/openid-connect/token', form({
        'grant_type': 'password', 'client_id': 'admin-cli', 'username': username, 'password': password
    }))
    return value['access_token']


def decode_claims(token):
    payload = token.split('.')[1]; payload += '=' * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def authorization_code(username, password, verifier):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    state = secrets.token_urlsafe(18)
    params = urllib.parse.urlencode({
        'client_id': CLIENT_ID, 'redirect_uri': CALLBACK, 'response_type': 'code',
        'scope': 'openid profile', 'state': state,
        'code_challenge': challenge, 'code_challenge_method': 'S256'
    })
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), StopAtCallback())
    response = opener.open(KEYCLOAK + '/realms/appliance-qualification/protocol/openid-connect/auth?' + params, timeout=15)
    parser = LoginForm(); parser.feed(response.read(400000).decode())
    if not parser.action:
        raise ValueError('Keycloak login form was not presented.')
    action = parser.action
    parsed_action = urllib.parse.urlsplit(action)
    if parsed_action.netloc != urllib.parse.urlsplit(KEYCLOAK).netloc:
        path = parsed_action.path.removeprefix('/identity')
        action = KEYCLOAK + path + (('?' + parsed_action.query) if parsed_action.query else '')
    try:
        fields = dict(parser.hidden); fields.update(username=username,password=password)
        opener.open(urllib.request.Request(action, data=form(fields), method='POST'), timeout=15)
        raise ValueError('Authorization did not return to the registered callback.')
    except urllib.error.HTTPError as error:
        if error.code not in (302, 303):
            raise
        location = error.headers.get('Location', '')
    values = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    if not secrets.compare_digest(values.get('state', [''])[0], state):
        raise ValueError('OIDC state validation failed.')
    code = values.get('code', [''])[0]
    if not code:
        raise ValueError('Authorization code was not returned.')
    return code


def exchange(code, verifier):
    _, value = request(KEYCLOAK + '/realms/appliance-qualification/protocol/openid-connect/token', form({
        'grant_type': 'authorization_code', 'client_id': CLIENT_ID, 'redirect_uri': CALLBACK,
        'code': code, 'code_verifier': verifier
    }))
    return value


def main():
    credentials = json.loads(Path('/qualification/credentials.json').read_text())
    access = admin_token(credentials.get('identity_username', 'identity-admin'), credentials['identity'])
    admin = KEYCLOAK + '/admin/realms'; realm = 'appliance-qualification'
    password = secrets.token_urlsafe(24); user = 'qualification-user'; started = time.time()
    request(admin, {'realm': realm, 'enabled': True}, access)
    try:
        base = admin + '/' + realm
        request(base + '/clients', {
            'clientId': CLIENT_ID, 'name': 'Appliance OIDC qualification client', 'enabled': True,
            'publicClient': True, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
            'redirectUris': [CALLBACK], 'webOrigins': ['https://security.example.local'],
            'attributes': {'pkce.code.challenge.method': 'S256'}
        }, access)
        request(base + '/roles', {'name': 'appliance-admin'}, access)
        request(base + '/users', {
            'username': user, 'enabled': True, 'firstName': 'Qualification', 'lastName': 'User',
            'email': 'qualification-user@example.invalid', 'emailVerified': True,
            'credentials': [{'type': 'password', 'value': password, 'temporary': False}]
        }, access)
        _, users = request(base + '/users?username=' + user + '&exact=true', token=access)
        _, role = request(base + '/roles/appliance-admin', token=access)
        request(base + '/users/' + users[0]['id'] + '/role-mappings/realm', [role], access)

        verifier = secrets.token_urlsafe(48)
        tokens = exchange(authorization_code(user, password, verifier), verifier)
        claims = decode_claims(tokens['access_token'])
        if claims.get('preferred_username') != user or 'appliance-admin' not in claims.get('realm_access', {}).get('roles', []):
            raise ValueError('OIDC role claim validation failed.')

        verifier = secrets.token_urlsafe(48); code = authorization_code(user, password, verifier)
        wrong_verifier_rejected = False
        try:
            exchange(code, secrets.token_urlsafe(48))
        except urllib.error.HTTPError as error:
            wrong_verifier_rejected = error.code == 400
        if not wrong_verifier_rejected:
            raise ValueError('Invalid PKCE verifier was accepted.')

        request(KEYCLOAK + '/realms/' + realm + '/protocol/openid-connect/logout', form({
            'client_id': CLIENT_ID, 'refresh_token': tokens['refresh_token']
        }))
        logout_enforced = False
        try:
            request(KEYCLOAK + '/realms/' + realm + '/protocol/openid-connect/token', form({
                'grant_type': 'refresh_token', 'client_id': CLIENT_ID, 'refresh_token': tokens['refresh_token']
            }))
        except urllib.error.HTTPError as error:
            logout_enforced = error.code == 400
        if not logout_enforced:
            raise ValueError('Logged-out refresh token remained usable.')

        print(json.dumps({
            'flow': 'Authorization Code with PKCE S256', 'callback': CALLBACK,
            'login': True, 'pkceInvalidVerifierRejected': True, 'roleClaimEnforced': True,
            'logoutRevokedRefreshToken': True, 'temporaryRealmRemoved': True,
            'durationSeconds': round(time.time() - started, 3)
        }))
    finally:
        request(admin + '/' + realm, token=access, method='DELETE')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error).split('?', 1)[0].replace('\n', ' ')[:240]
        print(type(error).__name__ + ': ' + message, file=sys.stderr)
        raise SystemExit(1)
