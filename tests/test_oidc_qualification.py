import io, json, sys, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'provisioning'))
import oidc_qualification as q


class Response:
 def __init__(self,value):self.value=value
 def read(self,limit):return json.dumps(self.value).encode()


class OidcQualificationTests(unittest.TestCase):
 def test_request_uses_urlopen_without_custom_opener(self):
  with patch.object(q.urllib.request,'urlopen',return_value=Response({'ok':True})) as urlopen:
   _,value=q.request('http://keycloak.test/status')
  self.assertTrue(value['ok']);urlopen.assert_called_once()
 def test_decode_claims(self):
  import base64
  payload=base64.urlsafe_b64encode(json.dumps({'preferred_username':'tester'}).encode()).rstrip(b'=').decode()
  self.assertEqual(q.decode_claims('x.'+payload+'.x')['preferred_username'],'tester')
 def test_public_issuer_redirect_is_kept_on_private_keycloak_path(self):
  handler=q.StopAtCallback();request=__import__('urllib.request').request.Request('http://keycloak.test/start')
  redirected=handler.redirect_request(request,None,302,'Found',{},'https://sso.example.local/identity/login-actions/authenticate?session=one')
  self.assertEqual(redirected.full_url,q.KEYCLOAK+'/login-actions/authenticate?session=one')
 def test_login_form_collects_hidden_fields(self):
  parser=q.LoginForm();parser.feed('<form method="post" action="/login"><input type="hidden" name="credentialId" value="abc"></form>')
  self.assertEqual(parser.action,'/login');self.assertEqual(parser.hidden,{'credentialId':'abc'})


if __name__=='__main__':unittest.main()
