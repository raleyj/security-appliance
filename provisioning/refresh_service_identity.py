"""Refresh hostname-derived service configuration without changing secrets or data."""
import json, os
from pathlib import Path

ROOT=Path('/etc/security-appliance')
cfg=json.loads((ROOT/'config.json').read_text())
credentials=json.loads((ROOT/'service-credentials.json').read_text())
issuer='https://'+cfg['sso_fqdn']+'/identity'
env={
 'KC_DB':'postgres','KC_DB_URL':'jdbc:postgresql://security-postgres:5432/keycloak','KC_DB_USERNAME':'keycloak',
 'KC_DB_PASSWORD':credentials['database'],'KC_HTTP_ENABLED':'true','KC_HTTP_RELATIVE_PATH':'/identity',
 'KC_HOSTNAME':issuer,'KC_PROXY_HEADERS':'xforwarded','KC_HTTP_MANAGEMENT_RELATIVE_PATH':'/','KC_HEALTH_ENABLED':'true'
}
path=ROOT/'keycloak.env';path.write_text(''.join(k+'='+v+'\n' for k,v in env.items()));os.chmod(path,0o600)
endpoints={'identity':issuer,'identityAdmin':issuer+'/admin/master/console/','identityUsername':'identity-admin','profile':'static lab identity; temporary certificate; no production relying parties'}
path=ROOT/'service-endpoints.json';path.write_text(json.dumps(endpoints));os.chmod(path,0o600)
