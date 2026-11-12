"""Lab routes: management and temporary IP-based identity URL, internal KMIP TCP."""
import json,os
from pathlib import Path
root=Path(os.environ.get('SECURITY_CONFIG','/etc/security-appliance'));cfg=json.loads((root/'config.json').read_text())
management=cfg['hostname']+'.'+cfg['domain'];identity=cfg['sso_fqdn']
allow='\n'.join('allow '+c+';' for c in cfg['admin_cidrs'])+'\ndeny all;\n'
text='''events {}
stream {
 log_format security_stream '$remote_addr [$time_local] $protocol $status $bytes_sent $bytes_received $session_time';
 access_log /dev/stdout security_stream;
 resolver 127.0.0.11 valid=5s ipv6=off;
 server { listen 5696; set $kms security-kmip:5696; proxy_pass $kms; proxy_connect_timeout 5s; }
}
http {
 include /etc/nginx/mime.types;
 server_tokens off;
 resolver 127.0.0.11 valid=5s ipv6=off;
 server {
 listen 80;
 server_name _;
 return 308 https://$host$request_uri;
 }
 server {
 listen 443 ssl default_server;
 server_name _;
 ssl_certificate /certs/current/server.crt;
 ssl_certificate_key /certs/current/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 add_header Strict-Transport-Security "max-age=31536000" always;
 return 404;
 }
 server {
 listen 443 ssl;
 server_name '''+management+''';
 ssl_certificate /certs/current/server.crt;
 ssl_certificate_key /certs/current/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 add_header Strict-Transport-Security "max-age=31536000" always;
 location = / { return 302 /admin/; }
 location = /admin { return 302 /admin/; }
 location /admin/ {
 '''+allow+'''
 proxy_set_header Host $host;
 proxy_set_header X-Forwarded-Proto https;
 proxy_set_header X-Forwarded-For $remote_addr;
 set $management security-management:8080;
 proxy_pass http://$management;
 }
 location = /oidc-test/callback { return 410; }
 location = /identity { return 302 https://'''+identity+'''/identity/; }
 location /identity/ { return 302 https://'''+identity+'''$request_uri; }
 location / { return 404; }
 }
 server {
 listen 443 ssl;
 server_name '''+identity+''';
 ssl_certificate /certs/current/server.crt;
 ssl_certificate_key /certs/current/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 add_header Strict-Transport-Security "max-age=31536000" always;
 location = / { return 302 /identity/; }
 location = /identity { return 302 /identity/; }
 location /identity/ {
 '''+allow+'''
 proxy_set_header Host $host;
 proxy_set_header X-Forwarded-Proto https;
 proxy_set_header X-Forwarded-Port 443;
 proxy_set_header X-Forwarded-Host $host;
 proxy_set_header X-Forwarded-For $remote_addr;
 set $identity security-keycloak:8080;
 proxy_pass http://$identity;
 }
 location / { return 404; }
 }
}
'''
(root/'nginx.conf').write_text(text)
