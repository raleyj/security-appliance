#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
test -f /etc/security-appliance/auth.json
test ! -f /etc/security-appliance/installed
export DEBIAN_FRONTEND=noninteractive
systemctl mask --now ssh.service ssh.socket getty@.service serial-getty@.service console-getty.service || true
passwd -l root
install -d /etc/systemd/logind.conf.d
printf '[Login]\nNAutoVTs=0\nReserveVT=0\n' >/etc/systemd/logind.conf.d/security-appliance.conf
printf 'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n' >/etc/sysctl.d/60-security-appliance.conf
sysctl --system >/dev/null
apt-get update
apt-get install -y docker.io docker-compose-v2 ufw openssl python3
install -d -m 0700 /var/lib/security-appliance
# Fresh empty data disk only. Refuse a filesystem, partitions or unexpected size.
test "$(lsblk -bdno SIZE /dev/sdb)" = 68719476736
test "$(lsblk -n /dev/sdb | wc -l)" = 1
if blkid /dev/sdb >/dev/null; then echo 'Data disk already contains a filesystem; operator review required.' >&2; exit 1; fi
mkfs.ext4 -L security-data /dev/sdb
printf 'LABEL=security-data /var/lib/security-appliance ext4 defaults 0 2\n' >>/etc/fstab
mount /var/lib/security-appliance
install -d -m 0700 /var/lib/security-appliance/management /etc/security-appliance/tls
python3 - <<'PY'
import json
from pathlib import Path
r=Path('/etc/security-appliance');d=json.loads((r/'auth.json').read_text())
(r/'config.json').write_text(json.dumps(d['config']))
(r/'recovery.json').write_text(json.dumps(d['recovery']))
PY
python3 /opt/security-appliance/provisioning/firewall.py --build
install -d /etc/systemd/system/docker.service.d
printf '[Service]\nExecStartPost=/usr/bin/python3 /opt/security-appliance/provisioning/firewall.py\n' >/etc/systemd/system/docker.service.d/security-firewall.conf
systemctl daemon-reload
systemctl enable docker ufw
docker build -t lab-security-management:0.1.0 /opt/security-appliance/app
docker pull nginx:1.28.0
docker run --rm --network none --user 0 -v /var/lib/security-appliance/management:/var/lib/security-appliance/management -v /etc/security-appliance:/bootstrap:ro -v /opt/security-appliance/provisioning/bootstrap_state.py:/bootstrap_state.py:ro lab-security-management:0.1.0 python /bootstrap_state.py
chown -R 10001:10001 /var/lib/security-appliance/management
openssl req -x509 -newkey rsa:3072 -nodes -keyout /etc/security-appliance/tls/server.key -out /etc/security-appliance/tls/server.crt -days 30 -subj /CN=lab-security-test.example.local -addext subjectAltName=DNS:lab-security-test.example.local
chmod 0600 /etc/security-appliance/tls/server.key
python3 - <<'PY'
import json
from pathlib import Path
cfg=json.loads(Path('/etc/security-appliance/config.json').read_text())
allow='\n'.join('allow '+x+';' for x in cfg['admin_cidrs'])
Path('/etc/security-appliance/nginx.conf').write_text('''events {}\nhttp {\ninclude /etc/nginx/mime.types;\nserver {\nlisten 80;\nserver_name _;\nreturn 308 https://$host$request_uri;\n}\nserver {\nlisten 443 ssl;\nserver_name _;\nssl_certificate /certs/server.crt;\nssl_certificate_key /certs/server.key;\nssl_protocols TLSv1.2 TLSv1.3;\nlocation = / { return 302 /admin/; }\nlocation = /admin { return 302 /admin/; }\nlocation /admin/ {\n'''+allow+'''\ndeny all;\nproxy_set_header Host $host;\nproxy_set_header X-Forwarded-Proto https;\nproxy_set_header X-Forwarded-For $remote_addr;\nproxy_pass http://security-management:8080;\n}\nlocation / { return 404; }\n}\n}\n''')
PY
docker network create --internal security-management
docker network create security-edge
install -d -m 0750 -g 10001 /run/security-appliance
docker run -d --name security-management --restart no --network security-management --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges -v /run/security-appliance:/run/security-appliance -v /var/lib/security-appliance/management:/var/lib/security-appliance/management lab-security-management:0.1.0
docker create --name security-proxy --restart no --network security-edge --read-only --tmpfs /var/cache/nginx --tmpfs /var/run --tmpfs /tmp --security-opt no-new-privileges -p 80:80 -p 443:443 -v /etc/security-appliance/nginx.conf:/etc/nginx/nginx.conf:ro -v /etc/security-appliance/tls:/certs:ro nginx:1.28.0
docker network connect security-management security-proxy
docker start security-proxy
cat >/etc/systemd/system/security-appliance.service <<'UNIT'
[Unit]
Description=Security appliance containers after storage and firewall
Requires=docker.service ufw.service security-host-control.service
After=docker.service ufw.service security-host-control.service
RequiresMountsFor=/var/lib/security-appliance
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/mountpoint -q /var/lib/security-appliance
ExecStartPre=/usr/bin/python3 /opt/security-appliance/provisioning/firewall.py
ExecStart=/usr/bin/docker start security-management security-proxy
ExecStop=/usr/bin/docker stop security-proxy security-management
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/security-host-control.service <<'UNIT'
[Unit]
Description=Restricted appliance network transaction service
After=docker.service
RequiresMountsFor=/var/lib/security-appliance
[Service]
ExecStart=/usr/bin/python3 /opt/security-appliance/provisioning/host_control.py
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/security-console.service <<'UNIT'
[Unit]
Description=Restricted security appliance console
After=systemd-user-sessions.service
Conflicts=getty@tty1.service
[Service]
ExecStart=/usr/bin/python3 /opt/security-appliance/provisioning/console.py
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
python3 /opt/security-appliance/provisioning/firewall.py
systemctl daemon-reload
systemctl enable --now security-host-control security-appliance security-console
touch /etc/security-appliance/installed
rm -f /etc/security-appliance/auth.json
python3 /opt/security-appliance/provisioning/report.py
