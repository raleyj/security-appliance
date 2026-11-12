#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
test -f /etc/security-appliance/installed
mountpoint -q /var/lib/security-appliance
media="${1:-/mnt/security-service-media}"
test -f "$media/lab-security-appliance-containers.tar"
test -f "$media/containers.sha256"
(cd "$media" && sha256sum -c containers.sha256)
docker load --input "$media/lab-security-appliance-containers.tar"
python3 /opt/security-appliance/provisioning/prepare_services.py
systemctl stop security-appliance
python3 /opt/security-appliance/provisioning/certificates.py
python3 /opt/security-appliance/provisioning/render_proxy.py
docker rm -f security-management security-proxy 2>/dev/null || true
python3 /opt/security-appliance/provisioning/compose_runtime.py
cat >/etc/systemd/system/security-appliance.service <<'UNIT'
[Unit]
Description=Security appliance Compose services after storage and firewall
Requires=docker.service ufw.service security-host-control.service
After=docker.service ufw.service security-host-control.service
RequiresMountsFor=/var/lib/security-appliance
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/mountpoint -q /var/lib/security-appliance
ExecStartPre=/usr/bin/python3 /opt/security-appliance/provisioning/firewall.py
ExecStartPre=/usr/bin/python3 /opt/security-appliance/provisioning/compose_runtime.py --verify
ExecStart=/usr/bin/docker compose -f /etc/security-appliance/compose.json up -d --no-build --pull never
ExecStop=/usr/bin/docker compose -f /etc/security-appliance/compose.json stop
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl restart security-host-control
systemctl start security-appliance
python3 /opt/security-appliance/provisioning/service_control.py --initialize
docker compose -f /etc/security-appliance/compose.json up -d --no-deps --force-recreate --pull never keycloak
python3 /opt/security-appliance/provisioning/report.py
