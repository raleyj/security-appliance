#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "${SECURITY_RELEASE_SEAL_CLONE:-}" = 1
case "${SECURITY_RELEASE_VERSION:-}" in
  ''|1.0|1.2.5|1.2.18) ;;
  *) echo 'Unsupported release seal version.' >&2; exit 1 ;;
esac
test -f /etc/security-appliance/installed
if test -e /etc/security-appliance/build-auth-bypass || test -e /var/lib/security-appliance/management/build-auth-bypass.json || test -e /opt/security-appliance/provisioning/build-auth-bypass.json; then
  echo 'Release gate failed: disable build auto-login and verify standard login before sealing the deployable OVA.' >&2
  exit 1
fi
if docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' security-management 2>/dev/null | grep -qx 'SECURITY_BUILD_AUTH_BYPASS=1'; then
  echo 'Release gate failed: the management container still has SECURITY_BUILD_AUTH_BYPASS enabled.' >&2
  exit 1
fi
if test "${SECURITY_RELEASE_VERSION:-}" = 1.0 || test "${SECURITY_RELEASE_VERSION:-}" = 1.2.5; then
  management_image_id=$(docker image inspect lab-security-management:0.3.0 --format '{{.Id}}')
  docker save --output /var/tmp/security-management-v1.tar lab-security-management:0.3.0
fi
systemctl stop security-appliance security-host-control security-console security-health.timer 2>/dev/null || true
docker rm -f security-management security-proxy security-forward-proxy security-postgres security-keycloak security-kmip 2>/dev/null || true
python3 - <<'PY'
import hashlib,json
from pathlib import Path
root=Path('/mnt/release-source')
manifest=json.loads((root/'container-manifest.json').read_text())
archive=root/manifest['archive']
digest=hashlib.sha256()
with archive.open('rb') as source:
    for block in iter(lambda:source.read(1024*1024),b''):
        digest.update(block)
if digest.hexdigest()!=manifest['sha256'] or archive.stat().st_size!=manifest['sizeBytes']:
    raise SystemExit('Offline release container bundle does not match its manifest.')
PY
docker system prune -a --volumes --force >/dev/null
docker load --input /mnt/release-source/lab-security-appliance-containers.tar >/dev/null
if test "${SECURITY_RELEASE_VERSION:-}" = 1.0 || test "${SECURITY_RELEASE_VERSION:-}" = 1.2.5; then
  docker load --input /var/tmp/security-management-v1.tar >/dev/null
  rm -f /var/tmp/security-management-v1.tar
  test "$(docker image inspect lab-security-management:0.3.0 --format '{{.Id}}')" = "$management_image_id"
fi
for image in lab-security-management:0.3.0 lab-security-proxy:1.30.6-alpine-security-20261111 lab-security-forward-proxy:6.6-24.04-security-20261111 lab-security-postgres:17 lab-security-keycloak:0.3.0 lab-security-kmip:5.25.0 lab-security-kmip-client:0.2.0; do
  docker image inspect "$image" >/dev/null
done
umount /var/lib/security-appliance
wipefs -a /dev/sdb
sed -i '\|LABEL=security-data /var/lib/security-appliance|d' /etc/fstab
rm -rf /etc/security-appliance /var/lib/security-appliance
rm -f /etc/systemd/timesyncd.conf.d/security.conf /etc/systemd/timesyncd.conf.d/99-security.conf
install -d -m 0700 /etc/security-appliance /var/lib/security-appliance
if test "${SECURITY_RELEASE_VERSION:-}" = 1.0 || test "${SECURITY_RELEASE_VERSION:-}" = 1.2.5 || test "${SECURITY_RELEASE_VERSION:-}" = 1.2.18; then
  printf '{"version":"%s","source":"sealed-vsphere-ova"}\n' "$SECURITY_RELEASE_VERSION" > /etc/security-appliance/release.json
  chmod 0600 /etc/security-appliance/release.json
fi
install -m 0644 /opt/security-appliance/provisioning/security-firstboot.service /etc/systemd/system/security-firstboot.service
systemctl disable security-appliance security-host-control security-console security-health.timer 2>/dev/null || true
systemctl enable security-firstboot.service
rm -f /etc/machine-id /var/lib/dbus/machine-id
touch /etc/machine-id
cloud-init clean --logs --machine-id --seed
find /var/log -type f -exec truncate -s 0 {} +
# The clone came from a configured lab VM. Overwrite freed OS blocks before
# export so removed credentials and private material cannot ride in its VMDK.
available_bytes=$(df -B1 --output=avail / | tail -1)
dd if=/dev/zero of=/var/tmp/security-release-free-space.fill bs=16M status=none conv=fsync 2>/dev/null || test "$?" = 1
written_bytes=$(stat -c %s /var/tmp/security-release-free-space.fill)
test "$written_bytes" -ge "$((available_bytes - 16777216))"
rm -f /var/tmp/security-release-free-space.fill
sync
fstrim / >/dev/null 2>&1 || true
vmtoolsd --cmd 'info-set guestinfo.security.release.scrubbed true'
sync
# Keep the guest running long enough for vCenter to record the completion
# signal before the guestinfo RPC value disappears at power-off.
sleep 90
systemctl poweroff
