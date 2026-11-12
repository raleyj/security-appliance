#!/usr/bin/env bash
set -euo pipefail
umask 077

mountpoint=/run/security-appliance-container-bundle
expected=28ce1271570c30ae68d74b51c26f34ada696a85c92d0a1bd1b5e42ec3f84c906
device="$(findfs LABEL=SECURITYBUNDLE)"
mkdir -p "$mountpoint"
cleanup() { mountpoint -q "$mountpoint" && umount "$mountpoint" || true; rmdir "$mountpoint" 2>/dev/null || true; }
trap cleanup EXIT
mount -o ro "$device" "$mountpoint"
test "$(sha256sum "$mountpoint/lab-security-appliance-containers.tar" | awk '{print $1}')" = "$expected"
docker load --input "$mountpoint/lab-security-appliance-containers.tar"
echo 'Verified offline container bundle loaded.'
