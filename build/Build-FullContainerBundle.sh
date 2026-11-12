#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/build/full-container-bundle"
mkdir -p "$out/keycloak-build"

management_base='python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'
keycloak_base='quay.io/keycloak/keycloak:26.8.2@sha256:723b1d6e254c0fc96d5cffec860c7e0744d6a3277822b865bb538cf891575e41'
client_base='python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535'
proxy_base='nginx:1.30.6-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311'
proxy='lab-security-proxy:1.30.6-alpine-security-20261111'
postgres_base='postgres:17.11-trixie@sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'
postgres='lab-security-postgres:17'
kmip='ghcr.io/cosmian/kms:5.25.0@sha256:4f8a1b52fda43f43125849053a2030f80e48622dfcf8cbc24894f645960ca824'
forward_base='ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c'
forward='lab-security-forward-proxy:6.6-24.04-security-20261111'

for image in "$management_base" "$keycloak_base" "$client_base" "$proxy_base" "$postgres_base" "$kmip" "$forward_base"; do
  docker pull "$image"
done

docker build --provenance=false --pull=false --tag lab-security-management:0.3.0 "$root/app"
docker build --provenance=false --pull=false --tag lab-security-keycloak:0.3.0 "$root/provisioning/keycloak"
docker build --provenance=false --pull=false --tag lab-security-kmip-client:0.2.0 "$root/provisioning/kmip-client"
docker build --provenance=false --pull=false --tag "$forward" "$root/provisioning/forward-proxy"
docker build --provenance=false --pull=false --tag "$proxy" "$root/provisioning/reverse-proxy"
docker build --provenance=false --pull=false --tag "$postgres" "$root/provisioning/postgres"

docker tag "$kmip" lab-security-kmip:5.25.0

docker save --output "$out/lab-security-appliance-containers.tar" \
  lab-security-management:0.3.0 lab-security-keycloak:0.3.0 \
  "$proxy" "$postgres" \
  lab-security-kmip:5.25.0 "$forward" \
  lab-security-kmip-client:0.2.0

python3 "$root/build/create_release_evidence.py"
python3 "$root/build/finalize_container_bundle.py"
python3 "$root/build/verify_full_bundle.py"
