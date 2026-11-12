param()
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$destination=Join-Path $PSScriptRoot 'full-container-bundle'
New-Item -ItemType Directory -Force $destination|Out-Null
$management='lab-security-management:0.3.0'
$keycloak='lab-security-keycloak:0.3.0'
$kmipClient='lab-security-kmip-client:0.2.0'
$proxyBase='nginx:1.30.6-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311'
$proxy='lab-security-proxy:1.30.6-alpine-security-20261111'
$postgresBase='postgres:17.11-trixie@sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f'
$postgres='lab-security-postgres:17'
$kmip='ghcr.io/cosmian/kms:5.25.0@sha256:4f8a1b52fda43f43125849053a2030f80e48622dfcf8cbc24894f645960ca824'
$forwardBase='ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c'
$forward='lab-security-forward-proxy:6.6-24.04-security-20261111'
docker build --provenance=false --pull=false --tag $management (Join-Path $root 'app')
if($LASTEXITCODE){throw 'Management image build failed.'}
docker build --provenance=false --pull=false --tag $keycloak (Join-Path $root 'provisioning/keycloak')
if($LASTEXITCODE){throw 'Optimized Keycloak image build failed.'}
docker build --provenance=false --pull=false --tag $kmipClient (Join-Path $root 'provisioning/kmip-client')
if($LASTEXITCODE){throw 'KMIP qualification client image build failed.'}
docker build --provenance=false --pull=false --tag $forward (Join-Path $root 'provisioning/forward-proxy')
if($LASTEXITCODE){throw 'Forward proxy security image build failed.'}
docker build --provenance=false --pull=false --tag $proxy (Join-Path $root 'provisioning/reverse-proxy')
if($LASTEXITCODE){throw 'Reverse proxy security image build failed.'}
docker build --provenance=false --pull=false --tag $postgres (Join-Path $root 'provisioning/postgres')
if($LASTEXITCODE){throw 'PostgreSQL security image build failed.'}
$upstream=@($proxyBase,$postgresBase,$kmip,$forwardBase)
foreach($image in $upstream){docker image inspect $image|Out-Null;if($LASTEXITCODE){throw "Missing locked image: $image"}}
docker tag $kmip 'lab-security-kmip:5.25.0'
$images=@($management,$keycloak,$proxy,$postgres,'lab-security-kmip:5.25.0',$forward,$kmipClient)
$archive=Join-Path $destination 'lab-security-appliance-containers.tar'
docker save --output $archive @images
if($LASTEXITCODE){throw 'Full container export failed.'}
$python=Get-Command python -ErrorAction SilentlyContinue
if(-not $python){$python=Get-Command python3 -ErrorAction SilentlyContinue}
if(-not $python){throw 'Python is required to finalize and verify the offline release bundle.'}
foreach($script in @('create_release_evidence.py','finalize_container_bundle.py','verify_full_bundle.py')){
 & $python.Source (Join-Path $PSScriptRoot $script)
 if($LASTEXITCODE){throw "Release evidence or bundle verification failed: $script"}
}
