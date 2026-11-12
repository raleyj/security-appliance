param(
    [string]$EvidenceDirectory = 'build/stateful-qualification-20261111'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$evidence = Join-Path $root $EvidenceDirectory
$evidenceFull = [IO.Path]::GetFullPath($evidence)
$network = 'security-qualification-20261111'
$dataVolume = 'security-qualification-pgdata-20261111'
$restoreVolume = 'security-qualification-pgdata-restore-20261111'
$postgresName = 'security-qual-postgres-20261111'
$keycloakName = 'security-qual-keycloak-20261111'
$oldKeycloak = 'lab-security-keycloak:qualification-26.7.0'
$newKeycloak = 'lab-security-keycloak:0.3.0'
$oldPostgres = 'postgres@sha256:665dc7b37ac52a17e298511414c21d23ffa4e6a6ef6225b3e5d59c7afb35e994'
$newPostgres = 'lab-security-postgres:17'

function New-QualificationSecret {
    $bytes = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return 'Q!' + [Convert]::ToBase64String($bytes)
}

$databasePassword = New-QualificationSecret
$adminPassword = New-QualificationSecret
$clientSecret = New-QualificationSecret
$port = 18080
$createdNetwork = $false
$createdVolumes = @()

function Invoke-Docker {
    $dockerArguments = @($args)
    & docker @dockerArguments
    if ($LASTEXITCODE) { throw "Docker command failed: docker $($dockerArguments -join ' ')" }
}

function Assert-NameAvailable {
    param([string]$Kind,[string]$Name)
    & docker $Kind inspect $Name *> $null
    if ($LASTEXITCODE -eq 0) { throw "Qualification $Kind already exists: $Name" }
}

function Wait-Postgres {
    for ($i=0; $i -lt 60; $i++) {
        & docker exec $postgresName pg_isready -U keycloak -d keycloak *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw 'PostgreSQL did not become ready.'
}

function Wait-Keycloak {
    for ($i=0; $i -lt 90; $i++) {
        try {
            $document = Invoke-RestMethod "http://127.0.0.1:$port/identity/realms/master/.well-known/openid-configuration" -TimeoutSec 4
            if ($document.issuer) { return $document }
        } catch {}
        Start-Sleep -Seconds 2
    }
    throw 'Keycloak did not publish OIDC discovery.'
}

function Start-Postgres {
    param([string]$Image,[string]$Volume)
    Invoke-Docker run -d --name $postgresName --network $network `
        -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e "POSTGRES_PASSWORD=$databasePassword" `
        -v "${Volume}:/var/lib/postgresql/data" $Image | Out-Null
    Wait-Postgres
}

function Start-Keycloak {
    param([string]$Image,[bool]$Bootstrap)
    $arguments = @('run','-d','--name',$keycloakName,'--network',$network,
        '-p',"127.0.0.1:${port}:8080",
        '-e','KC_DB=postgres',
        '-e',"KC_DB_URL=jdbc:postgresql://${postgresName}:5432/keycloak",
        '-e','KC_DB_USERNAME=keycloak',
        '-e',"KC_DB_PASSWORD=$databasePassword",
        '-e','KC_HTTP_ENABLED=true',
        '-e','KC_HTTP_RELATIVE_PATH=/identity',
        '-e',"KC_HOSTNAME=http://127.0.0.1:${port}/identity",
        '-e','KC_PROXY_HEADERS=xforwarded')
    if ($Bootstrap) {
        $arguments += @('-e','KC_BOOTSTRAP_ADMIN_USERNAME=qualification-admin','-e',"KC_BOOTSTRAP_ADMIN_PASSWORD=$adminPassword")
    }
    $arguments += @($Image,'start','--optimized')
    Invoke-Docker @arguments | Out-Null
    return Wait-Keycloak
}

function Remove-TestContainers {
    foreach ($name in @($keycloakName,$postgresName)) {
        & docker rm -f $name *> $null
    }
}

function Test-ClientToken {
    $token = Invoke-RestMethod "http://127.0.0.1:$port/identity/realms/qualification/protocol/openid-connect/token" `
        -Method Post -ContentType 'application/x-www-form-urlencoded' -Body @{
            grant_type='client_credentials';client_id='qualification-client';client_secret=$clientSecret
        } -TimeoutSec 10
    if (-not $token.access_token -or $token.token_type -ne 'Bearer') { throw 'OIDC client credential token was not issued.' }
}

Assert-NameAvailable container $postgresName
Assert-NameAvailable container $keycloakName
Assert-NameAvailable network $network
Assert-NameAvailable volume $dataVolume
Assert-NameAvailable volume $restoreVolume
if (Test-Path $evidence) { throw "Evidence directory already exists: $evidence" }
New-Item -ItemType Directory -Path $evidence | Out-Null

$result = [ordered]@{
    startedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    oldKeycloak = '26.7.0'
    newKeycloak = '26.8.2 with Guava 33.7.2'
    oldPostgres = '17.11 Bookworm'
    newPostgres = '17.11 Trixie without gosu'
    cleanInitialization = $false
    protectedCopyCreated = $false
    oidcBeforeUpgrade = $false
    oidcAfterUpgrade = $false
    restoredPriorState = $false
}

try {
    Invoke-Docker build --pull=false -t $oldKeycloak (Join-Path $PSScriptRoot 'stateful-upgrade/old-keycloak') | Out-Null
    Invoke-Docker network create $network | Out-Null
    $createdNetwork = $true
    Invoke-Docker volume create $dataVolume | Out-Null
    $createdVolumes += $dataVolume
    Start-Postgres $oldPostgres $dataVolume
    $oldDiscovery = Start-Keycloak $oldKeycloak $true
    Invoke-Docker exec $keycloakName /opt/keycloak/bin/kcadm.sh config credentials `
        --server 'http://localhost:8080/identity' --realm master --user qualification-admin --password $adminPassword | Out-Null
    Invoke-Docker exec $keycloakName /opt/keycloak/bin/kcadm.sh create realms `
        -s realm=qualification -s enabled=true -s displayName='Stateful upgrade qualification' | Out-Null
    Invoke-Docker exec $keycloakName /opt/keycloak/bin/kcadm.sh create clients -r qualification `
        -s clientId=qualification-client -s enabled=true -s serviceAccountsEnabled=true `
        -s clientAuthenticatorType=client-secret -s "secret=$clientSecret" | Out-Null
    Test-ClientToken
    $result.cleanInitialization = $true
    $result.oidcBeforeUpgrade = $true

    Invoke-Docker stop $keycloakName $postgresName | Out-Null
    Invoke-Docker rm $keycloakName $postgresName | Out-Null
    Invoke-Docker run --rm `
        --mount "type=volume,source=$dataVolume,target=/from,readonly" `
        --mount "type=bind,source=$evidenceFull,target=/backup" `
        alpine:3.22 sh -c 'cd /from && tar -czf /backup/pgdata-before-upgrade.tgz .' | Out-Null
    $backup = Join-Path $evidence 'pgdata-before-upgrade.tgz'
    if (-not (Test-Path $backup) -or (Get-Item $backup).Length -lt 1024) { throw 'Protected PostgreSQL copy was not created.' }
    $result.protectedCopyCreated = $true
    $result.protectedCopySha256 = (Get-FileHash $backup -Algorithm SHA256).Hash.ToLowerInvariant()

    Start-Postgres $newPostgres $dataVolume
    $newDiscovery = Start-Keycloak $newKeycloak $false
    Test-ClientToken
    $result.oidcAfterUpgrade = $true
    $result.oldIssuer = $oldDiscovery.issuer
    $result.newIssuer = $newDiscovery.issuer

    Invoke-Docker stop $keycloakName $postgresName | Out-Null
    Invoke-Docker rm $keycloakName $postgresName | Out-Null
    Invoke-Docker volume create $restoreVolume | Out-Null
    $createdVolumes += $restoreVolume
    Invoke-Docker run --rm `
        --mount "type=volume,source=$restoreVolume,target=/restore" `
        --mount "type=bind,source=$evidenceFull,target=/backup,readonly" `
        alpine:3.22 sh -c 'cd /restore && tar -xzf /backup/pgdata-before-upgrade.tgz' | Out-Null
    Start-Postgres $oldPostgres $restoreVolume
    $restoredDiscovery = Start-Keycloak $oldKeycloak $false
    Test-ClientToken
    $result.restoredPriorState = $true
    $result.restoredIssuer = $restoredDiscovery.issuer
    $result.passed = $true
    $result.completedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $evidence 'stateful-upgrade-validation.json')
} finally {
    Remove-TestContainers
    foreach ($volume in $createdVolumes) { & docker volume rm $volume *> $null }
    if ($createdNetwork) { & docker network rm $network *> $null }
}

Get-Content (Join-Path $evidence 'stateful-upgrade-validation.json')
