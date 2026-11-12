# Security Appliance

Security Appliance is a deployable VMware vSphere appliance that combines identity, key management, controlled proxying, certificate lifecycle, health monitoring, and appliance administration in one hardened interface.

## Core services

- **Keycloak / OIDC** for standards-based identity federation, Authorization Code with PKCE, role mapping, and coordinated logout.
- **KMIP key management** with appliance-managed certificate hierarchy, client CSR signing, source-network controls, and mutual-TLS consumer enrollment.
- **Nginx reverse proxy** for hostname-aware HTTPS routing and HTTP-to-HTTPS redirection.
- **Squid forward proxy** for explicit, source-restricted outbound HTTP and HTTPS connectivity without TLS interception.
- **PostgreSQL** for durable identity service storage on a dedicated appliance data disk.
- **Management console** for first deployment, certificates, service control, updates, diagnostics, audit history, alert delivery, and recovery.

## Appliance behavior

- Guided five-step first deployment workflow.
- Static IPv4 or reservation-backed DHCP deployment properties.
- Separate management, identity, database, KMIP, edge, and forward-proxy container networks.
- Host firewall rules generated from approved management and client CIDRs.
- Private keys generated and retained at their owning endpoint.
- Signed update bundles with manifest verification, health checks, and guarded restore.
- Fixed-function VM console recovery with no general operating-system shell.
- Per-service functional tests and scoped connection activity.
- Health, storage, certificate, firewall, DNS, NTP, and alert status from one interface.
- Syslog, HTTPS webhook, and Mattermost health-alert delivery.

## Repository layout

- `app/` – management API and browser interface.
- `provisioning/` – first boot, service configuration, firewall, certificates, updates, and recovery.
- `build/` – offline image bundle, OVF-property, update-signing, and manifest utilities.
- `tests/` – functional and policy tests.
- `docs/` – architecture, deployment, and security documentation.
- `release/` – GA checksum and verification notes.

## Release

The current appliance release is **1.2 GA** (qualified build 1.2.18). The vSphere OVA is produced by the sealed-release workflow with blank deployment secrets and a fresh data disk. GitHub release assets provide the OVA in numbered parts because the complete image is larger than GitHub's per-asset limit. Reconstruct the OVA with the supplied script and verify it against `release/Lab-Security-Appliance-1.2-GA.ova.sha256` before import.

## Documentation

- [Deployment guide](docs/Security-Appliance-Deployment-Guide.docx)
- [User guide](docs/Security-Appliance-User-Guide.docx)
- [Troubleshooting guide](docs/Security-Appliance-Troubleshooting-Guide.docx)
- [Logical architecture diagram](docs/Security-Appliance-Logical-Architecture.png)
- [Deployment summary](docs/DEPLOYMENT.md)
- [Security model](docs/SECURITY.md)
