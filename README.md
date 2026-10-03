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

## Source package

The complete reviewed source tree is distributed as [`security-appliance-1.0-ga-source.zip`](security-appliance-1.0-ga-source.zip). Verify it with [`security-appliance-1.0-ga-source.zip.sha256`](security-appliance-1.0-ga-source.zip.sha256) before extracting it. The archive contains:

- `app/` – management API and browser interface.
- `provisioning/` – first boot, service configuration, firewall, certificates, updates, and recovery.
- `build/` – offline image bundle, OVF-property, update-signing, and manifest utilities.
- `tests/` – functional and policy tests.
- `docs/` – architecture, deployment, and security documentation.
- `release/` – GA checksum and verification notes.

## Release

The current appliance release is **1.0 GA**. The vSphere OVA is produced by the sealed-release workflow with blank deployment secrets and a fresh data disk. Verify any distributed OVA against [`Lab-Security-Appliance-1.0-GA.ova.sha256`](Lab-Security-Appliance-1.0-GA.ova.sha256) before import.

See [Deployment](DEPLOYMENT.md), [Security model](SECURITY.md), and the [architecture document](Security-Appliance-Architecture.docx).
