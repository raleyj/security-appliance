# Security model

The appliance exposes management through HTTPS and keeps database and application backends on private container networks. Host firewall policy is built from explicit management, proxy-client, and KMIP-client CIDRs. KMIP uses mutual TLS, and consumers generate their own private keys.

The first-boot contract requires separate administrator, recovery, and identity credentials. Deployment password properties are masked and blank in the sealed OVA. Build authentication markers are removed during first boot and rejected by release sealing.

Updates use a signed manifest and per-file SHA-256 digests. Installation is limited to approved appliance paths, followed by fixed health checks. The prior qualified application state is retained for guarded restoration.

The VM console exposes bounded recovery operations, service/firewall status, and appliance restart. It does not provide a general operating-system shell. Administrative actions, service operations, certificate changes, updates, and alert tests are recorded in the activity history.

Support bundles and activity views sanitize credential-related material. Alert delivery sends bounded summaries through configured syslog, HTTPS webhook, or Mattermost destinations.
