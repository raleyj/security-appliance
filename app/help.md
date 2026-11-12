# Security Appliance Help

Installed release: {{VERSION}}

## Deployment

Import the signed OVA and supply distinct web-administrator, console-recovery and Keycloak-administrator credentials. Use a stable hostname and service DNS names. Static IPv4 is preferred; DHCP requires a permanent reservation and matching DNS. Sign in at `/admin/`, complete the five deployment steps, and review Step 5 preflight before selecting Complete. Replace the temporary HTTPS certificate with a matching CA-signed certificate and chain. A new installation must enroll its own OIDC clients and KMIP consumers.

## Administration

Use Health Status for host, service, certificate, storage, firewall and alert summaries. The signed-in username menu opens Appliance Management, Certificates and Trust, Appliance Updates, Admin User Management and Help. Review storage categories and bounded diagnostics before changing a service. Use each service page for service controls and recent functional-test results. Restarting a stateful service can interrupt clients. Appliance network changes use a rollback timer and require reconnect confirmation. Signed updates retain one prior release for an authenticated restore. The fixed-function VM console can recover an existing web-administrator account without granting an Ubuntu shell.

## Identity and KMIP onboarding

In Keycloak, create a separate application realm or client with exact redirect URIs, audience and roles. Browser clients use Authorization Code with PKCE; retain a local appliance recovery administrator. For KMIP, generate the client key and CSR on the consumer, sign only the CSR on the appliance, install the returned certificate and CA chain on the consumer, then approve its exact source network. Test with a disposable encrypted workload before moving persistent keys. Do not remove a key provider while a workload still depends on its keys.

## Proxy and troubleshooting

Reverse-proxy routes require a specific trusted upstream, expected TLS name and access policy. The optional forward proxy is an explicit egress service for approved source networks; it is not a gateway and does not intercept TLS. For an outage, refresh Health Status, run bounded diagnostics, review the owning service's connection log and functional-test history, then download a support bundle if needed. Confirm DNS, NTP and certificate trust before troubleshooting OIDC. Check mutual-TLS client trust and allowed source networks before troubleshooting KMIP. For an update failure, inspect Appliance Updates and restore the qualified prior release only after reviewing its health and the effect on active clients.
