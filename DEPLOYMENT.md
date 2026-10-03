# Deployment

The appliance targets VMware vSphere and uses 4 vCPU, 8 GiB RAM, a 32 GiB OS disk, a separate 64 GiB data disk, and one network adapter.

Before import, create stable management, SSO, and KMIP DNS records; select approved DNS and NTP sources; and identify the management and KMIP client networks. The OVF deployment wizard collects hostname, domain, IPv4 mode, addressing, DNS, NTP, management CIDRs, service names, and three distinct deployment secrets.

The web administrator defaults to `admin`. Supply a unique 15–256 character password. Supply separate 16–256 character console-recovery and Keycloak-administrator passwords.

After first boot:

1. Open `https://<management-name>/admin/` and sign in.
2. Review identity, networking, DNS, NTP, storage, firewall, and service health.
3. Replace the temporary HTTPS certificate with a certificate issued for the management, SSO, and KMIP names.
4. Configure and test Keycloak/OIDC.
5. Enroll KMIP consumers using consumer-generated CSRs and explicit source networks.
6. Configure reverse-proxy routes and the optional forward-proxy policy.
7. Run every service functional test and complete first deployment.
8. Clear deployment-secret OVF values from the VM configuration after bootstrap.
