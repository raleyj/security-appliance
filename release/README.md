# Security Appliance 1.2 GA

Security Appliance 1.2 GA publishes qualified appliance build 1.2.18. The build is sealed from a validated appliance, removes deployment state and credentials, overwrites free OS blocks, attaches a fresh blank data disk, clears staging OVF values, and exposes masked deployment properties.

Qualification covers 107 automated tests, clean first boot, standard sign-in, static networking, DNS and NTP health, firewall isolation, all six service tests, trusted certificate enrollment, HTTP-to-HTTPS redirection, proxy policy, signed update and guarded restore, reboot persistence, fixed-function console recovery, and VMware vCenter KMIP encryption and decryption.

Download every numbered OVA part and one reconstruction script from the GitHub release. Reconstruct `Lab-Security-Appliance-1.2-GA.ova`, then verify it with the adjacent SHA-256 file before import.
