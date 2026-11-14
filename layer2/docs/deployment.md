# Layer 2 Deployment

1. Create VLANs for User, AI, Server, IoT, Management, and Data.
2. Route inter-VLAN traffic through a dedicated firewall/router.
3. Apply the default-deny policy and explicitly add required flows.
4. Run Suricata on the traffic visibility point.
5. Send Suricata EVE alerts to Sentinel's `/v1/events` endpoint.
6. Monitor drops and false positives before enabling automatic isolation.
7. Keep an out-of-band management path for recovery.

## Production requirements

- Do not expose the firewall administration UI to the Internet.
- Restrict management access to the Management zone.
- Back up firewall configuration securely.
- Test every policy change in a staging environment.
- Use redundant DNS/NTP where required.
- Protect Sentinel event endpoints with authentication and TLS in production.
