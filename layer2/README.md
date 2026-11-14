# SENTINEL Layer 2 — Network Fortress

Layer 2 turns Sentinel's network policy into host/router enforcement.

## Components

- `nftables/sentinel.nft.template` — default-deny Linux firewall policy.
- `suricata/suricata.yaml.example` — IDS/IPS telemetry configuration.
- `suricata_forwarder.py` — forwards Suricata alerts to Sentinel's event API.
- `config/zones.yaml` — canonical network-zone model.

## Zones

| Zone | CIDR | Purpose |
|---|---|---|
| User | 10.10.10.0/24 | Human devices |
| AI | 10.10.20.0/24 | Brahma/Jarvis/Thara agents |
| Server | 10.10.30.0/24 | Backend services |
| IoT | 10.10.40.0/24 | Cameras/sensors/devices |
| Management | 10.10.50.0/24 | Administrative systems |
| Data | 10.10.60.0/24 | Databases/storage |

## Deployment warning

Do not paste the nftables template onto a remote production host without first replacing interfaces, DNS resolver addresses, management CIDRs, and validating the policy locally. A bad default-deny rule can lock you out.

The policy is intentionally conservative. It is a starting point, not a finished enterprise ruleset.
