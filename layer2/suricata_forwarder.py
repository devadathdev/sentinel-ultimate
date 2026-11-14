#!/usr/bin/env python3
"""Forward Suricata EVE alerts to Sentinel's event API.

Fail-closed locally: if Sentinel is unavailable, the network firewall/IPS remains
responsible for enforcement; this process only forwards telemetry.
"""
import json, os, time, urllib.request

EVE = os.getenv("SENTINEL_EVE", "/var/log/suricata/eve.json")
URL = os.getenv("SENTINEL_EVENTS_URL", "http://127.0.0.1:8000/v1/events")
TOKEN = os.getenv("SENTINEL_EVENTS_TOKEN", "")


def send(event):
    body = json.dumps(event).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
    })
    with urllib.request.urlopen(req, timeout=3) as r:
        return 200 <= r.status < 300

with open(EVE, "r", encoding="utf-8") as f:
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event_type") != "alert":
            continue
        alert = record.get("alert", {})
        payload = {
            "source": "suricata",
            "event_type": "network_alert",
            "severity": alert.get("severity", 3),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dest_ip": record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "timestamp": record.get("timestamp"),
        }
        try:
            send(payload)
        except Exception:
            # Telemetry loss must not disable the firewall.
            pass
