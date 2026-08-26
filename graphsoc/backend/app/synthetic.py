"""
Synthetic security event generator.

Produces two things:
1. Baseline "normal enterprise noise" — logins, file access, DNS, etc.
2. Labeled attack scenarios that unfold as a *sequence* of correlated
   events across time, entities, and log types — the thing single-event
   detectors miss and GraphSOC's correlation layer is meant to catch.

Every event is a plain dict matching backend/app/schemas.py::SecurityEvent
so it can be validated by Pydantic on ingestion, or consumed directly by
ml/graph/agent modules during offline experimentation.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
DEVICES = {
    "alice": "LAPTOP-07",
    "bob": "LAPTOP-12",
    "carol": "LAPTOP-03",
    "dave": "LAPTOP-19",
    "erin": "LAPTOP-21",
    "frank": "LAPTOP-05",
}
INTERNAL_SERVERS = ["SERVER-DB01", "SERVER-APP02", "SERVER-FILE01"]
NORMAL_IPS = [f"10.0.0.{i}" for i in range(10, 60)]
SUSPICIOUS_EXTERNAL_IPS = ["185.220.101.7", "45.155.205.233", "193.106.191.15"]
NORMAL_PROCESSES = ["chrome.exe", "outlook.exe", "explorer.exe", "teams.exe", "excel.exe"]


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _base_event(event_type: str, ts: datetime, **fields) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _iso(ts),
        "event_type": event_type,
        "source": "synthetic",
        "label": fields.pop("label", "Benign"),
        "attack_type": fields.pop("attack_type", None),
        "metadata": fields.pop("metadata", {}),
        **fields,
    }


def generate_benign_stream(n: int, start: datetime | None = None) -> list[dict]:
    """Ordinary enterprise noise: logins, DNS lookups, file access, etc."""
    start = start or datetime.now(timezone.utc) - timedelta(hours=6)
    events = []
    t = start
    for _ in range(n):
        t += timedelta(seconds=random.randint(5, 240))
        user = random.choice(USERS)
        device = DEVICES[user]
        kind = random.choice(
            ["authentication", "dns", "process_execution", "file_access", "network_connection"]
        )
        if kind == "authentication":
            events.append(_base_event(
                "authentication", t, user_id=user, device_id=device,
                source_ip=random.choice(NORMAL_IPS), action="login", status="success",
                severity="LOW",
            ))
        elif kind == "dns":
            events.append(_base_event(
                "dns", t, user_id=user, device_id=device,
                source_ip=random.choice(NORMAL_IPS),
                resource=random.choice(["outlook.office365.com", "github.com", "google.com"]),
                action="query", status="success", severity="LOW",
            ))
        elif kind == "process_execution":
            events.append(_base_event(
                "process_execution", t, user_id=user, device_id=device,
                process_name=random.choice(NORMAL_PROCESSES), process_id=random.randint(1000, 9000),
                parent_process="explorer.exe", status="success", severity="LOW",
            ))
        elif kind == "file_access":
            events.append(_base_event(
                "file_access", t, user_id=user, device_id=device,
                resource=random.choice(["report.docx", "budget.xlsx", "notes.txt"]),
                action="read", status="success", severity="LOW",
            ))
        else:
            events.append(_base_event(
                "network_connection", t, user_id=user, device_id=device,
                source_ip=random.choice(NORMAL_IPS), destination_ip=random.choice(NORMAL_IPS),
                destination_port=443, protocol="TCP",
                bytes_sent=random.randint(500, 5000), bytes_received=random.randint(500, 5000),
                status="established", severity="LOW",
            ))
    return events


# ---------------------------------------------------------------------------
# Attack scenarios — each returns a chronologically ordered event sequence
# plus metadata describing the intended ATT&CK narrative, used both for
# training/eval labels and for the live simulator (scripts/simulate_attack.py)
# ---------------------------------------------------------------------------

def scenario_credential_compromise_to_exfiltration(
    user: str = "alice", start: datetime | None = None
) -> list[dict]:
    """
    Mirrors the exact chain described in the project design doc:
    unusual login -> PowerShell execution -> internal server access ->
    external C2 communication -> large outbound transfer.
    """
    start = start or datetime.now(timezone.utc)
    device = DEVICES[user]
    external_ip = random.choice(SUSPICIOUS_EXTERNAL_IPS)
    unusual_ip = "203.0.113.44"  # TEST-NET, plausible "unusual" login origin
    events = []

    t = start
    events.append(_base_event(
        "authentication", t, user_id=user, device_id=device, source_ip=unusual_ip,
        action="login", status="success", severity="MEDIUM",
        label="Malicious", attack_type="credential_compromise",
        metadata={"scenario": "cred_compromise_exfil", "step": 1, "note": "login from unseen IP"},
    ))

    t += timedelta(seconds=42)
    events.append(_base_event(
        "process_execution", t, user_id=user, device_id=device,
        process_name="powershell.exe", process_id=random.randint(1000, 9000),
        parent_process="explorer.exe", action="execute",
        resource="-enc <base64 removed>", status="success", severity="HIGH",
        label="Malicious", attack_type="suspicious_execution",
        metadata={"scenario": "cred_compromise_exfil", "step": 2,
                  "attack_technique": "T1059.001"},
    ))

    t += timedelta(seconds=75)
    internal_server = random.choice(INTERNAL_SERVERS)
    events.append(_base_event(
        "network_connection", t, user_id=user, device_id=device,
        source_ip=unusual_ip, destination_ip="10.0.0.50", destination_port=445,
        protocol="TCP", resource=internal_server, action="connect", status="established",
        severity="HIGH", label="Malicious", attack_type="lateral_movement",
        metadata={"scenario": "cred_compromise_exfil", "step": 3,
                  "attack_technique": "T1021"},
    ))

    t += timedelta(seconds=110)
    events.append(_base_event(
        "network_connection", t, user_id=user, device_id=device,
        source_ip="10.0.0.50", destination_ip=external_ip, destination_port=443,
        protocol="TCP", action="connect", status="established", severity="HIGH",
        label="Malicious", attack_type="command_and_control",
        metadata={"scenario": "cred_compromise_exfil", "step": 4,
                  "attack_technique": "T1071.001"},
    ))

    t += timedelta(seconds=60)
    events.append(_base_event(
        "network_connection", t, user_id=user, device_id=device,
        source_ip="10.0.0.50", destination_ip=external_ip, destination_port=443,
        protocol="TCP", action="transfer", status="established",
        bytes_sent=random.randint(50_000_000, 200_000_000), bytes_received=2000,
        severity="CRITICAL", label="Malicious", attack_type="exfiltration",
        metadata={"scenario": "cred_compromise_exfil", "step": 5,
                  "attack_technique": "T1041"},
    ))
    return events


def scenario_brute_force(user: str | None = None, start: datetime | None = None) -> list[dict]:
    user = user or random.choice(USERS)
    device = DEVICES[user]
    start = start or datetime.now(timezone.utc)
    external_ip = random.choice(SUSPICIOUS_EXTERNAL_IPS)
    events = []
    t = start
    for i in range(8):
        t += timedelta(seconds=random.randint(2, 6))
        events.append(_base_event(
            "authentication", t, user_id=user, device_id=device, source_ip=external_ip,
            action="login", status="failure", severity="MEDIUM",
            label="Malicious", attack_type="brute_force",
            metadata={"scenario": "brute_force", "attempt": i + 1, "attack_technique": "T1110"},
        ))
    t += timedelta(seconds=4)
    events.append(_base_event(
        "authentication", t, user_id=user, device_id=device, source_ip=external_ip,
        action="login", status="success", severity="HIGH",
        label="Malicious", attack_type="brute_force",
        metadata={"scenario": "brute_force", "note": "success after repeated failures",
                  "attack_technique": "T1110"},
    ))
    return events


def scenario_port_scan(start: datetime | None = None) -> list[dict]:
    start = start or datetime.now(timezone.utc)
    external_ip = random.choice(SUSPICIOUS_EXTERNAL_IPS)
    target = "10.0.0.50"
    events = []
    t = start
    for port in [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]:
        t += timedelta(milliseconds=random.randint(100, 500))
        events.append(_base_event(
            "network_connection", t, source_ip=external_ip, destination_ip=target,
            destination_port=port, protocol="TCP", action="connect", status="rejected",
            severity="MEDIUM", label="Malicious", attack_type="port_scan",
            metadata={"scenario": "port_scan", "attack_technique": "T1046"},
        ))
    return events


SCENARIOS = {
    "credential_compromise_exfiltration": scenario_credential_compromise_to_exfiltration,
    "brute_force": scenario_brute_force,
    "port_scan": scenario_port_scan,
}


def generate_dataset(n_benign: int = 400, seed: int | None = 42) -> list[dict]:
    """Build a mixed benign + attack dataset for offline training/eval."""
    if seed is not None:
        random.seed(seed)
    events = generate_benign_stream(n_benign)
    events += scenario_credential_compromise_to_exfiltration()
    events += scenario_brute_force()
    events += scenario_port_scan()
    events += scenario_credential_compromise_to_exfiltration(user="bob")
    events += scenario_brute_force(user="carol")
    events.sort(key=lambda e: e["timestamp"])
    return events


if __name__ == "__main__":
    import json
    ds = generate_dataset()
    print(f"generated {len(ds)} events")
    print(json.dumps(ds[0], indent=2))
