"""Feature engineering: raw normalized events -> numeric feature vectors."""

from __future__ import annotations

from datetime import datetime

import numpy as np
import pandas as pd

EVENT_TYPES = [
    "authentication", "network_connection", "dns", "process_execution",
    "file_access", "privilege_change", "cloud_activity",
]

SUSPICIOUS_PROCESSES = {"powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "mimikatz.exe"}
SENSITIVE_PORTS = {22, 23, 445, 3389, 135, 139}


def _parse_ts(ts) -> datetime:
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))


def events_to_dataframe(events: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(events)


def featurize(events: list[dict]) -> pd.DataFrame:
    """
    Turn a list of normalized SecurityEvent dicts into a feature matrix.

    Features are intentionally simple and explainable — this is the
    baseline layer; the graph/GNN layer is where relational structure
    gets captured instead of engineered by hand.
    """
    rows = []
    for e in events:
        ts = _parse_ts(e["timestamp"])
        event_type = e.get("event_type", "")
        process = (e.get("process_name") or "").lower()
        dest_port = e.get("destination_port")
        bytes_sent = e.get("bytes_sent") or 0
        bytes_received = e.get("bytes_received") or 0
        status = (e.get("status") or "").lower()

        row = {
            "hour_of_day": ts.hour,
            "is_off_hours": 1 if (ts.hour < 6 or ts.hour > 21) else 0,
            "is_auth_failure": 1 if (event_type == "authentication" and status == "failure") else 0,
            "is_auth_success": 1 if (event_type == "authentication" and status == "success") else 0,
            "is_suspicious_process": 1 if process in SUSPICIOUS_PROCESSES else 0,
            "is_sensitive_port": 1 if dest_port in SENSITIVE_PORTS else 0,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "log_bytes_sent": np.log1p(bytes_sent),
            "large_transfer": 1 if bytes_sent > 10_000_000 else 0,
            "is_status_rejected": 1 if status == "rejected" else 0,
        }
        for et in EVENT_TYPES:
            row[f"type_{et}"] = 1 if event_type == et else 0

        rows.append(row)

    return pd.DataFrame(rows).fillna(0)


def binary_labels(events: list[dict]) -> np.ndarray:
    return np.array([0 if (e.get("label") or "Benign") == "Benign" else 1 for e in events])


def multiclass_labels(events: list[dict]) -> np.ndarray:
    return np.array([e.get("attack_type") or "benign" for e in events])
