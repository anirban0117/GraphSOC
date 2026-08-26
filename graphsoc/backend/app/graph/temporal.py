"""Phase 6: Temporal correlation — build attack timelines around an alert."""

from __future__ import annotations

from datetime import datetime, timedelta

WINDOWS_MINUTES = [5, 15, 30, 60]


def _parse(ts) -> datetime:
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))


class TemporalCorrelator:
    def __init__(self, events: list[dict]):
        self.events = sorted(events, key=lambda e: e["timestamp"])

    def correlate_alert(self, alert_event: dict, window_minutes: int = 30) -> list[dict]:
        """Return events touching the same user/device within +/- window of the alert."""
        t0 = _parse(alert_event["timestamp"])
        lo, hi = t0 - timedelta(minutes=window_minutes), t0 + timedelta(minutes=window_minutes)
        user = alert_event.get("user_id")
        device = alert_event.get("device_id")

        related = []
        for e in self.events:
            t = _parse(e["timestamp"])
            if not (lo <= t <= hi):
                continue
            if e.get("user_id") == user or e.get("device_id") == device:
                related.append(e)
        return related

    def build_timeline(self, alert_event: dict, window_minutes: int = 30) -> list[dict]:
        related = self.correlate_alert(alert_event, window_minutes)
        return [
            {
                "timestamp": e["timestamp"],
                "event_id": e.get("event_id"),
                "event_type": e.get("event_type"),
                "description": _describe(e),
                "severity": e.get("severity"),
            }
            for e in related
        ]

    def extract_temporal_features(self, alert_event: dict, window_minutes: int = 30) -> dict:
        related = self.correlate_alert(alert_event, window_minutes)
        if not related:
            return {
                "event_count": 0, "unique_devices": 0, "unique_ips": 0,
                "rare_processes": 0, "total_bytes_transferred": 0,
            }
        devices = {e.get("device_id") for e in related if e.get("device_id")}
        ips = {e.get("destination_ip") for e in related if e.get("destination_ip")}
        processes = {e.get("process_name") for e in related if e.get("process_name")}
        suspicious = {"powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe"}
        total_bytes = sum((e.get("bytes_sent") or 0) for e in related)
        return {
            "event_count": len(related),
            "unique_devices": len(devices),
            "unique_ips": len(ips),
            "rare_processes": len(processes & suspicious),
            "total_bytes_transferred": total_bytes,
        }


def _describe(e: dict) -> str:
    et = e.get("event_type")
    if et == "authentication":
        return f"Authentication {e.get('status')} from {e.get('source_ip')}"
    if et == "process_execution":
        return f"Process executed: {e.get('process_name')}"
    if et == "network_connection":
        return f"Connection to {e.get('destination_ip')}:{e.get('destination_port')}"
    if et == "dns":
        return f"DNS query for {e.get('resource')}"
    if et == "file_access":
        return f"File {e.get('action')}: {e.get('resource')}"
    return et or "event"
