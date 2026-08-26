"""
Phase 9: MITRE ATT&CK knowledge layer + rule-based mapping from observed
behavior to techniques.

Technique IDs/names/tactics are loaded verbatim from knowledge/mitre/techniques.json
(a small curated subset of the real Enterprise ATT&CK matrix) — nothing here
invents an ATT&CK ID. The mapping rules are transparent and evidence-based:
each mapping rule states exactly which observed event condition triggered it.
"""

from __future__ import annotations

import json
from pathlib import Path

KNOWLEDGE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent / "knowledge" / "mitre" / "techniques.json"
)

SUSPICIOUS_PROCESSES = {"powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "mimikatz.exe"}
SENSITIVE_PORTS = {445, 3389, 22, 135, 139}


def load_techniques() -> dict:
    return json.loads(KNOWLEDGE_PATH.read_text())


class AttackMapper:
    def __init__(self):
        self.techniques = load_techniques()

    def get_technique(self, technique_id: str) -> dict | None:
        return self.techniques.get(technique_id)

    def get_related_techniques(self, tactic: str) -> list[dict]:
        return [t for t in self.techniques.values() if t["tactic"] == tactic]

    def get_tactic(self, tactic: str) -> list[dict]:
        return self.get_related_techniques(tactic)

    def map_events(self, events: list[dict]) -> list[dict]:
        """
        Rule-based mapping (Sigma-style thinking, simplified): each rule
        inspects observed event fields and, if matched, emits a technique
        with the specific event(s) that justified it.
        """
        mappings: list[dict] = []
        auth_failures = [e for e in events if e.get("event_type") == "authentication" and e.get("status") == "failure"]
        auth_success = [e for e in events if e.get("event_type") == "authentication" and e.get("status") == "success"]

        if len(auth_failures) >= 5 and auth_success:
            mappings.append({
                **self.techniques["T1110"],
                "evidence_event_ids": [e["event_id"] for e in auth_failures + auth_success],
                "rationale": f"{len(auth_failures)} failed logins followed by a success within the correlation window.",
            })

        unseen_ip_logins = [
            e for e in events
            if e.get("event_type") == "authentication" and e.get("status") == "success"
            and e.get("metadata", {}).get("note") == "login from unseen IP"
        ]
        if unseen_ip_logins:
            mappings.append({
                **self.techniques["T1078"],
                "evidence_event_ids": [e["event_id"] for e in unseen_ip_logins],
                "rationale": "Successful authentication from a source IP not previously associated with this account.",
            })

        proc_events = [
            e for e in events
            if e.get("event_type") == "process_execution"
            and (e.get("process_name") or "").lower() in SUSPICIOUS_PROCESSES
        ]
        if proc_events:
            mappings.append({
                **self.techniques["T1059.001"],
                "evidence_event_ids": [e["event_id"] for e in proc_events],
                "rationale": f"Execution of {sorted({e.get('process_name') for e in proc_events})} shortly after authentication.",
            })

        lateral_events = [
            e for e in events
            if e.get("event_type") == "network_connection"
            and e.get("destination_port") in SENSITIVE_PORTS
            and (e.get("destination_ip") or "").startswith("10.")
        ]
        if lateral_events:
            mappings.append({
                **self.techniques["T1021"],
                "evidence_event_ids": [e["event_id"] for e in lateral_events],
                "rationale": "Connection to an internal host on a remote-service port (SMB/RDP/SSH) atypical for this account.",
            })

        # port scan: many distinct destination ports to the same host, mostly rejected, short window
        by_target = {}
        for e in events:
            if e.get("event_type") == "network_connection" and e.get("status") == "rejected":
                by_target.setdefault(e.get("destination_ip"), []).append(e)
        for target, evs in by_target.items():
            ports = {e.get("destination_port") for e in evs}
            if len(ports) >= 5:
                mappings.append({
                    **self.techniques["T1046"],
                    "evidence_event_ids": [e["event_id"] for e in evs],
                    "rationale": f"{len(ports)} distinct ports probed against {target}, mostly rejected.",
                })

        c2_events = [
            e for e in events
            if e.get("event_type") == "network_connection"
            and not (e.get("destination_ip") or "").startswith("10.")
            and e.get("action") == "connect"
        ]
        if c2_events and lateral_events:
            mappings.append({
                **self.techniques["T1071.001"],
                "evidence_event_ids": [e["event_id"] for e in c2_events],
                "rationale": "Outbound connection to an external IP immediately following internal lateral movement.",
            })

        exfil_events = [
            e for e in events
            if e.get("event_type") == "network_connection" and (e.get("bytes_sent") or 0) > 10_000_000
        ]
        if exfil_events:
            mappings.append({
                **self.techniques["T1041"],
                "evidence_event_ids": [e["event_id"] for e in exfil_events],
                "rationale": f"Outbound transfer of {max(e.get('bytes_sent', 0) for e in exfil_events):,} bytes to an external destination.",
            })

        return mappings
