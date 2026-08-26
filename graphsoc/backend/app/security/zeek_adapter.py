"""
Phase 18: Zeek adapter.

Converts Zeek's line-delimited JSON logs (conn.log, dns.log, ssh.log, ...)
into GraphSOC's normalized SecurityEvent shape. Offline-safe: reads a
JSON-lines file, never touches a live interface.

Enable JSON logging in Zeek with:
    zeek -e "redef LogAscii::use_json=T;" <scripts...>
or in local.zeek:
    @load policy/tuning/json-logs.zeek

Usage:
    python -m app.security.zeek_adapter conn.log > events.json
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path


def _ts(zeek_ts) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(float(zeek_ts), tz=timezone.utc).isoformat()


def conn_log_to_events(line: dict) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _ts(line.get("ts", 0)),
        "event_type": "network_connection",
        "source": "zeek_conn",
        "source_ip": line.get("id.orig_h"),
        "source_port": line.get("id.orig_p"),
        "destination_ip": line.get("id.resp_h"),
        "destination_port": line.get("id.resp_p"),
        "protocol": line.get("proto"),
        "action": "connect",
        "status": line.get("conn_state", "unknown"),
        "bytes_sent": line.get("orig_bytes", 0),
        "bytes_received": line.get("resp_bytes", 0),
        "metadata": {"zeek_uid": line.get("uid"), "service": line.get("service")},
    }


def dns_log_to_events(line: dict) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _ts(line.get("ts", 0)),
        "event_type": "dns",
        "source": "zeek_dns",
        "source_ip": line.get("id.orig_h"),
        "destination_ip": line.get("id.resp_h"),
        "resource": line.get("query"),
        "action": "query",
        "status": "success" if line.get("rcode_name") == "NOERROR" else "failure",
        "metadata": {"zeek_uid": line.get("uid"), "qtype": line.get("qtype_name")},
    }


def ssh_log_to_events(line: dict) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _ts(line.get("ts", 0)),
        "event_type": "authentication",
        "source": "zeek_ssh",
        "source_ip": line.get("id.orig_h"),
        "destination_ip": line.get("id.resp_h"),
        "action": "ssh_login",
        "status": "success" if line.get("auth_success") else "failure",
        "metadata": {"zeek_uid": line.get("uid"), "client": line.get("client")},
    }


LOG_TYPE_HANDLERS = {
    "conn": conn_log_to_events,
    "dns": dns_log_to_events,
    "ssh": ssh_log_to_events,
}


def convert_file(path: str | Path, log_type: str | None = None) -> list[dict]:
    """
    Reads a Zeek JSON-lines log file and returns normalized events.
    log_type is inferred from the filename (conn.log -> 'conn') if not given.
    """
    path = Path(path)
    if log_type is None:
        log_type = path.stem.split(".")[0]
    handler = LOG_TYPE_HANDLERS.get(log_type)
    if handler is None:
        raise ValueError(f"No Zeek adapter for log type '{log_type}'. "
                          f"Supported: {list(LOG_TYPE_HANDLERS)}")

    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            events.append(handler(record))
    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.security.zeek_adapter <path/to/conn.log>")
        sys.exit(1)
    evs = convert_file(sys.argv[1])
    print(json.dumps(evs, indent=2))
