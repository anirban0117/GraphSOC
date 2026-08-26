#!/usr/bin/env python3
"""
Phase 17: Live demo simulator.

Streams synthetic events to a running GraphSOC backend (default
http://localhost:8000), then triggers the investigation agent on the
first event of the attack scenario — exactly like a real SOC alert
firing and an analyst opening the investigation.

Usage:
    python scripts/simulate_attack.py --scenario credential_compromise_exfiltration
    python scripts/simulate_attack.py --scenario brute_force
    python scripts/simulate_attack.py --scenario port_scan
    python scripts/simulate_attack.py --list

These are synthetic events only. No real network activity is generated.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.synthetic import SCENARIOS, generate_benign_stream  # noqa: E402


def post(url: str, payload: dict) -> dict:
    data = json.dumps(payload, default=str).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}")
        raise


def main():
    parser = argparse.ArgumentParser(description="GraphSOC live attack simulator")
    parser.add_argument("--scenario", default="credential_compromise_exfiltration",
                         choices=list(SCENARIOS.keys()))
    parser.add_argument("--host", default="http://localhost:8000")
    parser.add_argument("--n-benign", type=int, default=200)
    parser.add_argument("--list", action="store_true", help="list available scenarios and exit")
    parser.add_argument("--investigate", action="store_true", default=True,
                         help="automatically run the investigation agent on the first attack event")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  - {name}")
        return

    print(f"[1/4] Generating {args.n_benign} benign background events...")
    benign = generate_benign_stream(args.n_benign)

    print(f"[2/4] Generating attack scenario: {args.scenario}")
    attack_events = SCENARIOS[args.scenario]()
    print(f"       {len(attack_events)} attack events generated")

    print("[3/4] Streaming events to backend...")
    all_events = benign + attack_events
    all_events.sort(key=lambda e: e["timestamp"])
    resp = post(f"{args.host}/api/events/bulk", {"events": all_events})
    print(f"       ingested: {resp}")

    if args.investigate:
        print("[4/4] Triggering investigation agent on first attack event...")
        trigger = attack_events[0]
        result = post(f"{args.host}/api/investigate",
                       {"triggering_event_id": trigger["event_id"], "window_minutes": 30})
        print()
        print("=" * 70)
        print(f"INCIDENT {result['incident_id']}")
        print(f"Severity: {result['severity']}  |  Risk score: {result['risk_score']}/100")
        print(f"Attack chain: {' -> '.join(result['attack_chain'])}")
        print("-" * 70)
        print(result["investigation_summary"])
        print("-" * 70)
        print("Recommended actions:")
        for a in result["recommended_actions"]:
            print(f"  - {a['action']}")
        print("=" * 70)
        print(f"\nOpen the dashboard at {args.host.replace('8000', '5173')} "
              f"or view raw JSON at {args.host}/api/incidents/{result['incident_id']}")


if __name__ == "__main__":
    main()
