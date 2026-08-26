"""
Phase 14: Explainable risk engine.

Combines several signals into a 0-100 risk score with a documented,
inspectable formula (no unexplained magic constants) and returns the
per-factor breakdown so the UI/report can show *why* the score is what
it is.

Weights below are a deliberate starting design, documented here so they
can be tuned/justified in the project report rather than treated as
black-box:

  ml_confidence        25%  - supervised classifier's malicious probability
  anomaly_score         15%  - unsupervised anomaly score (0-100, batch-normalized)
  graph_fanout          15%  - how many distinct entity types the account/device touches
  attack_chain_length   25%  - number of distinct ATT&CK techniques mapped
  severity_events       20%  - fraction of correlated events marked HIGH/CRITICAL
"""

from __future__ import annotations

WEIGHTS = {
    "ml_confidence": 0.25,
    "anomaly_score": 0.15,
    "graph_fanout": 0.15,
    "attack_chain_length": 0.25,
    "severity_events": 0.20,
}

SEVERITY_THRESHOLDS = [
    (85, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
]


def severity_from_score(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def compute_risk(
    ml_confidence: float = 0.0,        # 0-1
    anomaly_score: float = 0.0,        # 0-100
    graph_fanout: dict | None = None,  # from SecurityGraph.entity_risk_signal
    attack_techniques: list | None = None,
    correlated_events: list | None = None,
) -> dict:
    graph_fanout = graph_fanout or {}
    attack_techniques = attack_techniques or []
    correlated_events = correlated_events or []

    # normalize each signal to 0-100
    s_ml = min(100.0, ml_confidence * 100)
    s_anomaly = min(100.0, anomaly_score)

    distinct_types = graph_fanout.get("distinct_neighbor_types", 0)
    s_graph = min(100.0, distinct_types / 4 * 100)  # 4 distinct types = fully suspicious fanout

    s_chain = min(100.0, len(attack_techniques) / 5 * 100)  # 5+ chained techniques = max

    if correlated_events:
        high_sev = sum(1 for e in correlated_events if e.get("severity") in ("HIGH", "CRITICAL"))
        s_severity = (high_sev / len(correlated_events)) * 100
    else:
        s_severity = 0.0

    factors = {
        "ml_confidence": round(s_ml, 1),
        "anomaly_score": round(s_anomaly, 1),
        "graph_fanout": round(s_graph, 1),
        "attack_chain_length": round(s_chain, 1),
        "severity_events": round(s_severity, 1),
    }

    total = sum(factors[k] * WEIGHTS[k] for k in WEIGHTS)
    total = round(min(100.0, total), 1)

    return {
        "risk_score": total,
        "severity": severity_from_score(total),
        "factors": factors,
        "weights": WEIGHTS,
        "explanation": [
            f"{k} contributed {round(factors[k] * WEIGHTS[k], 1)} points "
            f"(raw {factors[k]}/100 x weight {WEIGHTS[k]})"
            for k in WEIGHTS
        ],
    }
