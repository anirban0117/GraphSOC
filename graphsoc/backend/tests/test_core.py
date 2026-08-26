"""
Unit tests for the non-API core (event generation, ML, graph, temporal
correlation, ATT&CK mapping, risk scoring, RAG, agent). Run with:

    cd backend && pytest -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.synthetic import (
    generate_benign_stream, scenario_credential_compromise_to_exfiltration,
    scenario_brute_force, scenario_port_scan, generate_dataset,
)
from app.ml.features import featurize
from app.ml.baseline import BaselineClassifier, AnomalyDetector
from app.graph.security_graph import SecurityGraph
from app.graph.temporal import TemporalCorrelator
from app.security.attack_mapping import AttackMapper
from app.security.risk import compute_risk, severity_from_score
from app.rag.retriever import TfidfRetriever
from app.agent.investigator import InvestigationAgent


def test_benign_stream_shape():
    events = generate_benign_stream(50)
    assert len(events) == 50
    assert all(e["label"] == "Benign" for e in events)
    assert all("event_id" in e and "timestamp" in e for e in events)


def test_credential_compromise_scenario_has_five_stages():
    events = scenario_credential_compromise_to_exfiltration()
    assert len(events) == 5
    assert events[0]["event_type"] == "authentication"
    assert events[-1]["attack_type"] == "exfiltration"
    # chronological order
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)


def test_brute_force_scenario_ends_in_success():
    events = scenario_brute_force(user="dave")
    assert len(events) == 9
    assert all(e["status"] == "failure" for e in events[:-1])
    assert events[-1]["status"] == "success"


def test_featurize_produces_numeric_matrix():
    events = generate_dataset(n_benign=30, seed=1)
    df = featurize(events)
    assert len(df) == len(events)
    assert df.select_dtypes(exclude="number").empty  # every column numeric


def test_baseline_classifier_trains_and_predicts():
    events = generate_dataset(n_benign=300, seed=1)
    clf = BaselineClassifier()
    metrics = clf.train(events)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["n_test_samples"] > 0
    preds = clf.predict(events[:5])
    assert len(preds) == 5
    assert all("confidence" in p for p in preds)


def test_anomaly_detector_flags_reasonable_fraction():
    events = generate_dataset(n_benign=300, seed=2)
    det = AnomalyDetector(contamination=0.05)
    metrics = det.train(events)
    assert 0.0 < metrics["anomaly_rate"] < 0.5


def test_security_graph_connects_entities():
    events = scenario_credential_compromise_to_exfiltration(user="alice")
    g = SecurityGraph().build(events)
    stats = g.stats()
    assert stats["num_nodes"] > 0
    assert stats["num_edges"] > 0
    signal = g.entity_risk_signal("USER", "alice")
    assert signal["neighbor_count"] > 0


def test_temporal_correlator_finds_related_events():
    benign = generate_benign_stream(50)
    attack = scenario_credential_compromise_to_exfiltration(user="alice")
    all_events = benign + attack
    correlator = TemporalCorrelator(all_events)
    related = correlator.correlate_alert(attack[0], window_minutes=30)
    # every attack-scenario event for this user/device should be captured
    assert len(related) >= len(attack)


def test_attack_mapper_reconstructs_full_chain():
    events = scenario_credential_compromise_to_exfiltration()
    mapper = AttackMapper()
    mappings = mapper.map_events(events)
    mapped_ids = {m["id"] for m in mappings}
    assert {"T1078", "T1059.001", "T1021", "T1071.001", "T1041"}.issubset(mapped_ids)
    for m in mappings:
        assert m["evidence_event_ids"]  # every mapping cites evidence


def test_attack_mapper_detects_brute_force():
    events = scenario_brute_force()
    mapper = AttackMapper()
    mappings = mapper.map_events(events)
    assert any(m["id"] == "T1110" for m in mappings)


def test_attack_mapper_detects_port_scan():
    events = scenario_port_scan()
    mapper = AttackMapper()
    mappings = mapper.map_events(events)
    assert any(m["id"] == "T1046" for m in mappings)


def test_risk_scoring_is_explainable_and_bounded():
    result = compute_risk(ml_confidence=0.9, anomaly_score=80, graph_fanout={"distinct_neighbor_types": 4},
                           attack_techniques=[{}, {}, {}], correlated_events=[{"severity": "HIGH"}])
    assert 0 <= result["risk_score"] <= 100
    assert len(result["explanation"]) == 5
    assert result["severity"] == severity_from_score(result["risk_score"])


def test_rag_retrieval_returns_relevant_docs():
    retriever = TfidfRetriever()
    results = retriever.retrieve("brute force repeated login failures", top_k=3)
    assert len(results) > 0
    assert any("brute" in r["document_id"].lower() or "T1110" in r["document_id"] for r in results)


def test_investigation_agent_full_pipeline():
    benign = generate_benign_stream(150)
    attack = scenario_credential_compromise_to_exfiltration(user="alice")
    all_events = benign + attack
    all_events.sort(key=lambda e: e["timestamp"])

    agent = InvestigationAgent(all_events)
    incident = agent.investigate(attack[0], ml_confidence=0.9, anomaly_score=75)

    assert incident["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert incident["attack_chain"]  # non-empty chain reconstructed
    assert "alice" in incident["affected_users"]
    assert incident["evidence"]
    assert incident["recommended_actions"]
    assert len(incident["agent_trace"]) == 8  # all 8 agent steps logged
    # every technique cites the evidence event ids it used
    for t in incident["attack_techniques"]:
        assert t["evidence_event_ids"]
