"""
GraphSOC backend entrypoint.

Run with:
    uvicorn app.main:app --reload --port 8000

See README.md for full setup instructions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app import store
from app.schemas import SecurityEvent, EventBulkIngest
from app.synthetic import generate_dataset, SCENARIOS, generate_benign_stream
from app.ml.baseline import BaselineClassifier, AnomalyDetector, run_experiment_and_save_report, MODEL_DIR
from app.graph.security_graph import SecurityGraph
from app.security.attack_mapping import AttackMapper
from app.agent.investigator import InvestigationAgent

app = FastAPI(
    title="GraphSOC API",
    description="Graph-enhanced agentic Security Operations Center — MVP backend.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # relax for local dev / demo; restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

_mapper = AttackMapper()
_classifier: Optional[BaselineClassifier] = None
_anomaly: Optional[AnomalyDetector] = None


@app.on_event("startup")
def on_startup():
    store.init_db()
    _try_load_models()


def _try_load_models():
    global _classifier, _anomaly
    try:
        _classifier = BaselineClassifier.load()
    except FileNotFoundError:
        _classifier = None
    try:
        _anomaly = AnomalyDetector.load()
    except FileNotFoundError:
        _anomaly = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "events_stored": store.count_events(),
        "classifier_trained": _classifier is not None,
        "anomaly_model_trained": _anomaly is not None,
    }


# ---------------------------------------------------------------------------
# Events (Phase 2)
# ---------------------------------------------------------------------------

@app.post("/api/events")
def ingest_event(event: SecurityEvent):
    store.insert_event(event.model_dump(mode="json"))
    return {"status": "ingested", "event_id": event.event_id}


@app.post("/api/events/bulk")
def ingest_bulk(payload: EventBulkIngest):
    events = [e.model_dump(mode="json") for e in payload.events]
    store.insert_events(events)
    return {"status": "ingested", "count": len(events)}


@app.get("/api/events")
def list_events(limit: int = 200, event_type: Optional[str] = None, user_id: Optional[str] = None):
    return store.get_events(limit=limit, event_type=event_type, user_id=user_id)


@app.get("/api/events/{event_id}")
def get_event(event_id: str):
    e = store.get_event(event_id)
    if not e:
        raise HTTPException(404, "event not found")
    return e


class SeedRequest(BaseModel):
    n_benign: int = 400
    include_attacks: bool = True
    seed: Optional[int] = 42


@app.post("/api/dev/seed")
def seed_data(req: SeedRequest):
    """Convenience endpoint: populate the DB with synthetic events for demoing/testing."""
    if req.include_attacks:
        events = generate_dataset(n_benign=req.n_benign, seed=req.seed)
    else:
        events = generate_benign_stream(req.n_benign)
    store.insert_events(events)
    return {"status": "seeded", "count": len(events)}


@app.post("/api/dev/reset")
def reset():
    store.reset_db()
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# ML (Phase 3/4/19)
# ---------------------------------------------------------------------------

@app.post("/api/ml/train")
def train_models(n_benign: int = 500, seed: int = 42):
    global _classifier, _anomaly
    events = generate_dataset(n_benign=n_benign, seed=seed)

    _classifier = BaselineClassifier()
    clf_metrics = _classifier.train(events)
    _classifier.save()

    _anomaly = AnomalyDetector()
    anomaly_metrics = _anomaly.train(events)
    _anomaly.save()

    report_path = Path(__file__).resolve().parent.parent / "experiment_report.json"
    run_experiment_and_save_report(events, report_path)

    return {"classifier": clf_metrics, "anomaly_detector": anomaly_metrics, "training_set_size": len(events)}


@app.get("/api/metrics")
def get_metrics():
    report_path = Path(__file__).resolve().parent.parent / "experiment_report.json"
    if not report_path.exists():
        raise HTTPException(404, "No experiment report yet. POST /api/ml/train first.")
    import json
    return json.loads(report_path.read_text())


# ---------------------------------------------------------------------------
# Graph (Phase 5)
# ---------------------------------------------------------------------------

@app.get("/api/graph/entity/{kind}/{value}")
def graph_entity(kind: str, value: str, hops: int = 2):
    events = store.get_events(limit=5000)
    g = SecurityGraph().build(events)
    return g.get_subgraph(kind.upper(), value, hops=hops)


@app.get("/api/graph/stats")
def graph_stats():
    events = store.get_events(limit=5000)
    g = SecurityGraph().build(events)
    return g.stats()


# ---------------------------------------------------------------------------
# MITRE ATT&CK (Phase 9)
# ---------------------------------------------------------------------------

@app.get("/api/mitre/techniques")
def list_techniques():
    return list(_mapper.techniques.values())


@app.get("/api/mitre/techniques/{technique_id}")
def get_technique(technique_id: str):
    t = _mapper.get_technique(technique_id)
    if not t:
        raise HTTPException(404, "technique not found")
    return t


# ---------------------------------------------------------------------------
# RAG (Phase 10)
# ---------------------------------------------------------------------------

class RagQuery(BaseModel):
    query: str
    top_k: int = 3


@app.post("/api/rag/search")
def rag_search(q: RagQuery):
    from app.rag.retriever import TfidfRetriever
    retriever = TfidfRetriever()
    return retriever.retrieve(q.query, top_k=q.top_k)


# ---------------------------------------------------------------------------
# Investigation agent / incidents (Phase 12/13/15)
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    triggering_event_id: str
    window_minutes: int = 30


@app.post("/api/investigate")
def investigate(req: InvestigateRequest):
    trigger = store.get_event(req.triggering_event_id)
    if not trigger:
        raise HTTPException(404, "triggering event not found")

    all_events = store.get_events(limit=5000)

    ml_confidence, anomaly_score = 0.0, 0.0
    if _classifier is not None:
        try:
            pred = _classifier.predict([trigger])[0]
            ml_confidence = pred["confidence"]
        except Exception:
            pass
    if _anomaly is not None:
        try:
            score = _anomaly.score([trigger])[0]
            anomaly_score = score["risk_score"]
        except Exception:
            pass

    agent = InvestigationAgent(all_events)
    incident = agent.investigate(trigger, ml_confidence=ml_confidence,
                                  anomaly_score=anomaly_score, window_minutes=req.window_minutes)
    store.insert_incident(incident)
    return incident


@app.get("/api/incidents")
def list_incidents(limit: int = 50):
    return store.get_incidents(limit=limit)


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = store.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


# ---------------------------------------------------------------------------
# Demo: run a full scripted scenario end-to-end in one call
# ---------------------------------------------------------------------------

class DemoScenarioRequest(BaseModel):
    scenario: str = "credential_compromise_exfiltration"
    n_benign_context: int = 200


@app.post("/api/demo/run_scenario")
def run_demo_scenario(req: DemoScenarioRequest):
    """
    Seeds benign background traffic + one attack scenario, then immediately
    investigates the first event of the scenario. This is the single call
    that reproduces the "Example of the final experience" walkthrough.
    """
    if req.scenario not in SCENARIOS:
        raise HTTPException(400, f"unknown scenario. options: {list(SCENARIOS.keys())}")

    benign = generate_benign_stream(req.n_benign_context)
    attack_events = SCENARIOS[req.scenario]()
    store.insert_events(benign + attack_events)

    all_events = store.get_events(limit=5000)
    agent = InvestigationAgent(all_events)
    trigger = attack_events[0]

    ml_confidence, anomaly_score = 0.0, 0.0
    if _classifier is not None:
        try:
            ml_confidence = _classifier.predict([trigger])[0]["confidence"]
        except Exception:
            pass
    if _anomaly is not None:
        try:
            anomaly_score = _anomaly.score([trigger])[0]["risk_score"]
        except Exception:
            pass

    incident = agent.investigate(trigger, ml_confidence=ml_confidence, anomaly_score=anomaly_score)
    store.insert_incident(incident)
    return incident
