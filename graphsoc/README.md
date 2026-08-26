# GraphSOC — Graph-Enhanced Agentic Security Operations Center

A working MVP of an AI-powered SOC that ingests security events, correlates
them across **time and entity relationships** (not just individually), maps
suspected behavior to **MITRE ATT&CK**, retrieves grounded defensive
knowledge (**RAG**), and runs a multi-step **investigation agent** that
produces an evidence-cited incident report — not a chatbot answer.

## Research question

> Can graph- and time-based multi-event correlation improve cyberattack
> detection and investigation quality compared with independent,
> event-level detection?

This MVP is built specifically to let you *run that experiment*: Phase 3/4
give you an event-level ML baseline; Phase 5/6 give you the graph +
temporal layer; `/api/ml/train` and `/api/metrics` return real, computed
numbers you can compare — never fabricated ones.

## What's actually implemented right now

| Layer | Status | Notes |
|---|---|---|
| Unified event schema | ✅ | `backend/app/schemas.py` |
| Synthetic data + 3 labeled attack scenarios | ✅ | `backend/app/synthetic.py` |
| Baseline ML (Random Forest / Logistic Regression) | ✅ | real sklearn metrics, no fabrication |
| Anomaly detector (Isolation Forest) | ✅ | |
| Security knowledge graph (NetworkX) | ✅ | Users/Devices/IPs/Processes/Resources |
| Temporal correlation (5/15/30/60 min windows) | ✅ | |
| MITRE ATT&CK mapping | ✅ | Rule-based, real technique IDs, evidence-cited |
| RAG retrieval | ✅ | TF-IDF over MITRE + playbook docs (see note below) |
| Investigation agent | ✅ | 8-step traced pipeline, mock LLM by default |
| REST API (FastAPI) | ✅ | events, incidents, graph, MITRE, RAG, agent |
| Dashboard | ✅ | single-file HTML, no build step |
| Zeek log adapter | ✅ | offline JSON-lines parser for conn/dns/ssh logs |
| Docker / docker-compose | ✅ | |
| Tests | ✅ | 14 tests, all passing, covers every core module |
| GNN (GraphSAGE/GAT) | 🔲 not yet | see `ROADMAP.md` Phase R1 — this is your next big milestone |
| Dense-embedding RAG (FAISS + sentence-transformers) | 🔲 not yet | TF-IDF works today with zero downloads; see `ROADMAP.md` Phase R2 |
| Real CICIDS2017 ingestion | 🔲 not yet | adapter pattern is in place, see `ROADMAP.md` Phase R3 |
| React frontend | 🔲 not yet | current dashboard is deliberately framework-free; see `ROADMAP.md` Phase R4 |

**Why TF-IDF instead of FAISS/sentence-transformers for RAG right now:**
those require a model download and (for FAISS) a native build, which isn't
guaranteed to work on every laptop out of the box. The `TfidfRetriever` and
`EmbeddingRetriever` classes share an identical interface (`retrieve()`,
`retrieve_for_incident()`), so swapping is a one-file change once you're
ready — this is intentional, documented architecture, not a shortcut hidden
from you.

## Architecture

```
Synthetic / Zeek / CICIDS events
        |
Normalization (Pydantic schema)
        |
   +----+----+
   |         |
ML baseline  Anomaly detector          <- Phase 3/4, real sklearn metrics
   |         |
   +----+----+
        |
Security Graph (NetworkX)              <- Phase 5
        |
Temporal Correlator (5/15/30/60 min)   <- Phase 6
        |
MITRE ATT&CK Mapper (rule-based)       <- Phase 9, real technique IDs
        |
RAG retrieval (TF-IDF over playbooks)  <- Phase 10
        |
Investigation Agent (8-step trace)     <- Phase 12
        |
Incident (evidence-cited, JSON)        <- Phase 13
        |
FastAPI REST API  ->  Dashboard
```

## Project structure

```
graphsoc/
  backend/
    app/
      schemas.py           unified event/alert/incident schema
      synthetic.py          synthetic event + attack scenario generator
      store.py               SQLite storage
      main.py                 FastAPI app (all endpoints)
      ml/
        features.py         feature engineering
        baseline.py         classifier + anomaly detector + experiment runner
      graph/
        security_graph.py  NetworkX heterogeneous graph
        temporal.py          time-window correlation
      security/
        attack_mapping.py  MITRE ATT&CK rule-based mapper
        risk.py               explainable 0-100 risk engine
        zeek_adapter.py     Zeek JSON log -> normalized events
      rag/
        retriever.py         TF-IDF retrieval over MITRE + playbooks
      agent/
        llm_provider.py     mock / Anthropic provider abstraction
        investigator.py     the 8-step investigation agent
    tests/test_core.py       14 tests covering every module above
    requirements.txt
  frontend/
    index.html                single-file dashboard (no build step)
  knowledge/
    mitre/techniques.json    8 real ATT&CK techniques used by the mapper
    playbooks/playbooks.json  7 defensive playbook documents for RAG
  scripts/
    simulate_attack.py       live-style demo: streams events, triggers agent
  docker-compose.yml
  ROADMAP.md                  phased plan for GNN / real RAG / React / CICIDS2017
```

## Running it

### 1. Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Check it's alive: `curl http://localhost:8000/health`

### 2. Frontend

In a second terminal, no build step needed:

```bash
cd frontend
python3 -m http.server 5173
```

Open **http://localhost:5173** in your browser. It talks to the backend at
`http://localhost:8000` directly.

### 3. Run the demo

Either click through the dashboard UI:
1. **"Seed data + train models"** — generates ~500 synthetic events (benign
   + 2 attack scenarios), trains the Random Forest classifier and Isolation
   Forest anomaly detector, and shows you the real accuracy/F1/ROC-AUC.
2. Pick a scenario from the dropdown and click **"Run scenario +
   investigate"** — this streams a fresh attack sequence and immediately
   runs the investigation agent on it, producing a full incident with
   reconstructed attack chain, MITRE mapping, evidence, and recommended
   response.

...or from the command line:

```bash
# from the repo root, with the backend already running
python3 scripts/simulate_attack.py --scenario credential_compromise_exfiltration
python3 scripts/simulate_attack.py --list   # see all scenarios
```

### 4. Run tests

```bash
cd backend
pytest -v
```
All 14 tests pass as of this writing — they were run and verified during
development, not just written.

### 5. Docker (optional)

```bash
docker compose up --build
```

## Example incident output

Running the `credential_compromise_exfiltration` scenario reliably
reconstructs the exact chain the project was designed around, purely from
raw normalized events — no hardcoded scenario detection:

```
Severity: HIGH   Risk score: 75.8/100   Confidence: 100%
Attack chain: Valid Accounts (T1078) -> PowerShell (T1059.001) ->
              Remote Services (T1021) -> Web Protocols C2 (T1071.001) ->
              Exfiltration Over C2 Channel (T1041)

"Evidence suggests a potential command and control, execution,
exfiltration, initial access, lateral movement sequence beginning with
[authentication] login (user=alice, device=LAPTOP-07). The strongest
indicators are: Valid Accounts -> PowerShell -> Remote Services -> Web
Protocols -> Exfiltration Over C2 Channel. This assessment is grounded
in 5 rule-matched ATT&CK technique(s) and 9 correlated event(s) within
the analysis window."

Recommended actions:
- Force re-authentication (MFA) for the affected account
- Isolate the affected device pending forensic review
- Review and revoke access to the destination server
- Block the suspicious destination at the perimeter
- Escalate to CRITICAL, preserve network capture for forensics
```

## Using a real LLM instead of the mock

By default `LLM_PROVIDER=mock` — the agent's summary is template-based over
structured evidence (deterministic, zero hallucination risk, no API key
needed, fully demoable offline). To use a real model:

```bash
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-...
pip install anthropic
```

The prompt sent to the model explicitly instructs it to reason **only**
from the structured evidence block — not to invent facts — matching the
project's evidence-grounding principle.

## Safety boundaries (by design, not just by prompt)

- The agent's tool surface is entirely **read-only + recommend**. There is
  no code path that isolates a host, disables an account, or blocks an IP —
  only functions that *return* a recommendation string.
- No offensive security functionality (exploits, credential harvesting,
  attack automation) exists anywhere in this codebase.
- ML/anomaly metrics shown in the API/dashboard are always the output of
  `sklearn.metrics` on a real train/test split — never hardcoded.

## Limitations (be upfront about these in a viva/interview)

- Detection uses **synthetic data** with 3 hand-built attack scenarios, not
  real-world attack traffic yet — CICIDS2017 integration is scaffolded
  (adapter pattern) but not wired up. See `ROADMAP.md` R3.
  - Note: CICIDS2017 IS suitable for real integration and is a reasonable
    next step — this MVP just didn't get there yet.
- No GNN yet — graph *features* (fanout, neighbor types) feed the risk
  score today, but there's no trained GraphSAGE/GAT model. This is the
  single highest-value next milestone for the "novelty" claim in your
  report. See `ROADMAP.md` R1.
- ATT&CK mapping is rule-based (Sigma-style), not learned. This is
  actually a defensible design choice for an MVP (explainable, no
  training data needed) — but say so explicitly rather than implying it's
  ML-driven.
- RAG uses TF-IDF, not dense embeddings — good enough to demonstrate
  retrieval-grounded reasoning, but won't handle paraphrased queries as
  well as embeddings would.

## License / attribution

MITRE ATT&CK® technique names, IDs, and descriptions in
`knowledge/mitre/techniques.json` are drawn from the public MITRE ATT&CK
knowledge base (https://attack.mitre.org), summarized/paraphrased for this
project's educational use.
