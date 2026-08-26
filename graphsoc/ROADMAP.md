# ROADMAP — from this MVP to the full GraphSOC vision

This MVP deliberately stopped at a *working, demoable, evidence-grounded*
system rather than attempting all 23 original phases at once (that's how
these projects become unmaintainable). Below is the prioritized path to
extend it, in the order I'd actually do it for a strong CV/viva story.

Each phase below is scoped to be a single focused session with Claude Code.
**Do them one at a time.** After each phase: run the tests, run the app,
verify the feature, update the README, then move on.

---

## R1 — Add a real GNN (highest priority for your "novelty" claim)

**Why first:** your project's stated contribution is "graph-enhanced"
detection. Right now the graph only feeds a hand-computed fanout signal
into the risk score — there's no learned graph model yet. This is the gap
between "we built a system with a graph in it" and "we built a
graph-enhanced detector," which is the actual research claim.

**Steps:**
1. `pip install torch torch-geometric` (uncomment in `requirements.txt`).
2. Add `backend/app/ml/gnn.py`:
   - `GraphDataset`: convert `SecurityGraph.to_dict()` output into a
     PyTorch Geometric `Data`/`HeteroData` object. Node features = one-hot
     node kind + `event_count` + the existing `entity_risk_signal()` fields.
   - `GraphSAGEModel` and `GATModel`: 2-layer, small hidden dim (32-64) —
     don't overbuild. Output: per-node risk embedding -> a linear head for
     node-level anomaly/risk score.
3. Train on the synthetic dataset: benign nodes vs. nodes touched by attack
   scenario events (use `label`/`attack_type` on the *edges* to derive
   node-level labels — a node is "risky" if it participates in any
   Malicious-labeled edge).
4. Add `POST /api/gnn/train` and use its output score as an additional
   input to `compute_risk()` in `security/risk.py` (add a `graph_gnn_score`
   weighted factor).
5. **Run Experiment 3 from the original spec: No graph vs. Graph** — compare
   the rule-based `graph_fanout` signal against the trained GNN's score on
   held-out attack scenarios. Write real numbers to
   `ml/experiments/e3_report.md`.

## R2 — Upgrade RAG to dense embeddings

**Why:** TF-IDF works today but won't generalize to paraphrased analyst
queries. This is a clean, contained upgrade.

**Steps:**
1. `pip install sentence-transformers faiss-cpu`.
2. Implement `EmbeddingRetriever` in `backend/app/rag/retriever.py` (the
   class stub is already there): embed the same `knowledge/` corpus with
   `all-MiniLM-L6-v2`, build a `faiss.IndexFlatIP` over normalized vectors.
3. Keep the exact same `retrieve()` / `retrieve_for_incident()` signature
   so `agent/investigator.py` doesn't need to change at all.
4. **Run Experiment 6: LLM alone vs. RAG-grounded investigation** — compare
   incident summaries with retrieval disabled vs. enabled, using
   `LLM_PROVIDER=anthropic` for both arms so the comparison isolates RAG's
   effect rather than mock-vs-real-model noise.

## R3 — Real CICIDS2017 ingestion

**Steps:**
1. Download CICIDS2017 (the labeled flow CSVs, not raw PCAP, for a first
   pass).
2. Add `backend/app/security/cicids_adapter.py` mirroring the pattern in
   `zeek_adapter.py`: map CICIDS2017's flow-level columns onto
   `SecurityEvent` fields (`event_type="network_connection"`, `bytes_sent`
   <- `Total Length of Fwd Packets`, etc. — check the exact CICIDS2017
   column names, they vary slightly by release).
3. Retrain `BaselineClassifier` on real CICIDS2017 + your synthetic data
   combined. Report real cross-dataset metrics — this is a legitimate
   "generalization" result for your report.
4. **Run Experiment 1: Traditional ML vs GNN on real data.**

## R4 — React frontend (only after R1-R3 give you something worth showing)

The current single-file dashboard is functionally complete and looks
professional — don't rebuild it in React just for the sake of it unless
you specifically want the React/TypeScript line on your CV, or need
features the vanilla version can't do cleanly (e.g., a force-directed graph
visualization with drag/zoom — `react-force-graph` or `d3` would help there).

If you do this: scaffold with Vite (`npm create vite@latest frontend-react
-- --template react-ts`), port the existing API calls 1:1 first, *then*
add the interactive graph view as the one genuinely new capability.

## R5 — Live Zeek pipeline

The adapter (`zeek_adapter.py`) already parses Zeek JSON logs offline. To
make it "live":
1. Run Zeek against a pcap or live interface with JSON logging enabled.
2. Add a small `watchdog`-based file tailer that calls `convert_file()` on
   new lines appended to `conn.log`/`dns.log`/`ssh.log` and POSTs them to
   `/api/events/bulk` in batches.
3. This is genuinely optional for a CV project — real network capture adds
   setup complexity without adding to the research contribution. Only do
   this if you want the "live demo" wow-factor for a specific presentation.

## R6 — Experiment framework polish

`ml/baseline.py::run_experiment_and_save_report()` already saves real
metrics. To match the original spec's Phase 19 fully:
1. Add `ml/experiments/run_all.py` that runs E1-E7 from the original spec
   (Traditional ML vs GNN, event-level vs temporal, no-graph vs graph,
   detection-only vs detection+ATT&CK, LLM-alone vs RAG-grounded, single
   alert vs agentic investigation) and writes each to its own
   `metrics.json` + `confusion_matrix.png` + `experiment_report.md`.
2. This is what turns "we built a tool" into "we ran a research study" —
   worth doing once R1 and R2 exist to compare against.

---

## What NOT to do

- Don't add Kubernetes/SOAR/malware-analysis/cloud-IAM sources. The
  original spec explicitly warns against this (section 16) and it's
  correct — scope creep is the #1 way these projects stall.
- Don't rebuild the storage layer in SQLAlchemy/Postgres unless you
  actually need concurrent multi-user access for a demo — the SQLite
  layer is already correct and tested.
- Don't let the GNN (R1) get elaborate. A 2-layer GraphSAGE that beats the
  rule-based fanout heuristic on your synthetic attack scenarios is a
  complete, defensible result. A fancier architecture with worse-explained
  results is a worse project.
