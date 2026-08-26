"""
Phase 10: Security knowledge retrieval.

Design note: the full spec calls for sentence-transformers + FAISS. Those
need a large model download + native build, which isn't guaranteed on
every dev laptop out of the box. This module ships a TF-IDF retriever
(scikit-learn only, zero downloads, works everywhere immediately) behind
the exact same interface, so swapping in a real embedding model later
is a one-file change — see EmbeddingRetriever stub at the bottom.

Every retrieved chunk keeps its document_id/source/metadata so the agent
and API can cite evidence rather than the LLM inventing an answer.
"""

from __future__ import annotations

import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

MITRE_PATH = Path(__file__).resolve().parent.parent.parent.parent / "knowledge" / "mitre" / "techniques.json"
PLAYBOOK_PATH = Path(__file__).resolve().parent.parent.parent.parent / "knowledge" / "playbooks" / "playbooks.json"


def _load_corpus() -> list[dict]:
    docs = []
    techniques = json.loads(MITRE_PATH.read_text())
    for tid, t in techniques.items():
        docs.append({
            "document_id": f"mitre-{tid}",
            "source": "mitre_attack",
            "chunk_id": f"mitre-{tid}-0",
            "text": f"{t['name']} ({t['tactic']}): {t['description']} Detection guidance: {t['detection_guidance']}",
            "metadata": {"technique_id": tid, "tactic": t["tactic"], "title": t["name"]},
        })
    playbooks = json.loads(PLAYBOOK_PATH.read_text())
    for p in playbooks:
        docs.append({
            "document_id": p["doc_id"],
            "source": p["source"],
            "chunk_id": f"{p['doc_id']}-0",
            "text": p["text"],
            "metadata": {"title": p["title"]},
        })
    return docs


class TfidfRetriever:
    """Default retriever: no external downloads required."""

    def __init__(self):
        self.docs = _load_corpus()
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.matrix = self.vectorizer.fit_transform([d["text"] for d in self.docs])

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        q_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self.matrix).flatten()
        ranked = sims.argsort()[::-1][:top_k]
        results = []
        for idx in ranked:
            if sims[idx] <= 0:
                continue
            d = dict(self.docs[idx])
            d["score"] = float(sims[idx])
            results.append(d)
        return results

    def retrieve_for_incident(self, attack_techniques: list[dict], top_k: int = 4) -> list[dict]:
        if not attack_techniques:
            return []
        query = " ".join(f"{t['name']} {t['tactic']}" for t in attack_techniques)
        return self.retrieve(query, top_k=top_k)


class EmbeddingRetriever:
    """
    Drop-in replacement using sentence-transformers + FAISS, for when the
    project wants real dense embeddings (see docs/rag.md for the swap).
    Left unimplemented here deliberately — see ROADMAP.md Phase R2.
    """

    def __init__(self, *_args, **_kwargs):
        raise NotImplementedError(
            "Install sentence-transformers + faiss-cpu, then implement retrieve() "
            "using an IndexFlatIP over normalized embeddings. See docs/rag.md."
        )
