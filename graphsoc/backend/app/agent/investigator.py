"""
Phase 12: Investigation agent.

Not a chatbot — a bounded, tool-using workflow that turns one triggering
event into an evidence-grounded Incident. Every step is a named "tool"
call whose output is logged into agent_trace, so the UI can show exactly
which step produced which fact (this is what "AI inference must be
distinguishable from observed evidence" means in practice).

The agent may only ever *recommend* actions (isolate, block, escalate) —
see RECOMMENDATION_LIBRARY. It never executes them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.agent.llm_provider import BaseLLMProvider, get_llm_provider
from app.graph.security_graph import SecurityGraph
from app.graph.temporal import TemporalCorrelator
from app.security.attack_mapping import AttackMapper
from app.security.risk import compute_risk
from app.rag.retriever import TfidfRetriever

RECOMMENDATION_LIBRARY = {
    "T1078": "Force re-authentication (MFA) for the affected account and review recent session activity.",
    "T1110": "Enforce account lockout / rate limiting on the source IP and rotate the account's credentials.",
    "T1059.001": "Isolate the affected device pending forensic review of the PowerShell execution.",
    "T1021": "Review and, if unauthorized, revoke the affected account's access to the destination server.",
    "T1046": "Log and monitor the scanning source IP; consider perimeter rate-limiting.",
    "T1071.001": "Block the suspicious destination at the perimeter after evidence is preserved.",
    "T1041": "Escalate to CRITICAL, isolate the source device, and preserve network capture for forensics.",
}

GENERIC_RECOMMENDATIONS = [
    "Escalate to a human analyst for confirmation before taking irreversible action.",
    "Preserve relevant logs and evidence for the affected entities.",
]


class InvestigationAgent:
    def __init__(self, all_events: list[dict], llm: BaseLLMProvider | None = None):
        self.all_events = all_events
        self.graph = SecurityGraph().build(all_events)
        self.correlator = TemporalCorrelator(all_events)
        self.mapper = AttackMapper()
        self.retriever = TfidfRetriever()
        self.llm = llm or get_llm_provider()
        self.trace: list[dict] = []

    def _log(self, step: str, detail: dict):
        self.trace.append({"step": step, "detail": detail, "at": datetime.now(timezone.utc).isoformat()})

    def investigate(self, triggering_event: dict, ml_confidence: float = 0.0,
                     anomaly_score: float = 0.0, window_minutes: int = 30) -> dict:
        self.trace = []

        # Step 1-2: receive alert, identify affected entities
        user = triggering_event.get("user_id")
        device = triggering_event.get("device_id")
        self._log("identify_entities", {"user": user, "device": device})

        # Step 3-4: correlate related events, build timeline
        related = self.correlator.correlate_alert(triggering_event, window_minutes)
        timeline = self.correlator.build_timeline(triggering_event, window_minutes)
        temporal_features = self.correlator.extract_temporal_features(triggering_event, window_minutes)
        self._log("temporal_correlation", {
            "window_minutes": window_minutes, "related_event_count": len(related),
            "temporal_features": temporal_features,
        })

        # Step 5-6: graph neighborhood / suspicious relationships
        graph_signal = self.graph.entity_risk_signal("USER", user) if user else {}
        subgraph = self.graph.get_subgraph("USER", user, hops=2) if user else {"nodes": [], "edges": []}
        self._log("graph_analysis", {"graph_signal": graph_signal,
                                      "subgraph_size": {"nodes": len(subgraph["nodes"]), "edges": len(subgraph["edges"])}})

        # Step 8: ATT&CK mapping (uses the correlated event set, not just the trigger)
        attack_techniques = self.mapper.map_events(related or [triggering_event])
        self._log("attack_mapping", {"technique_ids": [t["id"] for t in attack_techniques]})

        # Step 7: retrieve relevant security knowledge, grounded in the mapped techniques
        knowledge = self.retriever.retrieve_for_incident(attack_techniques)
        self._log("knowledge_retrieval", {"chunks_retrieved": [k["document_id"] for k in knowledge]})

        # Step 9-10: risk scoring
        risk = compute_risk(
            ml_confidence=ml_confidence,
            anomaly_score=anomaly_score,
            graph_fanout=graph_signal,
            attack_techniques=attack_techniques,
            correlated_events=related,
        )
        self._log("risk_scoring", risk)

        # Step 11: recommended actions
        actions = []
        for t in attack_techniques:
            rec = RECOMMENDATION_LIBRARY.get(t["id"])
            if rec and rec not in actions:
                actions.append(rec)
        actions += [a for a in GENERIC_RECOMMENDATIONS if a not in actions]
        self._log("recommend_response", {"actions": actions})

        # Step 12: incident report / grounded natural-language summary
        summary = self._summarize(triggering_event, attack_techniques, risk, temporal_features, knowledge)
        self._log("generate_report", {"summary_length": len(summary)})

        incident = {
            "incident_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "OPEN",
            "severity": risk["severity"],
            "confidence": round(max(ml_confidence, len(attack_techniques) / 5), 2),
            "risk_score": risk["risk_score"],
            "affected_users": sorted({e.get("user_id") for e in related if e.get("user_id")} | ({user} if user else set())),
            "affected_devices": sorted({e.get("device_id") for e in related if e.get("device_id")} | ({device} if device else set())),
            "affected_ips": sorted({e.get("destination_ip") for e in related if e.get("destination_ip")}),
            "attack_chain": [t["name"] for t in attack_techniques],
            "attack_techniques": attack_techniques,
            "timeline": timeline,
            "evidence": [
                {"event_id": e.get("event_id"), "type": "OBSERVED_EVIDENCE", "description": self._short_desc(e)}
                for e in (related or [triggering_event])
            ],
            "risk_factors": risk["explanation"],
            "retrieved_knowledge": knowledge,
            "recommended_actions": [{"action": a, "type": "RECOMMENDED_ACTION"} for a in actions],
            "investigation_summary": summary,
            "agent_trace": self.trace,
        }
        return incident

    @staticmethod
    def _short_desc(e: dict) -> str:
        return f"[{e.get('event_type')}] {e.get('action') or e.get('status') or ''} " \
               f"(user={e.get('user_id')}, device={e.get('device_id')})"

    def _summarize(self, trigger: dict, techniques: list[dict], risk: dict,
                    temporal_features: dict, knowledge: list[dict]) -> str:
        """
        Evidence-grounded natural-language summary. With MockLLMProvider this
        is template-based (guaranteed grounded, zero hallucination risk).
        With AnthropicProvider, the same structured evidence is handed to a
        real model with instructions to reason ONLY from what's given.
        """
        chain = " -> ".join(t["name"] for t in techniques) or "No distinct ATT&CK technique chain identified"
        tactic_list = ", ".join(sorted({t["tactic"] for t in techniques})) or "none"

        evidence_block = "\n".join(
            f"- {t['id']} ({t['name']}): {t['rationale']}" for t in techniques
        ) or "- No rule-based technique mapping matched the correlated events."

        knowledge_block = "\n".join(
            f"- [{k['document_id']}] {k['text'][:180]}..." for k in knowledge
        ) or "- No directly relevant knowledge base entries found."

        structured_prompt = (
            f"Triggering event: {self._short_desc(trigger)}\n"
            f"Correlated events in window: {temporal_features['event_count']}\n"
            f"Attack chain: {chain}\n"
            f"Tactics observed: {tactic_list}\n"
            f"Risk score: {risk['risk_score']}/100 ({risk['severity']})\n"
            f"Evidence:\n{evidence_block}\n"
            f"Retrieved knowledge:\n{knowledge_block}\n"
        )

        if isinstance(self.llm, type(get_llm_provider())) and self.llm.__class__.__name__ == "MockLLMProvider":
            pass  # fall through to template below regardless of provider identity check

        if self.llm.__class__.__name__ != "MockLLMProvider":
            system_prompt = (
                "You are a SOC investigation assistant. Reason ONLY from the structured evidence "
                "provided. Do not invent event details, IPs, or techniques not listed. Write a concise "
                "2-4 sentence incident assessment for an analyst."
            )
            return self.llm.generate(system_prompt, structured_prompt)

        # Deterministic template summary (MockLLMProvider path)
        if not techniques:
            return (
                f"The triggering event ({self._short_desc(trigger)}) did not correlate with a recognized "
                f"multi-step attack pattern within the analysis window. Risk score {risk['risk_score']}/100 "
                f"({risk['severity']}). No specific ATT&CK technique chain was identified from available evidence."
            )
        return (
            f"Evidence suggests a potential {tactic_list.lower()} sequence beginning with "
            f"{self._short_desc(trigger)}. The strongest indicators are: {chain}. "
            f"This assessment is grounded in {len(techniques)} rule-matched ATT&CK technique(s) "
            f"and {temporal_features['event_count']} correlated event(s) within the analysis window. "
            f"Risk score: {risk['risk_score']}/100 ({risk['severity']})."
        )
