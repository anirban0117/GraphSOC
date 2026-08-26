"""
Phase 5: Heterogeneous security graph.

Nodes: USER, DEVICE, IP, PROCESS, RESOURCE, DOMAIN, SERVER
Edges carry event_type, timestamp, source, confidence, metadata so the
graph is itself an auditable evidence trail, not just a topology.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

import networkx as nx


def _node(kind: str, value: str) -> str:
    """Namespaced node id so a device named the same as a user can't collide."""
    return f"{kind}:{value}"


class SecurityGraph:
    def __init__(self):
        self.g = nx.MultiDiGraph()

    def _ensure_node(self, kind: str, value: str):
        nid = _node(kind, value)
        if nid not in self.g:
            self.g.add_node(nid, kind=kind, value=value, event_count=0)
        self.g.nodes[nid]["event_count"] += 1
        return nid

    def add_event(self, e: dict):
        ts = e.get("timestamp")
        event_type = e.get("event_type")
        conf = 1.0  # observed events are ground truth in the graph, not inferred

        user = e.get("user_id")
        device = e.get("device_id")
        src_ip = e.get("source_ip")
        dst_ip = e.get("destination_ip")
        process = e.get("process_name")
        resource = e.get("resource")

        user_n = self._ensure_node("USER", user) if user else None
        device_n = self._ensure_node("DEVICE", device) if device else None
        src_ip_n = self._ensure_node("IP", src_ip) if src_ip else None
        dst_ip_n = self._ensure_node("IP", dst_ip) if dst_ip else None
        process_n = self._ensure_node("PROCESS", process) if process else None
        resource_n = self._ensure_node("RESOURCE", resource) if resource else None

        def edge(a, b, rel):
            if a and b:
                self.g.add_edge(
                    a, b, relation=rel, event_type=event_type, timestamp=ts,
                    source=e.get("source"), confidence=conf, event_id=e.get("event_id"),
                    severity=e.get("severity"), label=e.get("label"),
                )

        edge(user_n, device_n, "USES")
        edge(device_n, src_ip_n, "OBSERVED_FROM")
        edge(device_n, dst_ip_n, "CONNECTS_TO")
        edge(device_n, process_n, "RUNS")
        edge(process_n, dst_ip_n, "COMMUNICATES_WITH")
        edge(user_n, resource_n, "ACCESSES")

    def build(self, events: list[dict]) -> "SecurityGraph":
        for e in sorted(events, key=lambda x: x.get("timestamp") or ""):
            self.add_event(e)
        return self

    # -- queries -----------------------------------------------------------

    def get_neighbors(self, kind: str, value: str, hops: int = 1) -> list[str]:
        nid = _node(kind, value)
        if nid not in self.g:
            return []
        visited = {nid}
        frontier = {nid}
        for _ in range(hops):
            nxt = set()
            for n in frontier:
                nxt |= set(self.g.successors(n)) | set(self.g.predecessors(n))
            frontier = nxt - visited
            visited |= frontier
        visited.discard(nid)
        return sorted(visited)

    def get_subgraph(self, kind: str, value: str, hops: int = 2) -> dict:
        nid = _node(kind, value)
        if nid not in self.g:
            return {"nodes": [], "edges": []}
        neighborhood = set(self.get_neighbors(kind, value, hops)) | {nid}
        sub = self.g.subgraph(neighborhood)
        nodes = [{"id": n, **sub.nodes[n]} for n in sub.nodes]
        edges = [
            {"source": u, "target": v, **data}
            for u, v, data in sub.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges}

    def entity_risk_signal(self, kind: str, value: str) -> dict:
        """
        Cheap, explainable graph-based risk signal used before/alongside the
        GNN: how many *distinct* neighbor types and how many high-severity
        edges touch this entity. A real credential-compromise chain fans
        out across device/process/ip/resource types very quickly.
        """
        nid = _node(kind, value)
        if nid not in self.g:
            return {"neighbor_count": 0, "distinct_neighbor_types": 0, "high_severity_edges": 0}

        neighbors = self.get_neighbors(kind, value, hops=1)
        types = {self.g.nodes[n]["kind"] for n in neighbors}
        high_sev = 0
        for u, v, data in list(self.g.in_edges(nid, data=True)) + list(self.g.out_edges(nid, data=True)):
            if data.get("severity") in ("HIGH", "CRITICAL"):
                high_sev += 1
        return {
            "neighbor_count": len(neighbors),
            "distinct_neighbor_types": len(types),
            "high_severity_edges": high_sev,
        }

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n, **d} for n, d in self.g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.g.edges(data=True)],
        }

    def stats(self) -> dict:
        kinds = defaultdict(int)
        for _, d in self.g.nodes(data=True):
            kinds[d["kind"]] += 1
        return {
            "num_nodes": self.g.number_of_nodes(),
            "num_edges": self.g.number_of_edges(),
            "node_kinds": dict(kinds),
        }
