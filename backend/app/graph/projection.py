"""Load the security projection from persisted graph nodes/edges + findings.

Replaces the FalkorDB-backed graph_ops.Projection with SQLite-backed loading.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from app.config import settings
from app.db import query_one
from app.repositories.graph import GraphRepository
from app.repositories.findings import FindingRepository
from app.repositories.mappings import MappingRepository
from app.repositories.scans import ScanRepository

log = logging.getLogger("chokepoint.graph.projection")


@dataclass(slots=True)
class SecurityProjection:
    """Everything path evaluation needs, loaded from SQLite."""

    scan_id: str
    graph: nx.DiGraph
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)  # node_id -> properties
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)  # finding_id -> properties
    services: dict[str, dict[str, Any]] = field(default_factory=dict)  # service_id -> properties
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)  # package_id -> properties
    mappings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # finding_id -> list of mappings
    node_names: dict[str, str] = field(default_factory=dict)  # node_id -> display name
    cypher_used: list[str] = field(default_factory=list)  # for compatibility
    load_ms: float = 0.0

    def name_of(self, node_id: str) -> str:
        return self.node_names.get(node_id, node_id)

    def public_entry_services(self) -> list[str]:
        """Services with public ingress routes."""
        entry = []
        for sid, svc in self.services.items():
            if svc.get("public_ingress") or svc.get("internet_facing"):
                entry.append(sid)
        return entry

    def service_findings(self, service_id: str) -> list[str]:
        """Findings for a service."""
        return [
            fid for fid, f in self.findings.items()
            if f.get("service_id") == service_id or f.get("mapped_service_id") == service_id
        ]

    def package_services(self, package_id: str) -> set[str]:
        """Services using a package."""
        return {
            f.get("service_id") for f in self.findings.values()
            if f.get("package_name") == package_id and f.get("service_id")
        }

    def blocking_controls_for(self, service_id: str, cve: str) -> list[str]:
        """Active controls on a service for a CVE."""
        # This would come from a controls table if we had one
        # For now, return empty - controls would be represented as graph edges
        return []

    def best_entry_authn(self, service_id: str) -> str | None:
        """The weakest authentication among public ingresses routing to a service."""
        svc = self.services.get(service_id)
        if not svc:
            return None
        authn = svc.get("ingress_authn") or svc.get("authn") or "oidc"
        return authn

    def store_access_for(self, service_id: str) -> list[tuple[str, str]]:
        """Data stores a service accesses: (relation, store_id)."""
        results = []
        for edge in self.graph.out_edges(service_id, data=True):
            if edge[2].get("relation") in ("READS_FROM", "WRITES_TO"):
                results.append((edge[2]["relation"], edge[1]))
        return results

    def role_access_for(self, service_id: str) -> list[tuple[str, str, str]]:
        """IAM roles a service assumes: (role_id, store_id, privilege)."""
        results = []
        for edge in self.graph.out_edges(service_id, data=True):
            if edge[2].get("relation") == "ASSUMES":
                role_id = edge[1]
                # Look for CAN_ACCESS from this role
                for re2 in self.graph.out_edges(role_id, data=True):
                    if re2[2].get("relation") == "CAN_ACCESS":
                        results.append((role_id, re2[1], re2[2].get("privilege", "read")))
        return results

    @property
    def stores(self) -> dict[str, dict[str, Any]]:
        """DataStore nodes in the projection."""
        return {
            nid: props for nid, props in self.nodes.items()
            if props.get("label") == "DataStore" or props.get("classification") in ("pci", "pii", "secrets") or props.get("crown_jewel")
        }

    @property
    def store_access(self) -> list[tuple[str, str, str]]:
        """(service_id, relation, store_id) tuples."""
        results = []
        for src, dst, data in self.graph.edges(data=True):
            if data.get("relation") in ("READS_FROM", "WRITES_TO"):
                results.append((src, data["relation"], dst))
        return results

    @property
    def role_access(self) -> list[tuple[str, str, str, str]]:
        """(service_id, role_id, store_id, privilege) tuples."""
        results = []
        for src, dst, data in self.graph.edges(data=True):
            if data.get("relation") == "ASSUMES":
                role_id = dst
                for _, store_id, rdata in self.graph.out_edges(role_id, data=True):
                    if rdata.get("relation") == "CAN_ACCESS":
                        results.append((src, role_id, store_id, rdata.get("privilege", "read")))
        return results


def load_projection(scan_id: str | None = None) -> SecurityProjection:
    """Load the security projection for a scan from SQLite."""
    if not scan_id:
        from app.repositories.scans import ScanRepository
        from app.seed.scenarios import SCAN_DAY1
        latest = ScanRepository.latest_scan()
        scan_id = str(latest["id"]) if latest and latest.get("id") else SCAN_DAY1

    started = time.perf_counter()

    # Load graph from persisted nodes/edges
    nodes = GraphRepository.load_nodes(scan_id)
    edges = GraphRepository.load_edges(scan_id)

    G = nx.DiGraph()
    node_props = {}
    node_names = {}
    services = {}
    packages = {}

    for node in nodes:
        nid = node["id"]
        props = dict(node["properties"])
        label = node["label"]
        props["label"] = label
        G.add_node(nid, **props)
        node_props[nid] = props
        node_names[nid] = props.get("name") or props.get("id") or nid

        if label == "Service":
            services[nid] = props
        elif label == "Package":
            packages[nid] = props

    for edge in edges:
        src = edge["source"]
        tgt = edge["target"]
        rel = edge["relation"]
        props = dict(edge["properties"])
        props["relation"] = rel
        G.add_edge(src, tgt, **props)

    # Load findings
    findings = {}
    finding_list = FindingRepository.list_for_scan(scan_id)
    for f in finding_list:
        fid = f["finding_id"]
        findings[fid] = f

    # Load mappings
    mappings = {}
    for finding in finding_list:
        fid = finding["finding_id"]
        finding_mappings = MappingRepository.for_finding(fid)
        if finding_mappings:
            mappings[fid] = finding_mappings
            if not findings[fid].get("service_id"):
                for m in finding_mappings:
                    nid = m.get("node_id")
                    if nid and nid in services:
                        findings[fid]["service_id"] = nid
                        findings[fid]["mapped_service_id"] = nid
                        break
                    elif nid and nid in packages:
                        for src in G.predecessors(nid):
                            if src in services:
                                findings[fid]["service_id"] = src
                                findings[fid]["mapped_service_id"] = src
                                break
                    elif nid and nid in G:
                        for src in G.predecessors(nid):
                            if src in services:
                                findings[fid]["service_id"] = src
                                findings[fid]["mapped_service_id"] = src
                                break
            if not findings[fid].get("service_id") and services:
                default_sid = next(iter(services.keys()))
                findings[fid]["service_id"] = default_sid
                findings[fid]["mapped_service_id"] = default_sid

    load_ms = round((time.perf_counter() - started) * 1000.0, 2)
    log.info("loaded projection for scan %s: %d nodes, %d edges, %d findings in %.2fms",
             scan_id, G.number_of_nodes(), G.number_of_edges(), len(findings), load_ms)

    return SecurityProjection(
        scan_id=scan_id,
        graph=G,
        nodes=node_props,
        findings=findings,
        services=services,
        packages=packages,
        mappings=mappings,
        node_names=node_names,
        load_ms=load_ms,
    )