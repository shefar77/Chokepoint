"""Attack path enumeration and exploitability checking over the security graph.

Replaces the FalkorDB-backed attack.py with NetworkX-based analysis.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterator

import networkx as nx

from .projection import SecurityProjection
from .scoring import ExploitCheck, ScoreBreakdown, evaluate_finding, score_path

log = logging.getLogger("chokepoint.graph.attack")

CHAIN_CAP = 20000
CROWN_CLASSIFICATIONS = frozenset({"pci", "pii", "secrets", "critical"})


@dataclass(slots=True)
class Modifications:
    """A hypothetical change to the graph, applied without writing to the graph."""

    removed_findings: set[str] = field(default_factory=set)
    hardened_edges: set[tuple[str, str]] = field(default_factory=set)
    controlled_services: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not (self.removed_findings or self.hardened_edges or self.controlled_services)

    def copy(self) -> "Modifications":
        return Modifications(
            removed_findings=set(self.removed_findings),
            hardened_edges=set(self.hardened_edges),
            controlled_services=set(self.controlled_services),
        )


@dataclass(slots=True)
class AttackPath:
    """One internet-to-crown-jewel route with its score components."""

    id: str
    entry: str
    entry_ingress: str
    entry_authn: str
    target: str
    target_name: str
    target_classification: str
    target_records: int
    hops: int
    services: list[str]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    breakdown: ScoreBreakdown
    live_exploits: list[dict[str, Any]]
    mitigating_controls: list[str]
    mitigated_only: bool = False
    reachability_verified: bool = False

    @property
    def score(self) -> float:
        return self.breakdown.score

    def node_ids(self) -> list[str]:
        return [n["id"] for n in self.nodes]

    def finding_ids(self) -> list[str]:
        return [e["finding_id"] for e in self.live_exploits]

    def as_dict(self, *, verbose: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "score": round(self.breakdown.score, 4),
            "score_pct": round(self.breakdown.score * 100, 1),
            "hops": self.hops,
            "entry": self.entry,
            "entry_ingress": self.entry_ingress,
            "entry_authn": self.entry_authn,
            "target": self.target,
            "target_name": self.target_name,
            "target_classification": self.target_classification,
            "target_records": self.target_records,
            "components": self.breakdown.as_dict(),
            "nodes": self.nodes,
            "edges": self.edges,
            "live_exploits": self.live_exploits,
            "mitigating_controls": self.mitigating_controls,
            "reachability_verified": self.reachability_verified,
            "evidence_note": (
                "every hop and exploit on this route has reachability evidence"
                if self.reachability_verified
                else "reachability of the vulnerable code is not established on this route; "
                "it supports a hypothesis and is not proof of exploitability"
            ),
        }
        if self.mitigated_only:
            out["mitigated_only"] = True
        if not verbose:
            out.pop("nodes", None)
            out.pop("edges", None)
            out["node_ids"] = self.node_ids()
        return out


def _is_crown_jewel(node_props: dict[str, Any]) -> bool:
    return bool(node_props.get("crown_jewel")) or str(node_props.get("classification", "")) in CROWN_CLASSIFICATIONS


def _has_public_ingress(proj: SecurityProjection, service_id: str) -> bool:
    """Check if a service has a public ingress route."""
    svc = proj.services.get(service_id, {})
    return bool(svc.get("public_ingress") or svc.get("internet_facing"))


def _best_entry_authn(proj: SecurityProjection, service_id: str) -> str:
    """Get the authentication level of the public ingress to a service."""
    return proj.best_entry_authn(service_id) or "oidc"


def live_exploits(
    proj: SecurityProjection,
    mods: Modifications,
    *,
    as_entry: bool,
    ignore_controls: bool = False,
) -> dict[str, list[ExploitCheck]]:
    """Live exploits per service (entry point or after lateral movement)."""
    out: dict[str, list[ExploitCheck]] = {}
    for finding_id, facts in proj.findings.items():
        if finding_id in mods.removed_findings:
            continue
        service_id = facts.get("service_id") or facts.get("mapped_service_id", "")
        if not service_id or service_id not in proj.services:
            continue
        service = proj.services.get(service_id, {})
        authn = _best_entry_authn(proj, service_id)
        blockers = proj.blocking_controls_for(service_id, facts.get("cve", ""))
        if service_id in mods.controlled_services and not ignore_controls:
            blockers = [*blockers, f"simulated virtual patch on {service_id}"]
        check = evaluate_finding(
            finding_id=finding_id,
            service_id=service_id,
            cve=facts.get("cve", ""),
            cvss=float(facts.get("cvss") or 0.0),
            epss=float(facts.get("epss") or 0.0),
            kev=bool(facts.get("kev", False)),
            attack_vector=facts.get("attack_vector", "network"),
            requires_auth=bool(facts.get("requires_auth", False)),
            fixed_in=facts.get("fixed_in", ""),
            status=facts.get("status", "open"),
            reachable_code=bool(facts.get("reachable_code", False)),
            reachability=str(facts.get("reachability") or ""),
            service_status=str(service.get("status") or "active"),
            ingress_authn=authn,
            has_ingress_route=_has_public_ingress(proj, service_id),
            blocking_controls=blockers,
            allow_adjacent=not as_entry,
        )
        if check.live:
            out.setdefault(service_id, []).append(check)
    for checks in out.values():
        checks.sort(key=lambda c: (-c.exploitability, c.finding_id))
    return out


def check_finding(
    proj: SecurityProjection,
    finding_id: str,
    *,
    mods: Modifications | None = None,
    allow_adjacent: bool = False,
) -> ExploitCheck | None:
    """Check exploitability for a single finding."""
    facts = proj.findings.get(finding_id)
    if facts is None:
        return None
    overlay = mods or Modifications()
    service_id = facts.get("service_id") or facts.get("mapped_service_id", "")
    if not service_id:
        return None
    service = proj.services.get(service_id, {})
    authn = _best_entry_authn(proj, service_id)
    blockers = proj.blocking_controls_for(service_id, facts.get("cve", ""))
    if service_id in overlay.controlled_services:
        blockers = [*blockers, f"simulated virtual patch on {service_id}"]
    if finding_id in overlay.removed_findings:
        blockers = [*blockers, "fix already applied in this simulation"]
    return evaluate_finding(
        finding_id=finding_id,
        service_id=service_id,
        cve=facts.get("cve", ""),
        cvss=float(facts.get("cvss") or 0.0),
        epss=float(facts.get("epss") or 0.0),
        kev=bool(facts.get("kev", False)),
        attack_vector=facts.get("attack_vector", "network"),
        requires_auth=bool(facts.get("requires_auth", False)),
        fixed_in=facts.get("fixed_in", ""),
        status=facts.get("status", "open"),
        reachable_code=bool(facts.get("reachable_code", False)),
        reachability=str(facts.get("reachability") or ""),
        service_status=str(service.get("status") or "active"),
        ingress_authn=authn,
        has_ingress_route=_has_public_ingress(proj, service_id),
        blocking_controls=blockers,
        allow_adjacent=allow_adjacent,
    )


def _usable_calls(proj: SecurityProjection, mods: Modifications, service_id: str) -> list[tuple[str, dict[str, Any]]]:
    """Outbound CALLS edges from a service that are traversable."""
    edges = []
    for _, dst, data in proj.graph.out_edges(service_id, data=True):
        if data.get("relation") == "CALLS":
            if data.get("authz") == "mtls":
                continue
            if (service_id, dst) in mods.hardened_edges:
                continue
            dst_svc = proj.services.get(dst, {})
            if str(dst_svc.get("status") or "") != "active":
                continue
            edges.append((dst, data))
    return sorted(edges, key=lambda e: e[0])


def _service_chains(
    proj: SecurityProjection, mods: Modifications, entry: str, max_services: int
) -> Iterator[list[str]]:
    """Every lateral-movement chain starting at `entry`, including prefixes."""
    produced = 0
    stack: list[list[str]] = [[entry]]
    while stack:
        chain = stack.pop()
        yield chain
        produced += 1
        if produced >= CHAIN_CAP:
            log.warning("chain cap reached while expanding from %s", entry)
            return
        if len(chain) >= max_services:
            continue
        for dst, _ in _usable_calls(proj, mods, chain[-1]):
            if dst in chain:
                continue
            stack.append([*chain, dst])


def _node_dict(proj: SecurityProjection, node_id: str) -> dict[str, Any]:
    label = proj.nodes.get(node_id, {}).get("label", "Unknown")
    return {"id": node_id, "label": label, "name": proj.name_of(node_id)}


def _edge_dict(source: str, target: str, rel: str, authz: str = "") -> dict[str, Any]:
    return {"source": source, "target": target, "type": rel, "authz": authz}


def _mitigating_controls(proj: SecurityProjection, node_ids: set[str]) -> list[str]:
    """Active controls attached to nodes on the path."""
    # For now, return empty - controls would be separate nodes in the graph
    return []


def enumerate_attack_paths(
    proj: SecurityProjection,
    *,
    mods: Modifications | None = None,
    max_hops: int = 7,
    top_k: int = 8,
    target: str | None = None,
    include_mitigated: bool = False,
) -> list[AttackPath]:
    """All internet-to-crown-jewel paths, best first, deduplicated by entry and target."""
    overlay = mods or Modifications()
    entry_live = live_exploits(proj, overlay, as_entry=True)
    lateral_live = live_exploits(proj, overlay, as_entry=False)
    unmitigated_entries = set(entry_live)
    if include_mitigated:
        entry_live = live_exploits(proj, overlay, as_entry=True, ignore_controls=True)
        lateral_live = live_exploits(proj, overlay, as_entry=False, ignore_controls=True)

    best: dict[tuple[str, str], AttackPath] = {}

    for entry_service in sorted(entry_live):
        if str(proj.services.get(entry_service, {}).get("status") or "") != "active":
            continue
        authn = _best_entry_authn(proj, entry_service)
        entry_ingress = f"ingress-{entry_service}"  # simplified

        for chain in _service_chains(proj, overlay, entry_service, max_services=max(1, max_hops - 2)):
            tail = chain[-1]
            # Check data store access
            for rel, store_id in proj.store_access_for(tail):
                store = proj.nodes.get(store_id, {})
                if not _is_crown_jewel(store):
                    continue
                if target and store_id != target and store.get("name") != target:
                    continue
                path = _build_path(
                    proj,
                    chain=chain,
                    authn=authn,
                    store_id=store_id,
                    store=store,
                    rel=rel,
                    lateral_live=lateral_live,
                    max_hops=max_hops,
                )
                if path is None:
                    continue
                path.mitigated_only = include_mitigated and entry_service not in unmitigated_entries
                key = (entry_service, store_id)
                current = best.get(key)
                if current is None or path.breakdown.score > current.breakdown.score:
                    best[key] = path

            # Check role access
            for role_id, store_id, privilege in proj.role_access_for(tail):
                store = proj.nodes.get(store_id, {})
                if not _is_crown_jewel(store):
                    continue
                if target and store_id != target and store.get("name") != target:
                    continue
                path = _build_path(
                    proj,
                    chain=chain,
                    authn=authn,
                    store_id=store_id,
                    store=store,
                    rel="CAN_ACCESS",
                    role_id=role_id,
                    lateral_live=lateral_live,
                    max_hops=max_hops,
                )
                if path is None:
                    continue
                path.mitigated_only = include_mitigated and entry_service not in unmitigated_entries
                key = (entry_service, store_id)
                current = best.get(key)
                if current is None or path.breakdown.score > current.breakdown.score:
                    best[key] = path

    ordered = sorted(best.values(), key=lambda p: (-p.breakdown.score, p.hops, p.id))
    for index, path in enumerate(ordered, start=1):
        path.id = f"AP-{index:03d}-{path.entry}-{path.target}"
    return ordered[: max(1, top_k)] if top_k else ordered


def _build_path(
    proj: SecurityProjection,
    *,
    chain: list[str],
    authn: str,
    store_id: str,
    store: dict[str, Any],
    rel: str,
    lateral_live: dict[str, list[ExploitCheck]],
    max_hops: int,
    role_id: str | None = None,
) -> AttackPath | None:
    internet_id = "internet"
    node_ids = [internet_id, f"ingress-{chain[0]}", *chain]
    edges = [
        _edge_dict(internet_id, f"ingress-{chain[0]}", "REACHES"),
        _edge_dict(f"ingress-{chain[0]}", chain[0], "ROUTES_TO"),
    ]
    for src, dst in zip(chain, chain[1:], strict=False):
        edge_data = proj.graph.get_edge_data(src, dst) or {}
        authz = edge_data.get("authz", "none")
        edges.append(_edge_dict(src, dst, "CALLS", authz))
    if role_id:
        node_ids.append(role_id)
        edges.append(_edge_dict(chain[-1], role_id, "ASSUMES"))
        edges.append(_edge_dict(role_id, store_id, "CAN_ACCESS"))
    else:
        edges.append(_edge_dict(chain[-1], store_id, rel))
    node_ids.append(store_id)

    hops = len(edges)
    if hops > max_hops:
        return None

    exploits: list[dict[str, Any]] = []
    for service_id in chain:
        for check in lateral_live.get(service_id, []):
            facts = proj.findings.get(check.finding_id)
            exploits.append(
                {
                    "finding_id": check.finding_id,
                    "service_id": service_id,
                    "cve": check.cve,
                    "cvss": facts.get("cvss", 0.0) if facts else 0.0,
                    "epss": facts.get("epss", 0.0) if facts else 0.0,
                    "kev": facts.get("kev", False) if facts else False,
                    "package": (
                        f"{facts.get('package_name', '')}@"
                        f"{facts.get('installed_version', '') or facts.get('package_version', '')}"
                        if facts
                        else ""
                    ),
                    "exploitability": round(check.exploitability, 4),
                    "reachability": check.reachability,
                    "reachability_verified": check.reachability_verified,
                }
            )
    if not exploits:
        return None
    exploits.sort(key=lambda e: (-float(e["exploitability"]), str(e["finding_id"])))
    exploitability = float(exploits[0]["exploitability"])

    controls = _mitigating_controls(proj, set(node_ids))
    verified = any(bool(e.get("reachability_verified")) for e in exploits)
    raw_records = store.get("records")
    records = int(raw_records) if isinstance(raw_records, (int, float)) else None
    breakdown = score_path(
        exploitability=exploitability,
        authn=authn,
        classification=str(store.get("classification") or "unknown"),
        records=records,
        hops=hops,
        mitigations=len(controls),
        exploit_signal_observed=verified,
    )
    return AttackPath(
        id=f"AP-{chain[0]}-{store_id}",
        entry=chain[0],
        entry_ingress=f"ingress-{chain[0]}",
        entry_authn=authn,
        target=store_id,
        target_name=str(store.get("name") or store_id),
        target_classification=str(store.get("classification") or "unknown"),
        target_records=records if records is not None else 0,
        hops=hops,
        services=list(chain),
        nodes=[_node_dict(proj, nid) for nid in node_ids],
        edges=edges,
        breakdown=breakdown,
        live_exploits=exploits[:6],
        mitigating_controls=controls,
        reachability_verified=verified,
    )


def cypher_candidates(proj: SecurityProjection, max_hops: int) -> tuple[int, str]:
    """Compatibility shim - returns count of paths found."""
    paths = enumerate_attack_paths(proj, max_hops=max_hops, top_k=0)
    return len(paths), "NetworkX enumeration"


def reachable_set(
    proj: SecurityProjection, start: str, *, max_hops: int = 4, mods: Modifications | None = None
) -> dict[str, int]:
    """Breadth-first lateral reach over usable CALLS edges, depth per service."""
    overlay = mods or Modifications()
    depths = {start: 0}
    frontier = [start]
    for depth in range(1, max_hops + 1):
        nxt: list[str] = []
        for service_id in frontier:
            for dst, _ in _usable_calls(proj, overlay, service_id):
                if dst not in depths:
                    depths[dst] = depth
                    nxt.append(dst)
        frontier = nxt
        if not frontier:
            break
    return depths


def blast_radius(
    proj: SecurityProjection, service_id: str, *, max_hops: int = 4, mods: Modifications | None = None
) -> dict[str, Any]:
    """What an attacker reaches after owning one service."""
    overlay = mods or Modifications()
    depths = reachable_set(proj, service_id, max_hops=max_hops, mods=overlay)

    stores: list[dict[str, Any]] = []
    for sid, rel, store_id in [
        (s, d["relation"], t) for s, t, d in proj.graph.edges(data=True)
        if d.get("relation") in ("READS_FROM", "WRITES_TO") and s in depths
    ]:
        store = proj.nodes.get(store_id, {})
        stores.append({**store, "via_service": sid, "access": rel, "hops": depths[sid]})

    # The store id has to come from the CAN_ACCESS edge's target, not from a
    # 'store_id' property on the ASSUMES edge (which never carries one).
    roles: list[dict[str, Any]] = []
    for sid, role_id, store_id, privilege in [
        (s, t, t2, d2.get("privilege", "read"))
        for s, t, d in proj.graph.edges(data=True)
        if d.get("relation") == "ASSUMES" and s in depths
        for _, t2, d2 in proj.graph.out_edges(t, data=True)
        if d2.get("relation") == "CAN_ACCESS"
    ]:
        roles.append(
            {
                "role_id": role_id,
                "privilege": privilege,
                "store_id": store_id,
                "via_service": sid,
                "crown_jewel": _is_crown_jewel(proj.nodes.get(store_id, {})),
            }
        )
        if store_id in proj.nodes:
            store = proj.nodes[store_id]
            stores.append({**store, "via_service": sid, "access": "CAN_ACCESS", "hops": depths[sid]})

    unique_stores = {s["id"]: s for s in stores}
    crown = sorted(s["id"] for s in unique_stores.values() if s.get("crown_jewel"))

    return {
        "start": service_id,
        "services_reached": sorted(depths.keys()),
        "depths": depths,
        "data_stores_reached": sorted(unique_stores.values(), key=lambda s: str(s["id"])),
        "iam_roles_reached": roles,
        "crown_jewels_reached": crown,
    }


def total_weight(paths: list[AttackPath]) -> float:
    return sum(p.breakdown.score for p in paths)