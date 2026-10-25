"""Chokepoint solver and counterfactual simulation over NetworkX graph."""

from __future__ import annotations

import logging
import uuid
import networkx as nx
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .attack import AttackPath, Modifications, enumerate_attack_paths, live_exploits, total_weight
from .projection import SecurityProjection

log = logging.getLogger("chokepoint.graph.solver")

COVERAGE_TARGET = 0.95
MAX_CANDIDATES_PER_ROUND = 60

COST_UPGRADE_BASE = 1.0
COST_UPGRADE_PER_SERVICE = 0.3
COST_PATCH_SERVICE = 1.0
COST_HARDEN_EDGE = 2.0
COST_ADD_CONTROL = 1.5


@dataclass(slots=True)
class Fix:
    """One candidate remediation with its effort proxy."""

    kind: str
    label: str
    cost: float
    package_id: str = ""
    service_id: str = ""
    edge_from: str = ""
    edge_to: str = ""
    control_type: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return "|".join(
            [self.kind, self.package_id, self.service_id, self.edge_from, self.edge_to]
        )

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "label": self.label, "cost": round(self.cost, 2)}
        if self.package_id:
            out["package_id"] = self.package_id
        if self.service_id:
            out["service_id"] = self.service_id
        if self.edge_from:
            out["edge_from"] = self.edge_from
        if self.edge_to:
            out["edge_to"] = self.edge_to
        if self.control_type:
            out["control_type"] = self.control_type
        if self.detail:
            out["detail"] = self.detail
        return out

    def apply_to(self, proj: SecurityProjection, mods: Modifications) -> Modifications:
        out = mods.copy()
        if self.kind == "upgrade_package":
            out.removed_findings |= {
                fid for fid, f in proj.findings.items() if f.get("package_name") == self.package_id
            }
        elif self.kind == "patch_service_dependency":
            out.removed_findings |= {
                fid
                for fid, f in proj.findings.items()
                if f.get("package_name") == self.package_id and f.get("service_id") == self.service_id
            }
        elif self.kind == "harden_edge":
            out.hardened_edges.add((self.edge_from, self.edge_to))
        elif self.kind == "add_control":
            out.controlled_services.add(self.service_id)
        return out


def fix_from_dict(raw: dict[str, Any], proj: SecurityProjection) -> Fix | None:
    """Rebuild a Fix from the JSON shape find_chokepoints returns."""
    kind = str(raw.get("kind") or "").strip()
    package_id = str(raw.get("package_id") or "")
    service_id = str(raw.get("service_id") or "")
    edge_from = str(raw.get("from") or raw.get("edge_from") or "")
    edge_to = str(raw.get("to") or raw.get("edge_to") or "")
    if kind == "upgrade_package" and package_id:
        return _upgrade_fix(proj, package_id)
    if kind == "patch_service_dependency" and package_id and service_id:
        return _patch_fix(proj, service_id, package_id)
    if kind == "harden_edge" and edge_from and edge_to:
        return _harden_fix(proj, edge_from, edge_to)
    if kind == "add_control" and service_id:
        return _control_fix(proj, service_id)
    return None


def _package_label(proj: SecurityProjection, package_id: str) -> str:
    pkg = proj.packages.get(package_id, {})
    name = pkg.get("name") or package_id
    version = pkg.get("version") or "?"
    return f"{name}@{version}"


def _fixed_in_for(proj: SecurityProjection, package_id: str) -> str:
    versions = sorted(
        {f.get("fixed_in", "") for f in proj.findings.values() if f.get("package_name") == package_id and f.get("fixed_in")}
    )
    return versions[-1] if versions else ""


def _upgrade_fix(proj: SecurityProjection, package_id: str) -> Fix:
    users = proj.package_services(package_id)
    fixed_in = _fixed_in_for(proj, package_id)
    label = f"Upgrade {_package_label(proj, package_id)}"
    if fixed_in:
        label += f" to {fixed_in}"
    return Fix(
        kind="upgrade_package",
        label=label,
        cost=COST_UPGRADE_BASE + COST_UPGRADE_PER_SERVICE * len(users),
        package_id=package_id,
        detail={"services_using": len(users), "fixed_in": fixed_in},
    )


def _patch_fix(proj: SecurityProjection, service_id: str, package_id: str) -> Fix:
    fixed_in = _fixed_in_for(proj, package_id)
    label = f"Patch {_package_label(proj, package_id)} in {service_id}"
    if fixed_in:
        label += f" ({fixed_in})"
    return Fix(
        kind="patch_service_dependency",
        label=label,
        cost=COST_PATCH_SERVICE,
        package_id=package_id,
        service_id=service_id,
        detail={"fixed_in": fixed_in},
    )


def _harden_fix(proj: SecurityProjection, src: str, dst: str) -> Fix:
    # Find the edge to get current authz
    edge_data = proj.graph.get_edge_data(src, dst) or {}
    return Fix(
        kind="harden_edge",
        label=f"Require mTLS on {src} -> {dst}",
        cost=COST_HARDEN_EDGE,
        edge_from=src,
        edge_to=dst,
        detail={"current_authz": edge_data.get("authz", "none")},
    )


def _control_fix(proj: SecurityProjection, service_id: str) -> Fix:
    # Check if service has WAF
    svc = proj.services.get(service_id, {})
    control_type = "waf_rule" if svc.get("waf") else "virtual_patch"
    return Fix(
        kind="add_control",
        label=f"Add {control_type.replace('_', ' ')} in front of {service_id}",
        cost=COST_ADD_CONTROL,
        service_id=service_id,
        control_type=control_type,
        detail={"public_ingress": [f"ingress-{service_id}"]},
    )


def candidate_fixes(proj: SecurityProjection, paths: list[AttackPath], mods: Modifications) -> list[Fix]:
    """Fixes that could plausibly cut at least one of the given paths."""
    entry_live = live_exploits(proj, mods, as_entry=True)
    by_key: dict[str, Fix] = {}

    for path in paths:
        for exploit in path.live_exploits:
            finding = proj.findings.get(str(exploit["finding_id"]))
            if finding is None or not finding.get("package_name"):
                continue
            upgrade = _upgrade_fix(proj, finding["package_name"])
            by_key.setdefault(upgrade.key, upgrade)
            patch = _patch_fix(proj, finding.get("service_id", ""), finding["package_name"])
            by_key.setdefault(patch.key, patch)
        for edge in path.edges:
            if edge.get("type") == "CALLS":
                harden = _harden_fix(proj, str(edge["source"]), str(edge["target"]))
                by_key.setdefault(harden.key, harden)
        if path.entry in entry_live:
            control = _control_fix(proj, path.entry)
            by_key.setdefault(control.key, control)

    return sorted(by_key.values(), key=lambda f: (f.cost, f.key))[:MAX_CANDIDATES_PER_ROUND]


@dataclass(slots=True)
class SolverResult:
    baseline_paths: int
    baseline_weight: float
    fixes: list[dict[str, Any]]
    residual_paths: int
    residual_weight: float
    structural: dict[str, Any]
    engine: str
    cypher: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline": {
                "paths": self.baseline_paths,
                "total_weight": round(self.baseline_weight, 4),
            },
            "fixes": self.fixes,
            "residual": {
                "paths": self.residual_paths,
                "total_weight": round(self.residual_weight, 4),
            },
            "structural_corroboration": self.structural,
        }


def find_chokepoints(proj: SecurityProjection, *, max_fixes: int = 8, max_hops: int = 7) -> SolverResult:
    """Greedy weighted set cover over attack paths."""
    baseline = enumerate_attack_paths(proj, max_hops=max_hops, top_k=0)
    baseline_weight = total_weight(baseline)
    mods = Modifications()
    picked: list[dict[str, Any]] = []
    picked_keys: set[str] = set()
    current = baseline
    removed_total = 0.0

    while len(picked) < max_fixes and baseline_weight > 0:
        if removed_total >= COVERAGE_TARGET * baseline_weight:
            break
        current_weight = total_weight(current)
        best: tuple[float, float, str, Fix, list[AttackPath], float] | None = None
        for fix in candidate_fixes(proj, current, mods):
            if fix.key in picked_keys:
                continue
            trial_mods = fix.apply_to(proj, mods)
            trial_paths = enumerate_attack_paths(proj, mods=trial_mods, max_hops=max_hops, top_k=0)
            removed = current_weight - total_weight(trial_paths)
            if removed <= 1e-9:
                continue
            ratio = removed / max(fix.cost, 0.01)
            candidate = (-ratio, fix.cost, fix.key, fix, trial_paths, removed)
            if best is None or candidate[:3] < best[:3]:
                best = candidate
        if best is None:
            break
        _ratio, _cost, _key, fix, trial_paths, removed = best
        removed_total += removed
        mods = fix.apply_to(proj, mods)
        picked_keys.add(fix.key)
        cut = len(current) - len(trial_paths)
        current = trial_paths
        entry = fix.as_dict()
        entry.update(
            {
                "rank": len(picked) + 1,
                "risk_removed": round(removed, 4),
                "paths_removed": cut,
                "cumulative_risk_removed_pct": round(
                    100.0 * removed_total / baseline_weight if baseline_weight else 0.0, 1
                ),
                "paths_remaining": len(current),
            }
        )
        picked.append(entry)

    structural = _structural_corroboration(proj, baseline, picked)
    return SolverResult(
        baseline_paths=len(baseline),
        baseline_weight=baseline_weight,
        fixes=picked,
        residual_paths=len(current),
        residual_weight=total_weight(current),
        structural=structural,
        engine="networkx",
        cypher=list(structural.get("cypher", [])),
    )


def _structural_corroboration(
    proj: SecurityProjection, paths: list[AttackPath], picks: list[dict[str, Any]]
) -> dict[str, Any]:
    """Do graph-centrality measures agree with the greedy picks?"""
    on_paths = sorted({s for p in paths for s in p.services})
    if not on_paths:
        return {"engine": "networkx", "top_central": [], "agreement": 0.0, "cypher": []}

    # Use betweenness centrality on the call graph
    call_graph = nx.DiGraph()
    for src, dst, data in proj.graph.edges(data=True):
        if data.get("relation") == "CALLS":
            call_graph.add_edge(src, dst)

    if not call_graph.nodes():
        return {"engine": "networkx", "top_central": [], "agreement": 0.0, "cypher": []}

    # Restrict to services on paths
    subgraph = call_graph.subgraph([n for n in on_paths if n in call_graph]).copy()
    if subgraph.number_of_nodes() == 0:
        return {"engine": "networkx", "top_central": [], "agreement": 0.0, "cypher": []}

    try:
        scores = nx.betweenness_centrality(subgraph, normalized=True)
    except Exception:
        scores = nx.pagerank(subgraph, alpha=0.85) if subgraph.number_of_nodes() > 0 else {}

    ranked = sorted(scores.items(), key=lambda kv: (-float(kv[1]), kv[0]))[:5]
    touched: set[str] = set()
    for pick in picks:
        if pick.get("service_id"):
            touched.add(str(pick["service_id"]))
        if pick.get("edge_from"):
            touched.add(str(pick["edge_from"]))
        if pick.get("edge_to"):
            touched.add(str(pick["edge_to"]))
        if pick.get("package_id"):
            touched |= proj.package_services(str(pick["package_id"]))
    overlap = [node for node, _ in ranked if node in touched]
    return {
        "engine": "networkx",
        "measure": "betweenness",
        "top_central": [{"id": node, "score": round(float(score), 4)} for node, score in ranked],
        "agreement": round(len(overlap) / len(ranked), 2) if ranked else 0.0,
        "agreeing_nodes": overlap,
        "cypher": [],
    }



def simulate_fixes(proj: SecurityProjection, fixes: list[Fix], *, max_hops: int = 7, top_k: int = 8) -> dict[str, Any]:
    """Apply fixes to a copy of the graph and compare before with after."""
    before = enumerate_attack_paths(proj, max_hops=max_hops, top_k=0)
    before_weight = total_weight(before)
    crown_before = sorted({p.target for p in before})

    # Apply fixes to a copy
    mods = Modifications()
    for fix in fixes:
        mods = fix.apply_to(proj, mods)

    after = enumerate_attack_paths(proj, mods=mods, max_hops=max_hops, top_k=0)
    after_weight = total_weight(after)
    crown_after = sorted({p.target for p in after})

    return {
        "fixes_applied": [f.as_dict() for f in fixes],
        "before": {
            "paths": len(before),
            "total_weight": round(before_weight, 4),
            "top_score": round(before[0].breakdown.score, 4) if before else 0.0,
            "crown_jewels_reachable": crown_before,
            "top_paths": [p.as_dict(verbose=False) for p in before[:top_k]],
        },
        "after": {
            "paths": len(after),
            "total_weight": round(after_weight, 4),
            "top_score": round(after[0].breakdown.score, 4) if after else 0.0,
            "crown_jewels_reachable": crown_after,
            "top_paths": [p.as_dict(verbose=False) for p in after[:top_k]],
        },
        "delta": {
            "paths_removed": len(before) - len(after),
            "weight_removed": round(before_weight - after_weight, 4),
            "risk_removed_pct": round(
                100.0 * (before_weight - after_weight) / before_weight if before_weight else 0.0, 1
            ),
            "crown_jewels_cut": [c for c in crown_before if c not in crown_after],
        },
        "cypher": [],
    }


solve_chokepoints = find_chokepoints
