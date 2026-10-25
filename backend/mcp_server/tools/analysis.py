"""Analysis tools (PRD 8.2): paths, exploitability, algorithms, solver, simulation."""

from __future__ import annotations

import logging
import time
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import algos
from ..attack import check_finding, cypher_candidates, enumerate_paths, reachable_set, total_weight
from app.graph.attack import enumerate_attack_paths
from app.graph.projection import load_projection
from app.graph import envelope, error_envelope
from ..solver import find_chokepoints as solve_chokepoints
from ..solver import fix_from_dict, simulate

log = logging.getLogger("chokepoint.tools.analysis")


class FixSpec(BaseModel):
    """One remediation, in the exact shape `find_chokepoints` returns."""

    model_config = ConfigDict(extra="ignore")

    kind: Literal["upgrade_package", "patch_service_dependency", "harden_edge", "add_control"] = Field(
        description="Which kind of fix to apply."
    )
    package_id: str = Field(default="", description="Package node id, for upgrade or patch fixes.")
    service_id: str = Field(default="", description="Service node id, for patch or control fixes.")
    edge_from: str = Field(default="", description="Caller service id, for harden_edge.")
    edge_to: str = Field(default="", description="Callee service id, for harden_edge.")


def find_attack_paths(
    target: Annotated[
        str | None, Field(description="Restrict to one data store id or name, for example 'payments-vault'.")
    ] = None,
    max_hops: Annotated[int, Field(ge=2, le=7, description="Maximum path length in edges.")] = 7,
    top_k: Annotated[int, Field(ge=1, le=25, description="How many paths to return, best first.")] = 8,
    include_mitigated: Annotated[
        bool, Field(description="Also return paths that only exist if active controls are ignored.")
    ] = False,
) -> dict[str, Any]:
    """Enumerate internet-to-crown-jewel attack paths with scored components."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        candidate_rows, candidate_cypher = cypher_candidates(proj, max_hops)
        paths = enumerate_paths(
            proj,
            max_hops=max_hops,
            top_k=top_k,
            target=target,
            include_mitigated=include_mitigated,
        )
        all_paths = enumerate_paths(proj, max_hops=max_hops, top_k=0, target=target)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("find_attack_paths failed", detail=str(exc))

    data = {
        "paths": [p.as_dict() for p in paths],
        "path_count": len(all_paths),
        "total_weight": round(total_weight(all_paths), 4),
        "candidate_rows_from_cypher": candidate_rows,
        "max_hops": max_hops,
        "target": target or "any crown jewel",
    }
    if paths:
        best = paths[0]
        chain = " -> ".join(n["id"] for n in best.nodes)
        summary = (
            f"{len(all_paths)} path(s) from the internet to a crown jewel; total weighted risk "
            f"{round(total_weight(all_paths), 3)}. Best: {chain} at {round(best.breakdown.score * 100, 1)} "
            f"({best.hops} hops, entry authn '{best.entry_authn}')."
        )
    else:
        summary = (
            "No path from the internet to a crown-jewel data store under current controls"
            + (f" for target {target}." if target else ".")
        )
    touched = [nid for p in paths for nid in p.node_ids()] + [
        f["finding_id"] for p in paths for f in p.live_exploits
    ]
    return envelope(
        summary=summary,
        data=data,
        cypher=[candidate_cypher, *proj.cypher_used[:3]],
        touched_ids=touched,
        rows=len(paths),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        # The model sees `data.paths` after clipping; the orchestrator persists
        # from `full.paths`, so the map and the ribbon are never truncated.
        extra={"full": {"paths": [p.as_dict() for p in all_paths[:12]]}},
    )


def blast_radius(
    service_id: Annotated[str, Field(description="Service id to expand from.")],
    max_hops: Annotated[int, Field(ge=1, le=6, description="Maximum lateral hops.")] = 4,
) -> dict[str, Any]:
    """What an attacker reaches after owning one service: services, roles, data, crown jewels."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        if service_id not in proj.services:
            return error_envelope(f"No service with id '{service_id}'.", detail="unknown service")
        algo = algos.bfs_levels(service_id, max_hops, proj.graph)
        depths = reachable_set(proj, service_id, max_hops=max_hops)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("blast_radius failed", detail=str(exc))

    reached = sorted(depths)
    stores: list[dict[str, Any]] = []
    for sid, rel, store_id in proj.store_access:
        if sid in depths and store_id in proj.stores:
            store = proj.stores[store_id]
            stores.append({**store, "via_service": sid, "access": rel, "hops": depths[sid]})
    roles: list[dict[str, Any]] = []
    for sid, role_id, store_id, privilege in proj.role_access:
        if sid in depths:
            roles.append(
                {
                    "role_id": role_id,
                    "privilege": privilege,
                    "store_id": store_id,
                    "via_service": sid,
                    "crown_jewel": bool(proj.stores.get(store_id, {}).get("crown_jewel")),
                }
            )
            if store_id in proj.stores:
                stores.append(
                    {**proj.stores[store_id], "via_service": sid, "access": "CAN_ACCESS", "hops": depths[sid]}
                )
    unique_stores = {s["id"]: s for s in stores}
    crown = sorted(s["id"] for s in unique_stores.values() if s.get("crown_jewel"))
    data = {
        "start": service_id,
        "services_reached": reached,
        "depths": depths,
        "data_stores_reached": sorted(unique_stores.values(), key=lambda s: str(s["id"])),
        "iam_roles_reached": roles,
        "crown_jewels_reached": crown,
        "lateral_edges_considered": "CALLS where authz <> 'mtls'",
    }
    summary = (
        f"From {service_id}: {len(reached) - 1} other service(s) within {max_hops} non-mTLS hops, "
        f"{len(unique_stores)} data store(s), {len(crown)} crown jewel(s)"
        + (f" ({', '.join(crown)})." if crown else ".")
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=algo.cypher,
        touched_ids=[service_id, *reached, *unique_stores.keys()],
        rows=len(reached) + len(unique_stores),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        engine=algo.engine,
    )


def check_exploitability(
    finding_id: Annotated[str, Field(description="Finding id, for example 'F-0001'.")],
) -> dict[str, Any]:
    """Decide whether one finding is a live exploit, with a boolean per predicate and a reason."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        check = check_finding(proj, finding_id)
        if check is None:
            return error_envelope(f"No finding with id '{finding_id}'.", detail="unknown finding")
        adjacent = check_finding(proj, finding_id, allow_adjacent=True)
        paths = enumerate_attack_paths(proj, top_k=0)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("check_exploitability failed", detail=str(exc))

    facts = proj.findings[finding_id]
    service_id = facts.get("service_id") or facts.get("mapped_service_id", "")
    on_paths = [p for p in paths if finding_id in p.finding_ids()]
    service = proj.services.get(service_id, {})
    cve = facts.get("cve", "")
    cvss = float(facts.get("cvss", 0.0))
    pkg_name = facts.get("package_name", "")
    pkg_ver = facts.get("installed_version", "")
    data = {
        **check.as_dict(),
        "live_after_lateral_movement": bool(adjacent and adjacent.live),
        "vulnerability": {
            "cve": cve,
            "cvss": cvss,
            "epss": float(facts.get("epss", 0.0)),
            "kev": bool(facts.get("kev", False)),
            "attack_vector": facts.get("attack_vector", "network"),
            "requires_auth": bool(facts.get("requires_auth", False)),
            "fixed_in": facts.get("fixed_in", ""),
            "summary": facts.get("summary", ""),
        },
        "package": f"{pkg_name}@{pkg_ver}" if pkg_name else "",
        "service": {
            "id": service_id,
            "status": service.get("status"),
            "tier": service.get("tier"),
            "env": service.get("env"),
            "cluster": service.get("cluster"),
        },
        "on_attack_paths": [
            {"path_id": p.id, "target": p.target, "score_pct": round(p.breakdown.score * 100, 1)}
            for p in on_paths[:5]
        ],
        "attack_path_count": len(on_paths),
    }
    verdict_word = "a live exploit" if check.live else "not a live exploit"
    summary = (
        f"{finding_id} ({cve} on {service_id}, CVSS {cvss}) is {verdict_word}: "
        + "; ".join(check.reasons[:3])
        + f". It sits on {len(on_paths)} crown-jewel attack path(s)."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=proj.cypher_used[:3],
        touched_ids=[finding_id, service_id, *(p.target for p in on_paths[:5])],
        rows=1 + len(on_paths),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def rank_centrality(
    scope: Annotated[
        Literal["attack_paths", "services"], Field(description="Rank only services on attack paths, or all.")
    ] = "attack_paths",
    algorithm: Annotated[
        Literal["betweenness", "pagerank"], Field(description="Which centrality measure to run.")
    ] = "betweenness",
) -> dict[str, Any]:
    """Structural importance of services, to corroborate or question the chokepoint picks."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        nodes: list[str] | None = None
        if scope == "attack_paths":
            paths = enumerate_attack_paths(proj, top_k=0)
            nodes = sorted({s for p in paths for s in p.services})
            if not nodes:
                return envelope(
                    summary="No services on attack paths, so there is nothing to rank.",
                    data={"scope": scope, "algorithm": algorithm, "ranking": []},
                    cypher=proj.cypher_used[:2],
                    rows=0,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    engine="networkx",
                )
        result = (
            algos.betweenness_centrality(nodes, proj.graph)
            if algorithm == "betweenness"
            else algos.pagerank(nodes, proj.graph)
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("rank_centrality failed", detail=str(exc))

    scores = dict(result.data.get("scores") or {})
    ranking = [
        {"id": node, "score": round(float(score), 5), "name": proj.name_of(node)}
        for node, score in sorted(scores.items(), key=lambda kv: (-float(kv[1]), kv[0]))[:12]
    ]
    top = ", ".join(r["id"] for r in ranking[:5]) or "none"
    return envelope(
        summary=f"{algorithm} over {scope} ranks: {top} (engine {result.engine}).",
        data={"scope": scope, "algorithm": algorithm, "ranking": ranking, "ranked_nodes": len(scores)},
        cypher=result.cypher,
        touched_ids=[r["id"] for r in ranking],
        rows=len(ranking),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        engine=result.engine,
    )


def find_chokepoints(
    max_fixes: Annotated[int, Field(ge=1, le=8, description="Maximum fixes in the returned set.")] = 8,
) -> dict[str, Any]:
    """The smallest ordered set of fixes that removes the most weighted attack-path risk."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        result = solve_chokepoints(proj, max_fixes=max_fixes)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("find_chokepoints failed", detail=str(exc))

    data = result.as_dict()
    if result.fixes:
        first = result.fixes[0]
        top3 = result.fixes[: min(3, len(result.fixes))]
        data["top3_cumulative_pct"] = top3[-1]["cumulative_risk_removed_pct"]
        summary = (
            f"{len(result.fixes)} fix(es) remove "
            f"{result.fixes[-1]['cumulative_risk_removed_pct']}% of {round(result.baseline_weight, 3)} "
            f"weighted path risk across {result.baseline_paths} paths. First: {first['label']} "
            f"(cost {first['cost']}, removes {first['cumulative_risk_removed_pct']}%). "
            f"Structural agreement with centrality: {result.structural.get('agreement')}."
        )
    else:
        summary = "No fix removes any weighted path risk; there are no viable attack paths to cut."
    touched = []
    for fix in result.fixes:
        if fix.get("service_id"):
            touched.append(str(fix["service_id"]))
        if fix.get("package_id"):
            touched.append(str(fix["package_id"]))
        for key in ("edge_from", "edge_to"):
            if fix.get(key):
                touched.append(str(fix[key]))
    return envelope(
        summary=summary,
        data=data,
        cypher=[*result.cypher, *proj.cypher_used[:2]],
        touched_ids=touched,
        rows=len(result.fixes),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        engine=result.engine,
    )


def simulate_fix(
    fixes: Annotated[list[FixSpec], Field(description="Fixes to apply, as returned by find_chokepoints.")],
) -> dict[str, Any]:
    """Apply fixes to a throwaway copy of the graph and report before and after."""
    started = time.perf_counter()
    if not fixes:
        return error_envelope("simulate_fix needs at least one fix.", detail="empty fix list")
    try:
        proj = load_projection()
        resolved = []
        unknown: list[dict[str, Any]] = []
        for spec in fixes[:8]:
            # Over MCP the SDK coerces to FixSpec; in-process callers pass dicts.
            raw = spec.model_dump() if hasattr(spec, "model_dump") else dict(spec)
            fix = fix_from_dict(raw, proj)
            if fix is None:
                unknown.append(raw)
            else:
                resolved.append(fix)
        if not resolved:
            return error_envelope(
                "No fix could be resolved against the graph.",
                detail=f"unrecognised fixes: {unknown}",
            )
        result = simulate(proj, resolved)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("simulate_fix failed", detail=str(exc))

    delta = result["delta"]
    cut = ", ".join(delta["crown_jewels_cut"]) or "none"
    summary = (
        f"Applying {len(resolved)} fix(es) on a graph copy removes {delta['paths_removed']} of "
        f"{result['before']['paths']} paths and {delta['risk_removed_pct']}% of weighted risk. "
        f"Crown jewels cut off: {cut}. Scratch graph deleted."
    )
    if unknown:
        result["unresolved_fixes"] = unknown
    return envelope(
        summary=summary,
        data=result,
        cypher=result["cypher"],
        touched_ids=[p["target"] for p in result["before"]["top_paths"]],
        rows=result["before"]["paths"] + result["after"]["paths"],
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def connected_components(
    scope: Annotated[
        Literal["calls", "services"], Field(description="Component analysis over the service CALLS graph.")
    ] = "calls",
) -> dict[str, Any]:
    """Weakly connected components of the call graph: proves which segments cannot reach each other."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        result = algos.weakly_connected(proj.graph)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("connected_components failed", detail=str(exc))

    components = list(result.data.get("components") or [])
    isolated = [c for c in components if len(c) <= 4]
    described = []
    for index, members in enumerate(components[:12], start=1):
        clusters = sorted({str(proj.services.get(m, {}).get("cluster") or "?") for m in members})
        envs = sorted({str(proj.services.get(m, {}).get("env") or "?") for m in members})
        crown = sorted(
            {
                store_id
                for sid, _rel, store_id in proj.store_access
                if sid in members and proj.stores.get(store_id, {}).get("crown_jewel")
            }
            | {
                store_id
                for sid, _role, store_id, _priv in proj.role_access
                if sid in members and proj.stores.get(store_id, {}).get("crown_jewel")
            }
        )
        described.append(
            {
                "component": index,
                "size": len(members),
                "members": members[:20],
                "clusters": clusters,
                "envs": envs,
                "crown_jewels_reachable": crown,
            }
        )
    orphan_services = sorted(
        sid for sid in proj.services if all(sid not in c for c in components)
    )
    data = {
        "scope": scope,
        "component_count": len(components) + len(orphan_services),
        "components": described,
        "services_with_no_call_edges": orphan_services[:30],
    }
    summary = (
        f"{len(components)} connected component(s) in the CALLS graph plus "
        f"{len(orphan_services)} service(s) with no call edges at all; "
        f"{len(isolated)} component(s) hold four services or fewer."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=result.cypher,
        touched_ids=[m for c in components[:4] for m in c[:10]],
        rows=len(components),
        latency_ms=(time.perf_counter() - started) * 1000.0,
        engine=result.engine,
    )


def shortest_path(
    from_id: Annotated[str, Field(description="Source node id, for example 'internet'.")],
    to_id: Annotated[str, Field(description="Destination node id.")],
    rel_types: Annotated[
        list[str] | None,
        Field(description="Restrict to these relationship types, for example ['CALLS','ROUTES_TO']."),
    ] = None,
) -> dict[str, Any]:
    """Shortest connection between two nodes - the cheapest way to prove or disprove reachability."""
    started = time.perf_counter()
    try:
        proj = load_projection()
        result = algos.shortest_path(from_id, to_id, proj.graph, rel_types)
    except Exception as exc:  # noqa: BLE001
        return error_envelope("shortest_path failed", detail=str(exc))

    data = {"from": from_id, "to": to_id, "rel_types": rel_types or "all estate types", **result.data}
    if result.data.get("found"):
        chain = " -> ".join(str(n) for n in result.data.get("nodes", []))
        summary = f"{result.data.get('hops')} hop(s) from {from_id} to {to_id}: {chain}."
    else:
        summary = f"No connection from {from_id} to {to_id}: {result.data.get('reason')}"
    return envelope(
        summary=summary,
        data=data,
        cypher=result.cypher,
        touched_ids=[from_id, to_id, *[str(n) for n in result.data.get("nodes", [])]],
        rows=result.rows,
        latency_ms=(time.perf_counter() - started) * 1000.0,
        engine=result.engine,
    )


DESCRIPTIONS = {
    "find_attack_paths": (
        "The primary risk tool. Enumerates ordered Internet -> Ingress -> Service(+) -> [IAMRole] -> "
        "DataStore paths where every service hop is actually enterable (public ingress with a live "
        "exploit, or lateral movement over a non-mTLS call edge), scores each path deterministically "
        "and returns the best ones with every score component. Use it before forming any opinion "
        "about what matters. It persists nothing."
    ),
    "blast_radius": (
        "Breadth-first reach from one service over non-mTLS call edges: which services, IAM roles and "
        "data stores an attacker gets after owning it. Use it to size the consequence of a single "
        "compromise, and in ticket bodies."
    ),
    "check_exploitability": (
        "Evaluate one finding against every live-exploit predicate (open, service active, network "
        "vector, authentication, reachable code, blocking control) and return a boolean plus a reason "
        "for each, and whether the finding sits on an attack path. Use it to verify a claim before "
        "making it, and to falsify someone else's."
    ),
    "rank_centrality": (
        "Betweenness or PageRank over the call graph, optionally restricted to services on attack "
        "paths. Use it as independent structural evidence for or against a chokepoint claim. It is "
        "not a risk score."
    ),
    "find_chokepoints": (
        "Greedy weighted set cover over the attack-path set: the ordered minimal fix list with cost, "
        "paths removed and cumulative percentage of weighted risk removed, plus centrality "
        "corroboration. This is the answer to 'what should we do first'. Report its numbers exactly."
    ),
    "simulate_fix": (
        "Counterfactual: copy the graph, apply the given fixes to the copy, re-run path search and "
        "return before and after (path counts, total weight, top score, crown jewels still "
        "reachable). The scratch graph is always deleted. Use it to quantify a recommendation."
    ),
    "connected_components": (
        "Weakly connected components of the CALLS graph. Use it to prove that a segment (for example "
        "a sandbox cluster) has no call route to anything that touches production data."
    ),
    "shortest_path": (
        "Shortest path between two node ids over chosen relationship types. Use it for a cheap, "
        "decisive reachability answer, including proving that no route exists."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="find_attack_paths", description=DESCRIPTIONS["find_attack_paths"])(find_attack_paths)
    mcp.tool(name="blast_radius", description=DESCRIPTIONS["blast_radius"])(blast_radius)
    mcp.tool(name="check_exploitability", description=DESCRIPTIONS["check_exploitability"])(
        check_exploitability
    )
    mcp.tool(name="rank_centrality", description=DESCRIPTIONS["rank_centrality"])(rank_centrality)
    mcp.tool(name="find_chokepoints", description=DESCRIPTIONS["find_chokepoints"])(find_chokepoints)
    mcp.tool(name="simulate_fix", description=DESCRIPTIONS["simulate_fix"])(simulate_fix)
    mcp.tool(name="connected_components", description=DESCRIPTIONS["connected_components"])(
        connected_components
    )
    mcp.tool(name="shortest_path", description=DESCRIPTIONS["shortest_path"])(shortest_path)