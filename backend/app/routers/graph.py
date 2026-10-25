"""Graph read endpoints for the map, the headline numbers and the naive view."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Query

from app.config import settings
from app.db import node_count
from app.graph.projection import load_projection
from app.graph.attack import enumerate_attack_paths, live_exploits, blast_radius, Modifications
from app.models import (
    CrownJewel,
    FindingRow,
    GraphEdge,
    GraphNode,
    GraphOverviewResponse,
    Headline,
    NaiveViewResponse,
    PublicIngress,
    SubgraphResponse,
)

router = APIRouter(prefix="/graph", tags=["graph"])

NODE_CAP = 150
EDGE_CAP = 900


def _clean_props(props: Any) -> dict[str, Any]:
    if not isinstance(props, dict):
        return {}
    return {
        key: value
        for key, value in props.items()
        if not key.startswith("__") and key not in ("embedding", "result_json", "payload_json")
    }


def _edges_between(G, ids: list[str]) -> list[GraphEdge]:
    if not ids:
        return []
    seen: dict[str, GraphEdge] = {}
    wanted = set(ids)
    for src in ids:
        if src not in G:
            continue
        for _u, dst, data in G.out_edges(src, data=True):
            if dst not in wanted:
                continue
            rel = str(data.get("relation", ""))
            key = f"{src}|{rel}|{dst}"
            if key in seen:
                continue
            seen[key] = GraphEdge(
                id=key, source=src, target=dst, type=rel, props=_clean_props(data)
            )
    return list(seen.values())


def _expand(G, ids: list[str], hops: int) -> list[str]:
    frontier = list(dict.fromkeys(ids))
    collected = list(frontier)
    for _ in range(max(0, hops)):
        if not frontier or len(collected) >= NODE_CAP * 2:
            break
        neighbours: list[str] = []
        for src in frontier:
            if src not in G:
                continue
            for dst in G.successors(src):
                if dst not in collected:
                    collected.append(dst)
                    neighbours.append(dst)
            for pred in G.predecessors(src):
                if pred not in collected:
                    collected.append(pred)
                    neighbours.append(pred)
        frontier = neighbours
    return collected


def _subgraph(G, ids: list[str], hops: int) -> SubgraphResponse:
    started = time.perf_counter()
    collected = _expand(G, ids, hops)
    truncated = len(collected) > NODE_CAP
    hidden = max(0, len(collected) - NODE_CAP)
    kept = collected[:NODE_CAP]
    nodes = [
        GraphNode(
            id=nid,
            label=str(G.nodes[nid].get("label", "Unknown")),
            props=_clean_props(G.nodes[nid]),
        )
        for nid in kept if nid in G
    ]
    present = [n.id for n in nodes]
    return SubgraphResponse(
        nodes=nodes,
        edges=_edges_between(G, present),
        truncated=truncated,
        hidden_nodes=hidden,
        latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
    )


def _overview() -> GraphOverviewResponse:
    proj = load_projection()
    scan_ids = [proj.scan_id]

    # These two were hardcoded to {} , so the Case Board legend and the type
    # counts were always empty even with a fully populated graph.
    nodes_by_label: dict[str, int] = {}
    for props in proj.nodes.values():
        label = str(props.get("label") or "Unknown")
        nodes_by_label[label] = nodes_by_label.get(label, 0) + 1
    relationships_by_type: dict[str, int] = {}
    for _s, _d, data in proj.graph.edges(data=True):
        rel = str(data.get("relation") or "UNKNOWN")
        relationships_by_type[rel] = relationships_by_type.get(rel, 0) + 1

    # Public ingress: services with public ingress
    public_ingress = []
    for sid, svc in proj.services.items():
        if svc.get("public_ingress") or svc.get("internet_facing"):
            public_ingress.append(
                PublicIngress(
                    id=f"ingress-{sid}",
                    host=svc.get("ingress_host", ""),
                    # Scoring reads ingress_authn; reading a non-existent
                    # 'authn' key made the board show oidc while the score used none.
                    authn=str(svc.get("ingress_authn") or svc.get("authn") or "unknown"),
                    waf=bool(svc.get("waf")),
                    service_id=sid,
                )
            )

    # Crown jewels: data stores with crown_jewel or sensitive classification
    crown_jewels = []
    for nid, props in proj.nodes.items():
        if props.get("crown_jewel") or props.get("classification") in ("pci", "pii", "secrets"):
            crown_jewels.append(
                CrownJewel(
                    id=nid,
                    name=props.get("name", ""),
                    kind=props.get("kind", ""),
                    classification=props.get("classification", "unknown"),
                    records=int(props.get("records") or 0),
                )
            )

    # Live exploit counts
    entry_live = live_exploits(proj, Modifications(), as_entry=True)
    lateral_live = live_exploits(proj, Modifications(), as_entry=False)
    paths = enumerate_attack_paths(proj, top_k=0)
    path_services = {s for p in paths for s in p.services}
    internet_reachable = sum(len(v) for k, v in entry_live.items() if _has_public_ingress(proj, k))
    reaching_crown = sum(len(lateral_live.get(s, [])) for s in path_services)

    headline = Headline(
        open_findings=sum(1 for f in proj.findings.values() if f.get("status") == "open"),
        internet_reachable_findings=internet_reachable,
        findings_reaching_crown_jewel=reaching_crown,
        attack_paths=len(paths),
        crown_jewels_reachable=sorted({p.target for p in paths}),
        top_path_score_pct=round(paths[0].breakdown.score * 100, 1) if paths else 0.0,
    )

    return GraphOverviewResponse(
        nodes_by_label=dict(sorted(nodes_by_label.items(), key=lambda kv: -kv[1])),
        relationships_by_type=dict(sorted(relationships_by_type.items(), key=lambda kv: -kv[1])),
        scan_ids=scan_ids,
        public_ingress_count=len(public_ingress),
        public_ingress=public_ingress,
        crown_jewels=crown_jewels,
        headline=headline,
        latency_ms=proj.load_ms,
    )


def _has_public_ingress(proj, service_id: str) -> bool:
    svc = proj.services.get(service_id, {})
    return bool(svc.get("public_ingress") or svc.get("internet_facing"))


def _focus(kind: str) -> SubgraphResponse:
    proj = load_projection()
    G = proj.graph
    ids: list[str] = ["internet"]
    if kind == "attack_surface":
        paths = enumerate_attack_paths(proj, top_k=10)
        for path in paths:
            ids += [n["id"] for n in path.nodes]
        for sid, svc in proj.services.items():
            if _has_public_ingress(proj, sid):
                ids.append(sid)
        for nid, props in proj.nodes.items():
            if props.get("crown_jewel") or props.get("classification") in ("pci", "pii", "secrets"):
                ids.append(nid)
    elif kind == "controls":
        # Controls would be nodes in the graph
        for nid, props in proj.nodes.items():
            if props.get("label") == "Control":
                ids.append(nid)
    else:
        for sid, svc in proj.services.items():
            if _has_public_ingress(proj, sid):
                ids.append(sid)
        for nid, props in proj.nodes.items():
            if props.get("crown_jewel") or props.get("classification") in ("pci", "pii", "secrets"):
                ids.append(nid)
    unique = [i for i in dict.fromkeys(ids) if i and i in G]

    # Include all services, ingresses, and datastores
    for nid, data in G.nodes(data=True):
        lbl = str(data.get("label", ""))
        if lbl in ("Service", "DataStore", "Ingress"):
            if nid not in unique:
                unique.append(nid)

    # Include vulnerable packages (packages mapped to findings or on attack paths)
    vulnerable_pkg_ids = {
        m.get("node_id") for flist in proj.mappings.values() for m in flist if m.get("node_id") in G
    }
    for v_id in vulnerable_pkg_ids:
        if v_id and v_id in G and v_id not in unique:
            unique.append(v_id)

    # Fill remaining capacity with direct architecture nodes (routes, endpoints)
    if len(unique) < 25:
        for nid, data in G.nodes(data=True):
            lbl = str(data.get("label", ""))
            if lbl in ("Route", "EntryPoint"):
                if nid not in unique:
                    unique.append(nid)
            if len(unique) >= 25:
                break

    unique = unique[:NODE_CAP]
    return _subgraph(G, unique, hops=0)


def _naive(limit: int) -> NaiveViewResponse:
    proj = load_projection()
    rows = []
    for fid, f in proj.findings.items():
        if f.get("status") != "open":
            continue
        rows.append(
            FindingRow(
                finding_id=fid,
                service_id=f.get("service_id", ""),
                cve=f.get("cve", ""),
                cvss=float(f.get("cvss", 0.0)),
                epss=float(f.get("epss", 0.0)),
                kev=bool(f.get("kev", False)),
                attack_vector=f.get("attack_vector", "network"),
                reachable_code=bool(f.get("reachable_code", False)),
                package=f.get("package_name", ""),
                version=str(f.get("installed_version") or f.get("package_version") or ""),
                scan_id=f.get("scan_id", ""),
                summary=f.get("summary", ""),
                tier=int(f.get("tier", 3)),
            )
        )
        if len(rows) >= limit:
            break
    return NaiveViewResponse(findings=rows, latency_ms=proj.load_ms)


@router.get("/overview", response_model=GraphOverviewResponse)
async def overview() -> GraphOverviewResponse:
    return await asyncio.to_thread(_overview)


@router.get("/subgraph", response_model=SubgraphResponse)
async def subgraph(
    ids: str = Query(default="", description="Comma-separated node ids."),
    hops: int = Query(default=1, ge=0, le=3),
) -> SubgraphResponse:
    wanted = [part.strip() for part in ids.split(",") if part.strip()]
    if not wanted:
        return SubgraphResponse()
    proj = load_projection()
    return await asyncio.to_thread(_subgraph, proj.graph, wanted[:60], hops)


@router.get("/focus", response_model=SubgraphResponse)
async def focus(kind: str = Query(default="attack_surface")) -> SubgraphResponse:
    return await asyncio.to_thread(_focus, kind)


@router.get("/findings", response_model=NaiveViewResponse)
async def naive_view(limit: int = Query(default=10, ge=1, le=50)) -> NaiveViewResponse:
    return await asyncio.to_thread(_naive, limit)