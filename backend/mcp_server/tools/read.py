"""Read and discovery tools (PRD 8.1)."""

from __future__ import annotations

import logging
import re
import time
from typing import Annotated, Any

from pydantic import Field

from app.graph.projection import load_projection
from app.graph.attack import (
    Modifications,
    enumerate_attack_paths,
    live_exploits,
    check_finding,
    blast_radius,
)
from app.graph.algorithms import shortest_path
from app.graph import envelope, error_envelope

log = logging.getLogger("chokepoint.tools.read")

SAFE_SEARCH = re.compile(r"[^A-Za-z0-9 ._@/:-]+")


def graph_overview() -> dict[str, Any]:
    """Counts, scan ids, public ingress and crown jewels, plus the live headline numbers."""
    started = time.perf_counter()
    proj = load_projection()

    entry_live = live_exploits(proj, Modifications(), as_entry=True)
    lateral_live = live_exploits(proj, Modifications(), as_entry=False)
    paths = enumerate_attack_paths(proj, top_k=0)
    path_services = {s for p in paths for s in p.services}

    def _has_public_ingress(service_id: str) -> bool:
        svc = proj.services.get(service_id, {})
        return bool(svc.get("public_ingress") or svc.get("internet_facing"))

    internet_reachable = sum(len(v) for k, v in entry_live.items() if _has_public_ingress(k))
    reaching_crown = sum(len(lateral_live.get(s, [])) for s in path_services)

    # Crown jewels
    crown_rows = []
    for nid, props in proj.nodes.items():
        if props.get("crown_jewel") or props.get("classification") in ("pci", "pii", "secrets"):
            crown_rows.append({
                "id": nid,
                "name": props.get("name"),
                "kind": props.get("kind"),
                "classification": props.get("classification"),
                "records": int(props.get("records") or 0),
            })

    # Public ingress
    ingress_rows = []
    for sid, svc in proj.services.items():
        if _has_public_ingress(sid):
            ingress_rows.append({
                "id": f"ingress-{sid}",
                "host": svc.get("ingress_host", ""),
                "authn": svc.get("authn", "oidc"),
                "waf": bool(svc.get("waf")),
                "service_id": sid,
            })

    # Node/relationship counts from graph
    nodes_by_label = {}
    rels_by_type = {}
    for nid, props in proj.nodes.items():
        label = props.get("label", "Unknown")
        nodes_by_label[label] = nodes_by_label.get(label, 0) + 1
    for src, dst, data in proj.graph.edges(data=True):
        rel = data.get("relation", "UNKNOWN")
        rels_by_type[rel] = rels_by_type.get(rel, 0) + 1

    data = {
        "nodes_by_label": nodes_by_label,
        "relationships_by_type": rels_by_type,
        "scan_ids": [proj.scan_id],
        "public_ingress_count": len(ingress_rows),
        "public_ingress": ingress_rows,
        "crown_jewels": crown_rows,
        "headline": {
            "open_findings": sum(1 for f in proj.findings.values() if f.get("status") == "open"),
            "internet_reachable_findings": internet_reachable,
            "findings_reaching_crown_jewel": reaching_crown,
            "attack_paths": len(paths),
            "crown_jewels_reachable": sorted({p.target for p in paths}),
            "top_path_score_pct": round(paths[0].breakdown.score * 100, 1) if paths else 0.0,
        },
    }
    touched = [r["id"] for r in crown_rows] + [r["id"] for r in ingress_rows]
    return envelope(
        summary=(
            f"{data['headline']['open_findings']} open findings; "
            f"{internet_reachable} internet-reachable; {reaching_crown} on a crown-jewel path; "
            f"{len(paths)} attack paths across {data['public_ingress_count']} public ingress points."
        ),
        data=data,
        cypher=[],
        touched_ids=touched,
        rows=len(crown_rows) + len(ingress_rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def find_entities(
    query: Annotated[str, Field(description="Free text: a service name, repo, CVE id or package name.")],
    label: Annotated[
        str | None,
        Field(description="Restrict to one label: Service, Vulnerability, Package or DataStore."),
    ] = None,
    limit: Annotated[int, Field(ge=1, le=40, description="Maximum rows to return.")] = 10,
) -> dict[str, Any]:
    """Resolve free text to graph node ids before using any other tool."""
    started = time.perf_counter()
    proj = load_projection()
    query_lower = query.lower()
    hits = []

    for nid, props in proj.nodes.items():
        # Check various name/identifier fields
        name_fields = [
            props.get("name", ""),
            props.get("id", ""),
            props.get("cve", ""),
            props.get("repo", ""),
            props.get("package_name", ""),
            props.get("symbol", ""),
        ]
        if any(query_lower in str(f).lower() for f in name_fields if f):
            hits.append({
                "id": nid,
                "label": props.get("label", "Unknown"),
                "name": props.get("name") or props.get("id") or nid,
                "score": 1.0,
            })

    # Also check findings
    for fid, f in proj.findings.items():
        if query_lower in fid.lower() or query_lower in f.get("cve", "").lower():
            hits.append({
                "id": fid,
                "label": "Finding",
                "name": f.get("cve", fid),
                "score": 0.9,
            })

    hits.sort(key=lambda r: (-float(r.get("score") or 0.0), str(r.get("name") or "")))
    hits = hits[:limit]
    return envelope(
        summary=f"{len(hits)} match(es) for '{query}'."
        if hits
        else f"No entity matches '{query}'. Try a service name, a CVE id or a package name.",
        data={"matches": hits},
        cypher=[],
        touched_ids=[str(h["id"]) for h in hits],
        rows=len(hits),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def get_service_context(
    service_id: Annotated[str, Field(description="Service id, for example 'gateway'.")],
) -> dict[str, Any]:
    """Everything about one service: owners, on-call, ingress, controls, data, calls, open findings."""
    started = time.perf_counter()
    proj = load_projection()

    if service_id not in proj.services:
        return error_envelope(
            f"No service with id '{service_id}'.",
            detail="use find_entities to resolve the name first",
            cypher=[],
        )

    svc = proj.services[service_id]

    # Ingress
    ingress_rows = []
    if svc.get("public_ingress") or svc.get("internet_facing"):
        ingress_rows.append({
            "id": f"ingress-{service_id}",
            "host": svc.get("ingress_host", ""),
            "public": bool(svc.get("public_ingress") or svc.get("internet_facing")),
            "waf": bool(svc.get("waf")),
            "authn": svc.get("authn", "oidc"),
            "path_prefix": svc.get("path_prefix", "/"),
        })

    # On-call (placeholder - would come from team/people data)
    oncall = []

    # Controls (placeholder)
    controls = []

    # Data stores
    stores = []
    for _, store_id in proj.store_access_for(service_id):
        store_props = proj.nodes.get(store_id, {})
        stores.append({
            "id": store_id,
            "name": store_props.get("name", ""),
            "kind": store_props.get("kind", ""),
            "classification": store_props.get("classification", "internal"),
            "records": int(store_props.get("records") or 0),
            "crown_jewel": bool(store_props.get("crown_jewel")),
            "access": "READS_FROM",  # simplified
        })

    # IAM roles
    iam_roles = []
    for role_id, store_id, privilege in proj.role_access_for(service_id):
        iam_roles.append({
            "id": role_id,
            "name": role_id,
            "privilege": privilege,
            "store_id": store_id,
            "store_classification": proj.nodes.get(store_id, {}).get("classification", "internal"),
            "store_crown_jewel": bool(proj.nodes.get(store_id, {}).get("crown_jewel")),
        })

    # Calls
    calls_out = []
    calls_in = []
    for _, dst, data in proj.graph.out_edges(service_id, data=True):
        if data.get("relation") == "CALLS":
            calls_out.append({
                "src": service_id,
                "dst": dst,
                "authz": data.get("authz", "none"),
                "protocol": data.get("protocol", "http"),
                "rps": int(data.get("rps", 0)),
            })
    for src, _, data in proj.graph.in_edges(service_id, data=True):
        if data.get("relation") == "CALLS":
            calls_in.append({
                "src": src,
                "dst": service_id,
                "authz": data.get("authz", "none"),
                "protocol": data.get("protocol", "http"),
                "rps": int(data.get("rps", 0)),
            })

    # Open findings
    open_findings = []
    for fid in proj.service_findings(service_id):
        f = proj.findings.get(fid, {})
        open_findings.append({
            "finding_id": fid,
            "status": f.get("status", "open"),
            "reachable_code": bool(f.get("reachable_code")),
            "cve": f.get("cve", ""),
            "cvss": float(f.get("cvss", 0.0)),
            "epss": float(f.get("epss", 0.0)),
            "kev": bool(f.get("kev", False)),
            "package": f.get("package_name", ""),
            "version": f.get("package_version", ""),
        })

    touched = (
        [service_id]
        + [r["id"] for r in ingress_rows]
        + [r["id"] for r in controls]
        + [r["id"] for r in stores]
        + [r["finding_id"] for r in open_findings]
    )
    status = str(svc.get("status") or "active")
    summary = (
        f"{service_id} ({status}, tier {svc.get('tier')}, env {svc.get('env')}, cluster {svc.get('cluster')}) "
        f"owned by {svc.get('team_name') or 'nobody'}; {len(ingress_rows)} ingress route(s), "
        f"{len(calls_in)} inbound and {len(calls_out)} outbound calls, "
        f"{len(open_findings)} open findings."
    )
    return envelope(
        summary=summary,
        data={
            "service": svc,
            "on_call": oncall,
            "ingress": ingress_rows,
            "controls": controls,
            "data_stores": stores,
            "iam_roles": iam_roles,
            "calls_out": calls_out,
            "calls_in": calls_in,
            "open_findings": open_findings,
        },
        cypher=[],
        touched_ids=touched,
        rows=len(calls_out) + len(calls_in) + len(open_findings),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def list_open_findings(
    scan_id: Annotated[str | None, Field(description="Restrict to one scan id.")] = None,
    service_id: Annotated[str | None, Field(description="Restrict to one service id.")] = None,
    min_cvss: Annotated[float, Field(ge=0.0, le=10.0, description="Minimum CVSS.")] = 0.0,
    limit: Annotated[int, Field(ge=1, le=100, description="Maximum rows.")] = 25,
) -> dict[str, Any]:
    """The naive CVSS-sorted queue. Use it for context only; it says nothing about reachability."""
    started = time.perf_counter()
    proj = load_projection()
    rows = []
    for fid, f in proj.findings.items():
        if f.get("status") != "open":
            continue
        if scan_id and f.get("scan_id") != scan_id:
            continue
        if service_id and f.get("service_id") != service_id:
            continue
        if float(f.get("cvss", 0.0)) < min_cvss:
            continue
        rows.append({
            "finding_id": fid,
            "service_id": f.get("service_id", ""),
            "cve": f.get("cve", ""),
            "cvss": float(f.get("cvss", 0.0)),
            "epss": float(f.get("epss", 0.0)),
            "kev": bool(f.get("kev", False)),
            "attack_vector": f.get("attack_vector", "network"),
            "reachable_code": bool(f.get("reachable_code", False)),
            "package": f.get("package_name", ""),
            "version": f.get("package_version", ""),
            "scan_id": f.get("scan_id", ""),
            "summary": f.get("summary", ""),
            "tier": int(f.get("tier", 3)),
        })
        if len(rows) >= limit:
            break

    rows.sort(key=lambda r: (-r["cvss"], -r["epss"], r["finding_id"]))
    top = rows[0] if rows else None
    summary = (
        f"{len(rows)} open findings sorted by CVSS."
        + (
            f" Highest: {top['cve']} on {top['service_id']} at CVSS {top['cvss']}."
            if top
            else " Nothing open."
        )
        + " CVSS order says nothing about whether a path exists."
    )
    return envelope(
        summary=summary,
        data={"findings": rows},
        cypher=[],
        touched_ids=[str(r["finding_id"]) for r in rows] + [str(r["service_id"]) for r in rows],
        rows=len(rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def owner_of(
    node_id: Annotated[str, Field(description="Any estate node id: service, finding, package or data store.")],
) -> dict[str, Any]:
    """Route a node to the team that owns it and the people on call, through the graph."""
    started = time.perf_counter()
    proj = load_projection()

    if node_id not in proj.nodes:
        return error_envelope(f"No node with id '{node_id}'.", detail="unknown id", cypher=[])

    node = proj.nodes[node_id]
    label = node.get("label", "Unknown")

    service_id = node_id
    if label != "Service":
        # Try to find owning service
        if node_id.startswith("finding:"):
            # Finding -> service via finding data
            fid = node_id.replace("finding:", "")
            finding = proj.findings.get(fid)
            if finding:
                service_id = finding.get("service_id", node_id)
        elif "service_id" in node:
            service_id = node["service_id"]
        else:
            # Look for incoming edges from a service
            for pred in proj.graph.predecessors(node_id):
                if pred in proj.services:
                    service_id = pred
                    break

    # Team/on-call lookup (placeholder)
    team = None
    oncall = []
    if service_id in proj.services:
        svc = proj.services[service_id]
        team = {
            "team_id": svc.get("team_id", "unknown"),
            "team_name": svc.get("team_name", "unknown"),
            "slack_channel": svc.get("slack_channel", ""),
        }
        # oncall would come from people data

    oncall_rows = oncall
    data = {
        "node_id": node_id,
        "node_label": label,
        "service_id": service_id,
        "team": team,
        "on_call": oncall_rows,
        "members": [],
    }
    names = ", ".join(str(p.get("name", "")) for p in oncall_rows) or "nobody listed"
    summary = (
        f"{node_id} -> {service_id} owned by {team['team_name'] if team else 'no team'}"
        f" ({team['slack_channel'] if team else 'no channel'}); on call: {names}."
    )
    return envelope(
        summary=summary,
        data=data,
        cypher=[],
        touched_ids=[node_id, service_id]
        + ([str(team["team_id"])] if team else [])
        + [str(p.get("id", "")) for p in oncall_rows],
        rows=len(oncall_rows),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


DESCRIPTIONS = {
    "graph_overview": (
        "Shape of the whole estate: node and relationship counts, scan ids, public ingress points, "
        "crown-jewel data stores, and the live headline numbers (open findings, internet-reachable "
        "findings, findings on a crown-jewel path, attack-path count). Call this first to orient "
        "yourself. Do not use it to decide what to fix."
    ),
    "find_entities": (
        "Resolve free text (service name, repo, CVE id, package name) to graph node ids. Use it "
        "before any tool that needs an id. Not a risk tool."
    ),
    "get_service_context": (
        "One service in full: owning team, on-call people, ingress routes and their authn, protective "
        "controls, data stores and IAM roles it can reach, one-hop calls in and out, and open findings. "
        "Use it to confirm or refute a claim about a specific service."
    ),
    "list_open_findings": (
        "The scanner queue sorted by CVSS descending - the naive view this product exists to beat. "
        "Use it only for context or to show what a severity-first triage would pick. It carries no "
        "reachability information; prefer find_attack_paths and check_exploitability."
    ),
    "owner_of": (
        "Walk the graph from any estate node to the owning team, its Slack channel, its members and "
        "the people on call. Use it before proposing an action so the ticket is routed correctly."
    ),
}


def register(mcp: Any) -> None:
    mcp.tool(name="graph_overview", description=DESCRIPTIONS["graph_overview"])(graph_overview)
    mcp.tool(name="find_entities", description=DESCRIPTIONS["find_entities"])(find_entities)
    mcp.tool(name="get_service_context", description=DESCRIPTIONS["get_service_context"])(
        get_service_context
    )
    mcp.tool(name="list_open_findings", description=DESCRIPTIONS["list_open_findings"])(
        list_open_findings
    )
    mcp.tool(name="owner_of", description=DESCRIPTIONS["owner_of"])(owner_of)