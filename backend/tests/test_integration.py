"""End-to-end: fixture repo -> graph -> findings -> mapping -> investigation -> simulation.

The MCP server is not required: the deterministic pipeline is exercised through
the in-process tool functions, and an MCP-dependent step is reported as a failed
step rather than being skipped silently.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from mcp_server.tools import RoleError, allowed, catalog, require_role, tools_for_role


# ------------------------------------------------------- MCP role control ----
def test_catalog_exposes_twenty_one_tools() -> None:
    assert len(catalog()) == 21


def test_each_role_sees_only_its_own_tools() -> None:
    assert "post_hypothesis" in tools_for_role("scout")
    assert "post_hypothesis" not in tools_for_role("skeptic")
    assert "post_challenge" in tools_for_role("skeptic")
    assert "record_verdict" in tools_for_role("scribe")
    assert "record_verdict" not in tools_for_role("scout")
    assert "record_lesson" in tools_for_role("backend")
    for role in ("scout", "skeptic", "scribe"):
        assert "record_lesson" not in tools_for_role(role)


@pytest.mark.parametrize(
    "role,tool",
    [
        ("scout", "record_verdict"),
        ("skeptic", "post_hypothesis"),
        ("scribe", "record_lesson"),
        ("scout", "post_challenge"),
        ("memory", "find_attack_paths"),
    ],
)
def test_server_side_role_check_refuses(role: str, tool: str) -> None:
    """PRD: the server enforces permissions regardless of what a prompt claims."""
    assert allowed(role, tool) is False
    with pytest.raises(RoleError):
        require_role(role, tool)


def test_unknown_role_is_refused() -> None:
    with pytest.raises(RoleError):
        require_role("administrator", "record_verdict")


# ------------------------------------------------------------- MCP tools -----
def test_rank_centrality_runs(db, seeded_scan) -> None:
    """It called algos.betweenness, which does not exist -> always "failed"."""
    from mcp_server.tools.analysis import rank_centrality

    for scope in ("attack_paths", "services"):
        for algorithm in ("betweenness", "pagerank"):
            result = rank_centrality(scope=scope, algorithm=algorithm)
            assert "failed" not in result.get("summary", ""), result
            assert result.get("data", {}).get("algorithm") == algorithm


def test_shortest_path_tool_runs_and_proves_absence(db, seeded_scan) -> None:
    """It passed rel_types where the graph belonged -> TypeError every time."""
    from app.graph.projection import load_projection
    from mcp_server.tools.analysis import shortest_path

    proj = load_projection(seeded_scan["scan_id"])
    store = next(iter(proj.stores))

    found = shortest_path(from_id="internet", to_id=store)
    assert "failed" not in found.get("summary", ""), found
    assert found["data"]["found"] is True

    absent = shortest_path(from_id="internet", to_id="no-such-node")
    assert "failed" not in absent.get("summary", "")
    assert absent["data"]["found"] is False


def test_record_lesson_tool_persists(db) -> None:
    """It raised "FOREIGN KEY constraint failed" on every call."""
    from mcp_server.tools.actions import record_lesson
    from mcp_server.tools.memory import recall

    result = record_lesson(
        text="pyyaml findings in sandbox code are accepted",
        scope_kind="package",
        scope_value="pyyaml",
        effect="downgrade",
        role="backend",
    )
    assert "error" not in result, result
    assert result["data"]["lesson_id"].startswith("L-")

    back = recall(query_text="pyyaml", subject_ids=["pyyaml"], limit=5)
    assert back["data"]["lessons"], back
    assert any(item["text"].startswith("pyyaml findings") for item in back["data"]["lessons"])


def test_simulate_fix_runs_on_a_copy_and_reports_assumptions(db, seeded_scan) -> None:
    from app.graph.projection import load_projection
    from app.graph.solver import find_chokepoints
    from mcp_server.tools.analysis import simulate_fix

    proj = load_projection(seeded_scan["scan_id"])
    fixes = find_chokepoints(proj, max_fixes=2).fixes
    if not fixes:
        pytest.fail("the fixture should yield at least one chokepoint candidate")

    result = simulate_fix(fixes=[fixes[0]])
    assert "error" not in result, result
    data = result["data"]
    assert data["before"]["paths"] >= data["after"]["paths"]
    assert data["delta"]["risk_removed_pct"] >= 0.0


# -------------------------------------------------------- full pipeline ------
def test_full_pipeline_produces_grounded_output(db, vulnerable_repo: Path) -> None:
    """Repo -> graph -> findings -> mapping -> deterministic investigation."""
    from app.graph.projection import load_projection
    from app.orchestrator.runner import InvestigationRunner, create_investigation
    from app.repositories.blackboard import BlackboardRepository
    from app.repositories.findings import FindingRepository
    from app.repositories.graph import GraphRepository
    from app.repositories.messages import MessageRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.repositories.verdicts import VerdictRepository
    from app.services.graph_builder import SecurityGraphBuilder
    from app.services.scanner_orchestrator import ScannerOrchestrator

    ProjectRepository.create("pp", "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        "ss", "pp", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo)
    )
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "ss")
    GraphRepository.bulk_insert_nodes(nodes)
    GraphRepository.bulk_insert_edges(edges)
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "ss")
    FindingRepository.bulk_insert(findings)
    SecurityGraphBuilder.map_findings_to_graph("ss")
    ScanRepository.mark_completed("ss")

    proj = load_projection("ss")
    assert proj.findings, "the fixture must produce findings"
    assert proj.services and proj.stores

    created = create_investigation("Triage the latest scan")
    # A fresh investigation must not claim to be LLM-driven before a provider
    # has been health-checked.
    assert created["mode"] == "pending"

    runner = InvestigationRunner(created["id"], "Triage the latest scan")
    asyncio.run(runner._run_dynamic_graph_loop())

    board = BlackboardRepository.get_blackboard(created["id"])
    assert board["hypotheses"], "the Scout must post a hypothesis"
    assert board["challenges"], "the Skeptic must post a challenge"

    verdicts = VerdictRepository.list_for_investigation(created["id"])
    assert verdicts, "the Scribe must record verdicts"
    assert len(verdicts) == len(proj.findings)

    # Narration must be persisted, not only streamed.
    messages = MessageRepository.list_for_investigation(created["id"])
    assert messages, "agent narration must survive a reload"
    assert {m["agent"] for m in messages} >= {"memory", "scout", "skeptic", "scribe"}


def test_pipeline_claims_nothing_it_did_not_observe(db, vulnerable_repo: Path) -> None:
    """The old narration asserted an AST call graph and mTLS that never existed."""
    from app.orchestrator.runner import InvestigationRunner, create_investigation
    from app.repositories.findings import FindingRepository
    from app.repositories.graph import GraphRepository
    from app.repositories.messages import MessageRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.services.graph_builder import SecurityGraphBuilder
    from app.services.scanner_orchestrator import ScannerOrchestrator

    ProjectRepository.create("pq", "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        "sq", "pq", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo)
    )
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "sq")
    GraphRepository.bulk_insert_nodes(nodes)
    GraphRepository.bulk_insert_edges(edges)
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "sq")
    FindingRepository.bulk_insert(findings)
    SecurityGraphBuilder.map_findings_to_graph("sq")
    ScanRepository.mark_completed("sq")

    created = create_investigation("Triage the latest scan")
    runner = InvestigationRunner(created["id"], "Triage the latest scan")
    asyncio.run(runner._run_dynamic_graph_loop())

    prose = " ".join(m["text"] for m in MessageRepository.list_for_investigation(created["id"]))
    for fabricated in [
        "confirms direct imports and invocations",
        "unmitigated by mutual TLS",
        "confirmed exploitability",
        "Skeptic challenge verified",
    ]:
        assert fabricated not in prose, f"narration must not assert {fabricated!r}"
    assert "not established" in prose or "not proven" in prose


def test_verdicts_are_not_blanket_grounded(db, vulnerable_repo: Path) -> None:
    """grounded=True used to be hardcoded for every verdict."""
    from app.orchestrator.runner import InvestigationRunner, create_investigation
    from app.repositories.findings import FindingRepository
    from app.repositories.graph import GraphRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.repositories.verdicts import VerdictRepository
    from app.services.graph_builder import SecurityGraphBuilder
    from app.services.scanner_orchestrator import ScannerOrchestrator

    ProjectRepository.create("pr", "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        "sr", "pr", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo)
    )
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "sr")
    GraphRepository.bulk_insert_nodes(nodes)
    GraphRepository.bulk_insert_edges(edges)
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "sr")
    FindingRepository.bulk_insert(findings)
    SecurityGraphBuilder.map_findings_to_graph("sr")
    ScanRepository.mark_completed("sr")

    created = create_investigation("Triage the latest scan")
    runner = InvestigationRunner(created["id"], "Triage the latest scan")
    asyncio.run(runner._run_dynamic_graph_loop())

    verdicts = VerdictRepository.list_for_investigation(created["id"])
    assert verdicts
    for verdict in verdicts:
        grounding = json.loads(verdict.get("grounding_json") or "{}")
        # The check actually ran: the report names each claim it examined.
        assert grounding.get("claim_count") == len(verdict["claims"])


def test_repeat_runs_are_reproducible(db, seeded_scan) -> None:
    """PRD 15.3 item 10: three repeat runs with the same deterministic output."""
    from app.graph.attack import enumerate_attack_paths, total_weight
    from app.graph.projection import load_projection
    from app.graph.solver import find_chokepoints

    signatures = []
    for _ in range(3):
        proj = load_projection(seeded_scan["scan_id"])
        paths = enumerate_attack_paths(proj, top_k=0)
        signatures.append(
            {
                "paths": len(paths),
                "weight": round(total_weight(paths), 6),
                "ids": [p.id for p in paths],
                "scores": [round(p.breakdown.score, 6) for p in paths],
                "fixes": [f["label"] for f in find_chokepoints(proj, max_fixes=3).fixes],
            }
        )
    assert signatures[0] == signatures[1] == signatures[2], signatures
