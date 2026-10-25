"""Graph builder, Graphify parsing, algorithms, solver isolation and persistence."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from app.services.graph_builder import SecurityGraphBuilder


# ----------------------------------------------------- Graphify artifact -----
def test_graphify_artifact_is_parsed_from_links_not_edges(db, graphify_artifact: Path) -> None:
    """Graphify writes networkx node-link JSON: edges live under "links"."""
    from app.repositories.graph import GraphRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p1", "graphed", str(graphify_artifact))
    ScanRepository.create("s1", "p1", source_ref=str(graphify_artifact), workspace_path=str(graphify_artifact))

    report = SecurityGraphBuilder.run_graphify(graphify_artifact, "s1")
    assert report["graphify_nodes"] == 3
    assert report["graphify_edges"] == 2
    assert report["graphify_schema_version"] == "1"

    edges = GraphRepository.load_edges("s1")
    relations = {e["relation"] for e in edges}
    # Code relations are namespaced so they cannot be mistaken for estate hops.
    assert "CODE_CALLS" in relations
    assert "CODE_CONTAINS" in relations


def test_graphify_node_label_is_a_type_not_a_display_string(db, graphify_artifact: Path) -> None:
    """Storing Graphify's `label` as the node type made every function its own type."""
    from app.repositories.graph import GraphRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p2", "graphed", str(graphify_artifact))
    ScanRepository.create("s2", "p2", source_ref=str(graphify_artifact), workspace_path=str(graphify_artifact))
    SecurityGraphBuilder.run_graphify(graphify_artifact, "s2")

    nodes = GraphRepository.load_nodes("s2")
    graphify_nodes = [n for n in nodes if n["properties"].get("source") == "graphify"]
    assert graphify_nodes
    labels = {n["label"] for n in graphify_nodes}
    assert labels <= {"Function", "File", "CodeEntity"}
    assert "login()" not in labels


def test_graphify_provenance_and_file_location_are_preserved(db, graphify_artifact: Path) -> None:
    from app.repositories.graph import GraphRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p3", "graphed", str(graphify_artifact))
    ScanRepository.create("s3", "p3", source_ref=str(graphify_artifact), workspace_path=str(graphify_artifact))
    SecurityGraphBuilder.run_graphify(graphify_artifact, "s3")

    nodes = {n["id"]: n for n in GraphRepository.load_nodes("s3")}
    login = nodes["auth_login"]
    assert login["properties"]["file_path"] == "auth.py"
    assert login["properties"]["line"] == "L1"
    assert login["properties"]["provenance"] == "ast"
    assert login["properties"]["display_label"] == "login()"

    edges = GraphRepository.load_edges("s3")
    calls = next(e for e in edges if e["relation"] == "CODE_CALLS")
    assert calls["properties"]["provenance"] == "EXTRACTED"


def test_missing_graphify_is_never_reported_as_completed(db, tmp_path: Path, monkeypatch) -> None:
    """PRD FR-02: a missing Graphify must be skipped, not shown as a success."""
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    repo = tmp_path / "plain"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"plain","dependencies":{}}', encoding="utf-8")
    ProjectRepository.create("p4", "plain", str(repo))
    ScanRepository.create("s4", "p4", source_ref=str(repo), workspace_path=str(repo))

    monkeypatch.setattr(SecurityGraphBuilder, "graphify_version", staticmethod(lambda: ""))
    report = SecurityGraphBuilder.run_graphify(repo, "s4")
    assert report["graphify_status"] == "skipped"
    assert report["graphify_nodes"] == 0
    assert "not found" in report["graphify_error"]
    # The built-in reader still contributed; it is counted separately.
    assert report["builtin_nodes"] == report["total_nodes"]


# -------------------------------------------------- estate-model honesty -----
def test_synthesised_estate_nodes_are_marked_inferred(db, vulnerable_repo: Path) -> None:
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p5", "vulnshop", str(vulnerable_repo))
    ScanRepository.create("s5", "p5", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo))
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "s5")

    for node in nodes:
        if node["label"] in {"Service", "Ingress", "DataStore", "Route"}:
            assert node["properties"]["provenance"] == "INFERRED"
            assert node["properties"]["source"] == "chokepoint_estate_model"
    for node in nodes:
        if node["label"] == "Package":
            assert node["properties"]["provenance"] == "EXTRACTED"

    for edge in edges:
        if edge["relation"] in {"REACHES", "ROUTES_TO", "READS_FROM"}:
            assert edge["properties"]["provenance"] == "INFERRED"
            assert "not observed at runtime" in edge["properties"]["evidence"]


def test_data_store_classification_and_records_are_not_invented(db, vulnerable_repo: Path) -> None:
    """PRD 12.2 forbids inventing a record count or a data classification."""
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p6", "vulnshop", str(vulnerable_repo))
    ScanRepository.create("s6", "p6", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo))
    nodes, _ = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "s6")

    stores = [n for n in nodes if n["label"] == "DataStore"]
    assert stores
    for store in stores:
        assert store["properties"]["classification"] == "unknown"
        assert store["properties"]["records"] is None
        assert "inferred" in store["properties"]["crown_jewel_basis"]


def test_repo_name_is_not_a_full_filesystem_path(db, vulnerable_repo: Path) -> None:
    """A Windows source_ref used to become the service node id verbatim."""
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository

    ProjectRepository.create("p7", "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        "s7", "p7", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo)
    )
    nodes, _ = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "s7")
    services = [n for n in nodes if n["label"] == "Service"]
    assert services
    for svc in services:
        assert "\\" not in svc["id"]
        assert "/" not in svc["id"]
        assert len(svc["id"]) < 80


# ----------------------------------------------------------- algorithms ------
def test_shortest_path_uses_the_graph_and_honours_rel_types() -> None:
    """The MCP tool passed rel_types where the graph belonged (TypeError)."""
    from mcp_server import algos

    G = nx.DiGraph()
    G.add_edge("internet", "ingress", relation="REACHES")
    G.add_edge("ingress", "svc", relation="ROUTES_TO")
    G.add_edge("svc", "store", relation="READS_FROM")

    found = algos.shortest_path("internet", "store", G)
    assert found.data["found"] is True
    assert found.data["hops"] == 3

    restricted = algos.shortest_path("internet", "store", G, ["REACHES", "ROUTES_TO"])
    assert restricted.data["found"] is False

    missing = algos.shortest_path("internet", "nope", G)
    assert missing.data["found"] is False


def test_betweenness_centrality_entry_point_exists() -> None:
    """rank_centrality called algos.betweenness, which never existed."""
    from mcp_server import algos

    assert hasattr(algos, "betweenness_centrality")
    G = nx.DiGraph([("a", "b"), ("b", "c")])
    result = algos.betweenness_centrality(None, G)
    assert result.engine == "networkx"
    assert result.data["scores"]["b"] > 0


def test_algorithms_handle_an_empty_graph() -> None:
    from mcp_server import algos

    empty = nx.DiGraph()
    assert algos.betweenness_centrality(None, empty).rows == 0
    assert algos.pagerank(None, empty).rows == 0
    assert algos.weakly_connected(empty).rows == 0
    assert algos.bfs_levels("x", 3, empty).rows == 0


# -------------------------------------------------- simulation isolation -----
def test_simulation_does_not_mutate_the_baseline(db, seeded_scan) -> None:
    """PRD: a simulation runs on an isolated copy and leaves the baseline intact."""
    from app.graph.attack import enumerate_attack_paths, total_weight
    from app.graph.projection import load_projection
    from app.graph.solver import find_chokepoints, fix_from_dict, simulate_fixes

    proj = load_projection(seeded_scan["scan_id"])
    before_nodes = proj.graph.number_of_nodes()
    before_edges = proj.graph.number_of_edges()
    before_paths = enumerate_attack_paths(proj, top_k=0)
    before_weight = total_weight(before_paths)

    solution = find_chokepoints(proj, max_fixes=3)
    if not solution.fixes:
        pytest.skip("no chokepoint candidate for this fixture")

    fix = fix_from_dict(solution.fixes[0], proj)
    assert fix is not None
    result = simulate_fixes(proj, [fix])

    assert proj.graph.number_of_nodes() == before_nodes
    assert proj.graph.number_of_edges() == before_edges
    assert total_weight(enumerate_attack_paths(proj, top_k=0)) == pytest.approx(before_weight)
    # the API rounds to 4 decimal places
    assert result["before"]["total_weight"] == pytest.approx(before_weight, abs=5e-5)
    assert result["after"]["total_weight"] <= result["before"]["total_weight"]


def test_chokepoint_selection_is_deterministic(db, seeded_scan) -> None:
    from app.graph.projection import load_projection
    from app.graph.solver import find_chokepoints

    proj = load_projection(seeded_scan["scan_id"])
    first = find_chokepoints(proj, max_fixes=3).as_dict()
    for _ in range(3):
        assert find_chokepoints(proj, max_fixes=3).as_dict() == first


# ------------------------------------------------------------- mapping -------
def test_finding_mapping_records_how_it_matched(db, seeded_scan) -> None:
    from app.repositories.mappings import MappingRepository

    for finding in seeded_scan["findings"]:
        mappings = MappingRepository.for_finding(finding["finding_id"])
        assert mappings, finding["finding_id"]
        for m in mappings:
            assert m["match_kind"] in {"direct", "inferred", "ambiguous", "unmatched"}
            assert m["evidence"]
