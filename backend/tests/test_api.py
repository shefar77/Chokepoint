"""API contract tests for every route the frontend consumes.

These run against the real FastAPI app with a temporary SQLite database. The MCP
server is not started, so routes that need it are checked for a graceful
response rather than for agent output.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(db):
    from app.main import app

    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------------ health ---
def test_health_reports_sqlite_and_does_not_claim_a_model_it_cannot_reach(client) -> None:
    body = client.get("/api/health").json()
    assert body["graph_ok"] is True
    assert body["configured_agent_mode"] == "scripted"
    # With AGENT_MODE=scripted the document must not advertise an LLM.
    assert body["agent_mode"] == "scripted"
    assert body["model"] == "deterministic"


def test_openapi_exposes_every_frontend_route(client) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    for route in [
        "/api/health",
        "/api/graph/overview",
        "/api/graph/findings",
        "/api/graph/subgraph",
        "/api/graph/focus",
        "/api/investigations",
        "/api/investigations/{investigation_id}",
        "/api/investigations/{investigation_id}/stream",
        "/api/verdicts/{verdict_id}/feedback",
        "/api/actions/{action_id}/approve",
        "/api/actions/{action_id}/reject",
        "/api/memory/lessons",
        "/api/evals/run",
        "/api/schema",
        "/api/cypher/readonly",
        "/api/mcp/tools",
        "/api/codebases/scan-url",
        "/api/codebases/scan-upload",
        "/api/codebases/scans",
    ]:
        assert route in paths, route


# ----------------------------------------------------------------- explorer --
def test_every_saved_explorer_query_runs(client) -> None:
    """Six of the seven shipped examples used to fail with HTTP 400."""
    examples = client.get("/api/schema").json()["examples"]
    assert examples
    failures = []
    for example in examples:
        res = client.post("/api/cypher/readonly", json={"query": example["query"]})
        if res.status_code != 200:
            failures.append((example["name"], res.json().get("detail")))
    assert not failures, failures


def test_explorer_schema_reports_real_labels(client, seeded_scan) -> None:
    body = client.get("/api/schema").json()
    assert body["labels"]
    assert any(entry["label"] == "Package" for entry in body["labels"])


def test_explorer_rejects_writes_and_multiple_statements(client) -> None:
    for bad in [
        "DELETE FROM findings",
        "UPDATE findings SET cvss = 0",
        "DROP TABLE findings",
        "SELECT 1; DELETE FROM findings",
        "PRAGMA table_info(findings)",
    ]:
        res = client.post("/api/cypher/readonly", json={"query": bad})
        assert res.status_code == 400, bad


# ------------------------------------------------------------------ overview --
def test_overview_returns_real_type_counts(client, seeded_scan) -> None:
    """nodes_by_label and relationships_by_type were hardcoded to {}."""
    body = client.get("/api/graph/overview").json()
    assert body["nodes_by_label"], "node type counts must not be empty"
    assert body["relationships_by_type"], "relationship type counts must not be empty"
    assert body["nodes_by_label"].get("Package", 0) > 0


def test_overview_ingress_authn_matches_the_graph(client, seeded_scan) -> None:
    """The board showed 'oidc' while scoring used 'none'."""
    body = client.get("/api/graph/overview").json()
    for ingress in body["public_ingress"]:
        assert ingress["authn"] != "oidc" or ingress["authn"] == "unknown"


def test_naive_view_shows_the_declared_version(client, seeded_scan) -> None:
    rows = client.get("/api/graph/findings?limit=20").json()["findings"]
    assert rows
    with_pkg = [r for r in rows if r["package"]]
    assert with_pkg
    assert any(r["version"] for r in with_pkg), "declared versions must reach the UI"


# ------------------------------------------------------------------ feedback --
def test_feedback_on_a_verdict_succeeds_and_teaches_a_lesson(client, db, seeded_scan) -> None:
    """This endpoint returned HTTP 500: wrong arity, awaited a sync function."""
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.verdicts import VerdictRepository

    InvestigationRepository.create(
        "INV-T1", scan_id=seeded_scan["scan_id"], project_id=seeded_scan["project_id"], goal="t"
    )
    finding_id = seeded_scan["findings"][0]["finding_id"]
    VerdictRepository.create(
        verdict_id="INV-T1-V01",
        investigation_id="INV-T1",
        finding_ids=[finding_id],
        kind="FIX_NOW",
        requested_kind="FIX_NOW",
        confidence=0.6,
        grounded=False,
        safety_valve_applied=False,
        safety_valve_reason="",
        claims=[{"id": "C1", "text": "on a modelled route", "cites": [], "node_ids": []}],
        evidence_path_ids=[],
    )

    res = client.post(
        "/api/verdicts/INV-T1-V01/feedback",
        json={"action": "override", "new_kind": "ACCEPT", "note": "sandbox only", "by": "tester"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["feedback_id"]
    assert body["lesson"] is not None, "an override must distil a lesson"
    assert body["lesson"]["scope_value"]

    lessons = client.get("/api/memory/lessons").json()["lessons"]
    assert any(item["id"] == body["lesson"]["lesson_id"] for item in lessons)
    recorded = next(item for item in lessons if item["id"] == body["lesson"]["lesson_id"])
    # The lesson must be linked back to the feedback that produced it.
    assert recorded["source_feedback"] is not None
    assert recorded["applies_to"], "a lesson must be attached to the nodes it applies to"


def test_feedback_agreement_records_no_lesson(client, db, seeded_scan) -> None:
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.verdicts import VerdictRepository

    InvestigationRepository.create(
        "INV-T2", scan_id=seeded_scan["scan_id"], project_id=seeded_scan["project_id"], goal="t"
    )
    VerdictRepository.create(
        verdict_id="INV-T2-V01",
        investigation_id="INV-T2",
        finding_ids=[seeded_scan["findings"][0]["finding_id"]],
        kind="SCHEDULE",
        requested_kind="SCHEDULE",
        confidence=0.4,
        grounded=False,
        safety_valve_applied=False,
        safety_valve_reason="",
        claims=[{"id": "C1", "text": "scheduled", "cites": [], "node_ids": []}],
        evidence_path_ids=[],
    )
    res = client.post(
        "/api/verdicts/INV-T2-V01/feedback", json={"action": "agree", "note": "", "by": "tester"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["lesson"] is None


def test_feedback_on_an_unknown_verdict_is_404(client, db) -> None:
    res = client.post("/api/verdicts/nope/feedback", json={"action": "agree", "note": "", "by": "t"})
    assert res.status_code == 404


# ------------------------------------------------------------------- actions --
def test_action_approve_and_reject_work(client, db, seeded_scan) -> None:
    """Both returned HTTP 500: an async reader was run through asyncio.to_thread."""
    from app.repositories.actions import ActionRepository
    from app.repositories.investigations import InvestigationRepository

    InvestigationRepository.create(
        "INV-T3", scan_id=seeded_scan["scan_id"], project_id=seeded_scan["project_id"], goal="t"
    )
    ActionRepository.create(
        action_id="INV-T3-A01",
        investigation_id="INV-T3",
        verdict_id="",
        kind="ticket",
        title="Upgrade lodash",
        body_md="body",
        team="unknown",
    )
    ActionRepository.create(
        action_id="INV-T3-A02",
        investigation_id="INV-T3",
        verdict_id="",
        kind="ticket",
        title="Upgrade pyyaml",
        body_md="body",
        team="unknown",
    )

    approved = client.post("/api/actions/INV-T3-A01/approve")
    assert approved.status_code == 200, approved.text
    assert approved.json()["action"]["status"] == "executed"

    rejected = client.post("/api/actions/INV-T3-A02/reject")
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["action"]["status"] == "rejected"

    assert client.post("/api/actions/nope/approve").status_code == 404


def test_approving_twice_is_a_conflict(client, db, seeded_scan) -> None:
    from app.repositories.actions import ActionRepository
    from app.repositories.investigations import InvestigationRepository

    InvestigationRepository.create(
        "INV-T4", scan_id=seeded_scan["scan_id"], project_id=seeded_scan["project_id"], goal="t"
    )
    ActionRepository.create(
        action_id="INV-T4-A01",
        investigation_id="INV-T4",
        verdict_id="",
        kind="ticket",
        title="t",
        body_md="b",
        team="unknown",
    )
    assert client.post("/api/actions/INV-T4-A01/approve").status_code == 200
    assert client.post("/api/actions/INV-T4-A01/approve").status_code == 409


# ------------------------------------------------------------------- intake --
@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/o/r",
        "https://github.com.evil.example/o/r",
        "https://gitea.attacker.example/o/r",
        "https://user:pw@github.com/o/r",
        "file:///etc/passwd",
        "https://github.com",
        "https://127.0.0.1/o/r",
    ],
)
def test_unsupported_git_urls_are_rejected(client, url: str) -> None:
    res = client.post("/api/codebases/scan-url", json={"url": url, "name": "x"})
    assert res.status_code == 400, f"{url} should be rejected"


def test_supported_git_host_passes_validation() -> None:
    from app.services.repository_intake import RepositoryIntakeService

    ok, why = RepositoryIntakeService.validate_url("https://github.com/OWASP/NodeGoat")
    assert ok, why


@pytest.mark.parametrize("path", ["/etc", "../../..", "C:\\Windows", "/"])
def test_scan_directory_rejects_paths_outside_the_codebase_root(client, path: str) -> None:
    """PRD 8.1: a public endpoint must not take arbitrary filesystem paths."""
    res = client.post("/api/codebases/scan-directory", json={"path": path, "name": "x"})
    assert res.status_code in (400, 404), res.text


def test_verdict_claims_reach_the_api(client, db, seeded_scan) -> None:
    """_verdict_model read a rationale_json column that never existed, so every
    verdict rendered with an empty headline and no claims."""
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.verdicts import VerdictRepository

    InvestigationRepository.create(
        "INV-T5", scan_id=seeded_scan["scan_id"], project_id=seeded_scan["project_id"], goal="t"
    )
    VerdictRepository.create(
        verdict_id="INV-T5-V01",
        investigation_id="INV-T5",
        finding_ids=[seeded_scan["findings"][0]["finding_id"]],
        kind="FIX_NOW",
        requested_kind="FIX_NOW",
        confidence=0.6,
        grounded=False,
        safety_valve_applied=False,
        safety_valve_reason="",
        claims=[{"id": "C1", "text": "lodash is on a modelled route", "cites": [], "node_ids": []}],
        evidence_path_ids=["AP-001"],
        grounding={"grounded": False, "claims": [{"claim_id": "C1", "grounded": False, "failures": ["no citation"]}]},
    )
    detail = client.get("/api/investigations/INV-T5").json()
    verdict = detail["verdicts"][0]
    assert verdict["claims"], "claims must reach the UI"
    assert verdict["claims"][0]["text"] == "lodash is on a modelled route"
    assert verdict["headline"]
    assert verdict["grounded"] is False
    assert verdict["claims"][0]["failures"] == ["no citation"]
