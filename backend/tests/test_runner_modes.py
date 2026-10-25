"""Agent-mode honesty: provider selection, labelling and degraded fallback.

PRD FR-11 forbids labelling a deterministic run as LLM-driven, and PRD FR-08
requires a traceable failure event plus a safe degraded result when a provider
fails. These run with no model provider reachable.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.orchestrator.runner import InvestigationRunner, create_investigation


@pytest.fixture()
def scan(db, vulnerable_repo: Path):
    from app.repositories.findings import FindingRepository
    from app.repositories.graph import GraphRepository
    from app.repositories.projects import ProjectRepository
    from app.repositories.scans import ScanRepository
    from app.services.graph_builder import SecurityGraphBuilder
    from app.services.scanner_orchestrator import ScannerOrchestrator

    ProjectRepository.create("pm", "vulnshop", str(vulnerable_repo))
    ScanRepository.create(
        "sm", "pm", source_ref=str(vulnerable_repo), workspace_path=str(vulnerable_repo)
    )
    nodes, edges = SecurityGraphBuilder.extract_codebase_ast(vulnerable_repo, "sm")
    GraphRepository.bulk_insert_nodes(nodes)
    GraphRepository.bulk_insert_edges(edges)
    findings, _ = ScannerOrchestrator.run_manifest_scanner(vulnerable_repo, "sm")
    FindingRepository.bulk_insert(findings)
    SecurityGraphBuilder.map_findings_to_graph("sm")
    ScanRepository.mark_completed("sm")
    return "sm"


def test_new_investigation_does_not_claim_a_mode_yet(db) -> None:
    created = create_investigation("Triage")
    assert created["mode"] == "pending"


def test_scripted_mode_is_named_deterministic_not_live(db, scan) -> None:
    runner = InvestigationRunner(create_investigation("Triage")["id"], "Triage")
    provider, model, reason = asyncio.run(runner._select_provider())
    assert provider is None
    assert model == "deterministic"
    assert "deterministic" in reason.lower()
    assert "no model reasoning" in reason.lower()


def test_run_records_the_mode_it_actually_used(db, scan) -> None:
    from app.repositories.investigations import InvestigationRepository

    inv_id = create_investigation("Triage")["id"]
    runner = InvestigationRunner(inv_id, "Triage")
    asyncio.run(runner.run())

    row = InvestigationRepository.get(inv_id)
    assert row["status"] == "done"
    assert row["mode"] == "deterministic", "a run with no provider must not be labelled live"
    assert row["model"] == "deterministic"


def test_degraded_fallback_runs_when_the_model_produces_nothing(db, scan, monkeypatch) -> None:
    """A provider that returns nothing must not yield an empty "done" run."""
    from app.repositories.blackboard import BlackboardRepository
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.verdicts import VerdictRepository

    class SilentProvider:
        """Stands in for a model that times out on every turn."""

        name = "silent"

        async def run_agent(self, **kwargs):
            from app.orchestrator.providers.base import AgentResult

            return AgentResult(text="", tool_calls=0, stopped_because="llm_error")

        async def close(self):
            return None

    inv_id = create_investigation("Triage")["id"]
    runner = InvestigationRunner(inv_id, "Triage")
    monkeypatch.setattr(
        runner,
        "_select_provider",
        lambda: _ready((SilentProvider(), "fake-model", "Running with fake-model.")),
    )

    asyncio.run(runner.run())

    row = InvestigationRepository.get(inv_id)
    assert row["status"] == "done"
    # The run is relabelled: it must not stay "live" after the model failed.
    assert row["mode"] == "deterministic (LLM failed)"
    assert runner.degraded is True

    # And it produced real output instead of an empty investigation.
    assert BlackboardRepository.get_blackboard(inv_id)["hypotheses"]
    assert VerdictRepository.list_for_investigation(inv_id)


async def _ready(value):
    return value


def test_deterministic_run_fills_every_dossier_section(db, scan) -> None:
    """chokepoints used to receive attack paths, and the simulation was never run."""
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.simulations import SimulationRepository

    inv_id = create_investigation("Triage")["id"]
    runner = InvestigationRunner(inv_id, "Triage")
    asyncio.run(runner.run())

    import json

    row = InvestigationRepository.get(inv_id)
    chokepoints = json.loads(row["chokepoints_json"] or "[]")
    assert chokepoints, "the solver output must be stored"
    # Chokepoint rows are fixes, not attack paths.
    assert all("kind" in fix and "cost" in fix for fix in chokepoints)
    assert not any("hops" in fix for fix in chokepoints)

    simulation = json.loads(row["simulation_json"] or "{}")
    assert simulation.get("before"), "one remediation must be simulated (PRD 7.1 item 9)"
    assert simulation.get("after")
    assert simulation.get("assumptions"), "the simulation must state its assumptions"
    assert SimulationRepository.list_for_investigation(inv_id)
