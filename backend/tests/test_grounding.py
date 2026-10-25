"""The grounding check must reject fabricated claims and accept supported ones."""

from __future__ import annotations

import pytest

from app.graph.grounding import check_claims


@pytest.fixture()
def investigation(db):
    """One investigation with a single step whose result holds known numbers."""
    from app.repositories.investigations import InvestigationRepository
    from app.repositories.steps import StepRepository

    InvestigationRepository.create("INV-G1", goal="grounding")
    StepRepository.create(
        step_id="INV-G1-S1",
        investigation_id="INV-G1",
        n=1,
        agent="scout",
        tool="list_open_findings",
        args={},
        cypher=[],
        rows=2,
        latency_ms=1.0,
        summary="2 open findings; highest CVSS 9.8 on jsonwebtoken",
        touched_ids=["pkg-jsonwebtoken@8.5.1", "vulnshop"],
        engine="networkx",
        ok=True,
        result={"findings": [{"cve": "CVE-2022-23529", "cvss": 9.8}], "count": 2},
    )
    return "INV-G1"


def test_a_claim_with_no_citation_is_not_grounded(investigation) -> None:
    report = check_claims(investigation, [{"id": "C1", "text": "lodash is exploitable"}])
    assert report.grounded is False
    assert "no citation" in report.claims[0].failures[0]


def test_a_claim_citing_a_foreign_step_is_not_grounded(investigation) -> None:
    report = check_claims(
        investigation,
        [{"id": "C1", "text": "something", "cites": ["INV-OTHER-S9"]}],
    )
    assert report.grounded is False
    assert "does not belong to investigation" in report.claims[0].failures[0]


def test_an_invented_number_is_not_grounded(investigation) -> None:
    """The headline defence: the model cannot make up a figure."""
    report = check_claims(
        investigation,
        [
            {
                "id": "C1",
                "text": "This removes 73.4% of the weighted path risk",
                "cites": ["INV-G1-S1"],
            }
        ],
    )
    assert report.grounded is False
    assert any("73.4" in f for f in report.claims[0].failures)


def test_a_number_from_a_cited_step_is_grounded(investigation) -> None:
    report = check_claims(
        investigation,
        [{"id": "C1", "text": "The highest CVSS is 9.8", "cites": ["INV-G1-S1"]}],
    )
    assert report.grounded is True, report.claims[0].failures


def test_a_node_not_touched_by_a_cited_step_is_not_grounded(investigation) -> None:
    report = check_claims(
        investigation,
        [
            {
                "id": "C1",
                "text": "payments-vault is reachable",
                "cites": ["INV-G1-S1"],
                "node_ids": ["payments-vault"],
            }
        ],
    )
    assert report.grounded is False
    assert "not in the touched_ids" in report.claims[0].failures[0]


def test_a_touched_node_is_grounded(investigation) -> None:
    report = check_claims(
        investigation,
        [
            {
                "id": "C1",
                "text": "the service is affected",
                "cites": ["INV-G1-S1"],
                "node_ids": ["vulnshop"],
            }
        ],
    )
    assert report.grounded is True, report.claims[0].failures


@pytest.mark.parametrize(
    "identifier",
    ["CVE-2022-23529", "CWE-798", "GHSA-wh77-3x4m-4q9g", "CVE-2020-14343"],
)
def test_identifier_digits_are_not_treated_as_numeric_claims(investigation, identifier: str) -> None:
    """Every CVE-citing verdict used to fail on the digits inside the id."""
    report = check_claims(
        investigation,
        [{"id": "C1", "text": f"{identifier} affects this package", "cites": ["INV-G1-S1"]}],
    )
    assert report.grounded is True, report.claims[0].failures


def test_an_empty_claim_list_is_not_grounded(investigation) -> None:
    """No claims means nothing was substantiated, so it cannot pass."""
    report = check_claims(investigation, [])
    assert report.grounded is False


def test_the_report_counts_every_claim_it_examined(investigation) -> None:
    report = check_claims(
        investigation,
        [
            {"id": "C1", "text": "CVSS 9.8", "cites": ["INV-G1-S1"]},
            {"id": "C2", "text": "removes 99.9%", "cites": ["INV-G1-S1"]},
        ],
    )
    data = report.as_dict()
    assert data["claim_count"] == 2
    assert data["grounded_claim_count"] == 1
    assert data["grounded"] is False
