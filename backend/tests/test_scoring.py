"""Deterministic scoring: boundaries, missing data, coverage, reproducibility."""

from __future__ import annotations

import pytest

from app.graph.scoring import (
    UNKNOWN_CLASSIFICATION_WEIGHT,
    control_discount_of,
    evaluate_finding,
    exploitability_of,
    exposure_of,
    impact_of,
    length_penalty_of,
    score_path,
)


# ------------------------------------------------------------- components ----
def test_exploitability_formula() -> None:
    assert exploitability_of(10.0, 1.0, True) == pytest.approx(0.45 + 0.25 + 0.30)
    assert exploitability_of(0.0, 0.0, False) == 0.0


def test_exploitability_clamps_out_of_range_inputs() -> None:
    assert exploitability_of(99.0, 5.0, True) == pytest.approx(1.0)
    assert exploitability_of(-5.0, -1.0, False) == 0.0


def test_exposure_defaults_for_unknown_authn() -> None:
    assert exposure_of("none") == 1.0
    assert exposure_of("basic") == 0.6
    assert exposure_of("oidc") == 0.35
    assert exposure_of("something-else") == 0.35
    assert exposure_of("") == 1.0  # empty is treated as "none"


def test_unknown_classification_uses_the_documented_default() -> None:
    """Unknown must be neither 0 (harmless) nor 1 (crown jewel)."""
    assert impact_of("unknown", None) == pytest.approx(0.6 * UNKNOWN_CLASSIFICATION_WEIGHT)
    assert 0.0 < impact_of("unknown", None) < impact_of("pci", 10**9)


def test_missing_record_count_is_not_invented() -> None:
    assert impact_of("pii", None) == impact_of("pii", 0)
    assert impact_of("pii", 10**9) > impact_of("pii", None)


def test_length_penalty_is_bounded() -> None:
    assert length_penalty_of(1) == 1.0
    assert length_penalty_of(3) == 1.0
    assert length_penalty_of(200) == 0.5
    assert 0.5 <= length_penalty_of(7) <= 1.0


def test_control_discount_halves_per_control() -> None:
    assert control_discount_of(0) == 1.0
    assert control_discount_of(1) == 0.5
    assert control_discount_of(3) == 0.125
    assert control_discount_of(-2) == 1.0


# --------------------------------------------------------------- coverage ----
def test_score_reports_coverage_for_missing_inputs() -> None:
    breakdown = score_path(
        exploitability=0.5,
        authn="none",
        classification="unknown",
        records=None,
        hops=3,
        mitigations=0,
    )
    assert breakdown.coverage["data_classification"] is False
    assert breakdown.coverage["record_count"] is False
    assert breakdown.coverage["ingress_authn"] is True
    assert breakdown.coverage_pct < 100.0
    assert "heuristic" in breakdown.as_dict()["score_kind"]


def test_full_coverage_when_every_input_is_observed() -> None:
    breakdown = score_path(
        exploitability=0.5,
        authn="oidc",
        classification="pci",
        records=50_000,
        hops=4,
        mitigations=0,
    )
    assert breakdown.coverage_pct == 100.0


def test_score_is_the_product_of_its_components() -> None:
    b = score_path(
        exploitability=0.8, authn="none", classification="pci", records=1000, hops=3, mitigations=1
    )
    assert b.score == pytest.approx(
        b.exploitability * b.exposure * b.impact * b.length_penalty * b.control_discount
    )


def test_scoring_is_reproducible() -> None:
    kwargs = dict(
        exploitability=0.42, authn="basic", classification="pii", records=777, hops=5, mitigations=1
    )
    first = score_path(**kwargs).as_dict()
    for _ in range(20):
        assert score_path(**kwargs).as_dict() == first


# ------------------------------------------------------ live-exploit gate ----
def _check(**overrides):
    base = dict(
        finding_id="F1",
        service_id="svc",
        cve="CVE-1",
        cvss=9.0,
        epss=0.5,
        kev=False,
        attack_vector="network",
        requires_auth=False,
        fixed_in="2.0",
        status="open",
        reachable_code=True,
        service_status="active",
        ingress_authn="none",
        has_ingress_route=True,
        blocking_controls=[],
    )
    base.update(overrides)
    return evaluate_finding(**base)


def test_all_predicates_satisfied_is_live() -> None:
    check = _check()
    assert check.live is True
    assert check.exploitability > 0.0


@pytest.mark.parametrize(
    "override",
    [
        {"status": "resolved"},
        {"service_status": "decommissioned"},
        {"attack_vector": "local"},
        {"blocking_controls": ["waf"]},
        {"reachability": "contradicted"},
    ],
)
def test_any_failed_predicate_removes_live_status(override: dict) -> None:
    check = _check(**override)
    assert check.live is False
    assert check.exploitability == 0.0
    assert check.reasons


def test_unestablished_reachability_stays_a_candidate() -> None:
    """PRD FR-04: 'not established' must never be treated as 'unreachable'."""
    check = _check(reachable_code=False, reachability="not_established")
    assert check.live is True, "unknown is not safe"
    assert check.reachability_verified is False
    assert 0.0 < check.exploitability < _check().exploitability
    reason = " ".join(check.reasons)
    assert "not established" in reason


def test_contradicted_reachability_is_fatal() -> None:
    check = _check(reachability="contradicted")
    assert check.live is False
    assert check.exploitability == 0.0
    assert "contradicts" in " ".join(check.reasons)


def test_unverified_reachability_is_discounted_by_the_documented_factor() -> None:
    from app.graph.scoring import UNVERIFIED_REACHABILITY_FACTOR

    verified = _check(reachability="supported")
    unverified = _check(reachability="not_established")
    assert unverified.exploitability == pytest.approx(
        verified.exploitability * UNVERIFIED_REACHABILITY_FACTOR
    )


def test_adjacent_vector_only_counts_after_lateral_movement() -> None:
    assert _check(attack_vector="adjacent", allow_adjacent=False).live is False
    assert _check(attack_vector="adjacent", allow_adjacent=True).live is True


def test_auth_required_blocks_unless_ingress_is_open() -> None:
    assert _check(requires_auth=True, ingress_authn="oidc").live is False
    assert _check(requires_auth=True, ingress_authn="none").live is True
