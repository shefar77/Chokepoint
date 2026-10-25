"""Deterministic exploitability and path scoring.

This is the only place where a risk number is created. It has no
database access and no I/O so that it can be reasoned about and tested
on plain data structures.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

CLASSIFICATION_WEIGHT: dict[str, float] = {
    "pci": 1.0,
    "secrets": 1.0,
    "pii": 0.85,
    "internal": 0.3,
    "public": 0.05,
    # Missing-data policy (PRD FR-07): an unknown classification is scored at
    # the "internal" weight and reported as a coverage gap. It is deliberately
    # not 0.0 -- unknown is not the same as harmless -- and not 1.0, which
    # would inflate every unlabelled store into a crown jewel.
    "unknown": 0.3,
}
UNKNOWN_CLASSIFICATION_WEIGHT = 0.3

EXPOSURE_BY_AUTHN: dict[str, float] = {"none": 1.0, "basic": 0.6, "oidc": 0.35}

LENGTH_BASE = 0.92
LENGTH_PIVOT = 3
LENGTH_FLOOR = 0.5
CONTROL_FACTOR = 0.5

# Missing-data policy for reachability (PRD FR-04 / 12.1). A finding whose
# reachability was never established stays a candidate -- unknown is not safe --
# but its exploitability is discounted by this documented factor so it cannot
# outrank a finding with real reachability evidence.
UNVERIFIED_REACHABILITY_FACTOR = 0.5
REACHABILITY_SUPPORTED = "supported"
REACHABILITY_NOT_ESTABLISHED = "not_established"
REACHABILITY_CONTRADICTED = "contradicted"
REACHABILITY_UNKNOWN = "unknown"


@dataclass(slots=True)
class ExploitCheck:
    """Result of exploitability evaluation for one finding."""

    finding_id: str
    service_id: str
    cve: str
    live: bool
    exploitability: float
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    blocking_controls: list[str] = field(default_factory=list)
    ingress_authn: str = ""
    reachability: str = REACHABILITY_NOT_ESTABLISHED
    reachability_verified: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "service_id": self.service_id,
            "cve": self.cve,
            # "candidate" is honest: the predicates that could be checked hold,
            # which is not the same as a proven exploit.
            "live_exploit": self.live,
            "exploitability": round(self.exploitability, 4),
            "reachability": self.reachability,
            "reachability_verified": self.reachability_verified,
            "checks": dict(self.checks),
            "reasons": list(self.reasons),
            "blocking_controls": list(self.blocking_controls),
            "ingress_authn": self.ingress_authn,
        }


@dataclass(slots=True)
class ScoreBreakdown:
    """The five multiplicands plus the product."""

    exploitability: float
    exposure: float
    impact: float
    length_penalty: float
    control_discount: float
    score: float
    coverage: dict[str, bool] = field(default_factory=dict)

    @property
    def coverage_pct(self) -> float:
        """Share of scoring inputs backed by observed data rather than a default."""
        if not self.coverage:
            return 0.0
        return round(100.0 * sum(1 for v in self.coverage.values() if v) / len(self.coverage), 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "exploitability": round(self.exploitability, 4),
            "exposure": round(self.exposure, 4),
            "impact": round(self.impact, 4),
            "length_penalty": round(self.length_penalty, 4),
            "control_discount": round(self.control_discount, 4),
            "score": round(self.score, 4),
            "coverage": dict(self.coverage),
            "coverage_pct": self.coverage_pct,
            "score_kind": "prioritisation heuristic, not a probability of exploitation",
        }


def exploitability_of(cvss: float, epss: float, kev: bool) -> float:
    """0.45*epss + 0.25*(cvss/10) + 0.30*kev."""
    epss = min(max(epss, 0.0), 1.0)
    cvss = min(max(cvss, 0.0), 10.0)
    return 0.45 * epss + 0.25 * (cvss / 10.0) + 0.30 * (1.0 if kev else 0.0)


def exposure_of(authn: str) -> float:
    return EXPOSURE_BY_AUTHN.get((authn or "none").lower(), 0.35)


def impact_of(classification: str, records: int | None) -> float:
    """0.6 * classification weight + 0.4 * log-scaled record count.

    An unknown record count contributes 0 to the scaled term rather than being
    invented; `score_path` reports that as a coverage gap so the number on screen
    can be read for what it is.
    """
    key = (classification or "unknown").lower()
    weight = CLASSIFICATION_WEIGHT.get(key, UNKNOWN_CLASSIFICATION_WEIGHT)
    scaled = min(1.0, math.log10(max(int(records or 0), 0) + 1) / 9.0)
    return 0.6 * weight + 0.4 * scaled


def length_penalty_of(hops: int) -> float:
    raw = LENGTH_BASE ** (hops - LENGTH_PIVOT)
    return min(1.0, max(LENGTH_FLOOR, raw))


def control_discount_of(mitigation_count: int) -> float:
    return CONTROL_FACTOR ** max(0, int(mitigation_count))


def score_path(
    *,
    exploitability: float,
    authn: str,
    classification: str,
    records: int | None,
    hops: int,
    mitigations: int,
    exploit_signal_observed: bool = True,
) -> ScoreBreakdown:
    exposure = exposure_of(authn)
    impact = impact_of(classification, records)
    length = length_penalty_of(hops)
    discount = control_discount_of(mitigations)
    coverage = {
        "exploit_signal": bool(exploit_signal_observed),
        "ingress_authn": bool(authn) and authn.lower() in EXPOSURE_BY_AUTHN,
        "data_classification": (classification or "unknown").lower() != "unknown",
        "record_count": records is not None,
        "hop_count": True,
    }
    return ScoreBreakdown(
        exploitability=exploitability,
        exposure=exposure,
        impact=impact,
        length_penalty=length,
        control_discount=discount,
        score=exploitability * exposure * impact * length * discount,
        coverage=coverage,
    )


def evaluate_finding(
    finding_id: str,
    service_id: str,
    cve: str,
    cvss: float,
    epss: float,
    kev: bool,
    attack_vector: str,
    requires_auth: bool,
    fixed_in: str,
    status: str,
    reachable_code: bool,
    service_status: str,
    ingress_authn: str | None,
    has_ingress_route: bool,
    blocking_controls: list[str],
    allow_adjacent: bool = False,
    reachability: str = "",
) -> ExploitCheck:
    """Evaluate one finding against the live-exploit predicates."""
    vector = (attack_vector or "network").lower()
    authn = (ingress_authn or "").lower()

    # Prefer the explicit three-state value; fall back to the legacy boolean.
    reach = (reachability or "").strip().lower()
    if reach not in {
        REACHABILITY_SUPPORTED,
        REACHABILITY_NOT_ESTABLISHED,
        REACHABILITY_CONTRADICTED,
        REACHABILITY_UNKNOWN,
    }:
        reach = REACHABILITY_SUPPORTED if reachable_code else REACHABILITY_NOT_ESTABLISHED
    verified = reach == REACHABILITY_SUPPORTED

    checks = {
        "finding_open": status == "open",
        "service_active": service_status == "active",
        "network_vector": vector == "network" or (allow_adjacent and vector == "adjacent"),
        "auth_satisfied": (not requires_auth) or authn == "none",
        # Only contradicted evidence rules a finding out. "not established"
        # must not be read as "unreachable" (PRD FR-04).
        "reachability_not_contradicted": reach != REACHABILITY_CONTRADICTED,
        "reachability_supported": verified,
        "no_blocking_control": not blocking_controls,
        "ingress_route_exists": has_ingress_route,
    }
    reasons: list[str] = []
    if not checks["finding_open"]:
        reasons.append(f"finding status is '{status}', not 'open'")
    if not checks["service_active"]:
        reasons.append(f"service {service_id} status is '{service_status}'")
    if not checks["network_vector"]:
        reasons.append(
            f"attack vector is '{vector}' and the service is not entered from a compromised neighbour"
        )
    if not checks["auth_satisfied"]:
        reasons.append(
            f"exploit requires authentication and the ingress authn is '{authn or 'n/a'}'"
        )
    if reach == REACHABILITY_CONTRADICTED:
        reasons.append("evidence contradicts the vulnerable code being reachable here")
    elif not verified:
        reasons.append(
            "reachability of the vulnerable code is not established: no scanner or "
            "code-graph evidence shows this service calling it, so the exploitability "
            f"signal is discounted by {UNVERIFIED_REACHABILITY_FACTOR:.0%} rather than "
            "assumed to be zero"
        )
    if not checks["no_blocking_control"]:
        reasons.append("active control blocks it: " + ", ".join(blocking_controls))
    if not checks["ingress_route_exists"]:
        reasons.append(f"no public ingress routes to {service_id}")

    live = all(
        (
            checks["finding_open"],
            checks["service_active"],
            checks["network_vector"],
            checks["auth_satisfied"],
            checks["reachability_not_contradicted"],
            checks["no_blocking_control"],
        )
    )
    if live and verified:
        reasons.append("all live-exploit predicates hold")
    elif live:
        reasons.append(
            "every predicate that could be checked holds, but reachability is unverified: "
            "this is a candidate, not a proven exploit"
        )

    raw = exploitability_of(cvss, epss, kev)
    if not live:
        score = 0.0
    elif verified:
        score = raw
    else:
        score = raw * UNVERIFIED_REACHABILITY_FACTOR

    return ExploitCheck(
        finding_id=finding_id,
        service_id=service_id,
        cve=cve,
        live=live,
        exploitability=score,
        checks=checks,
        reasons=reasons,
        blocking_controls=list(blocking_controls),
        ingress_authn=authn,
        reachability=reach,
        reachability_verified=verified,
    )
