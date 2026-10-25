"""Deterministic exploitability and path scoring (PRD 7.2 and 7.3).

This module is the only place where a risk number is created. It has no
database access and no I/O so that it can be reasoned about and tested on
plain data structures.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

CLASSIFICATION_WEIGHT: dict[str, float] = {
    "pci": 1.0,
    "secrets": 1.0,
    "pii": 0.85,
    "internal": 0.3,
    "public": 0.05,
}

EXPOSURE_BY_AUTHN: dict[str, float] = {"none": 1.0, "basic": 0.6, "oidc": 0.35}

LENGTH_BASE = 0.92
LENGTH_PIVOT = 3
LENGTH_FLOOR = 0.5
CONTROL_FACTOR = 0.5


@dataclass(slots=True)
class VulnFacts:
    """The vulnerability properties scoring depends on."""

    cve: str
    cvss: float
    epss: float
    kev: bool
    attack_vector: str
    requires_auth: bool
    fixed_in: str = ""
    summary: str = ""


@dataclass(slots=True)
class FindingFacts:
    """A finding joined to its service, package and vulnerability."""

    finding_id: str
    service_id: str
    status: str
    reachable_code: bool
    scan_id: str
    package_id: str
    package_name: str
    package_version: str
    vuln: VulnFacts


@dataclass(slots=True)
class ExploitCheck:
    """Result of PRD 7.2 for one finding, with the reason for every negative."""

    finding_id: str
    service_id: str
    cve: str
    live: bool
    exploitability: float
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    blocking_controls: list[str] = field(default_factory=list)
    ingress_authn: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "service_id": self.service_id,
            "cve": self.cve,
            "live_exploit": self.live,
            "exploitability": round(self.exploitability, 4),
            "checks": dict(self.checks),
            "reasons": list(self.reasons),
            "blocking_controls": list(self.blocking_controls),
            "ingress_authn": self.ingress_authn,
        }


@dataclass(slots=True)
class ScoreBreakdown:
    """The five multiplicands of PRD 7.3 plus the product."""

    exploitability: float
    exposure: float
    impact: float
    length_penalty: float
    control_discount: float
    score: float

    def as_dict(self) -> dict[str, float]:
        return {
            "exploitability": round(self.exploitability, 4),
            "exposure": round(self.exposure, 4),
            "impact": round(self.impact, 4),
            "length_penalty": round(self.length_penalty, 4),
            "control_discount": round(self.control_discount, 4),
            "score": round(self.score, 4),
        }


def exploitability_of(vuln: VulnFacts) -> float:
    """0.45*epss + 0.25*(cvss/10) + 0.30*kev."""
    epss = min(max(vuln.epss, 0.0), 1.0)
    cvss = min(max(vuln.cvss, 0.0), 10.0)
    return 0.45 * epss + 0.25 * (cvss / 10.0) + 0.30 * (1.0 if vuln.kev else 0.0)


def exposure_of(authn: str) -> float:
    return EXPOSURE_BY_AUTHN.get((authn or "none").lower(), 0.35)


def impact_of(classification: str, records: int) -> float:
    """0.6 * classification weight + 0.4 * log-scaled record count."""
    weight = CLASSIFICATION_WEIGHT.get((classification or "internal").lower(), 0.3)
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
    records: int,
    hops: int,
    mitigations: int,
) -> ScoreBreakdown:
    exposure = exposure_of(authn)
    impact = impact_of(classification, records)
    length = length_penalty_of(hops)
    discount = control_discount_of(mitigations)
    return ScoreBreakdown(
        exploitability=exploitability,
        exposure=exposure,
        impact=impact,
        length_penalty=length,
        control_discount=discount,
        score=exploitability * exposure * impact * length * discount,
    )


def evaluate_finding(
    finding: FindingFacts,
    *,
    service_status: str,
    ingress_authn: str | None,
    has_ingress_route: bool,
    blocking_controls: list[str],
    allow_adjacent: bool = False,
) -> ExploitCheck:
    """PRD 7.2 with an explicit reason for every failed predicate.

    ``allow_adjacent`` is set when the service is entered from an already
    compromised neighbour, which makes an ``adjacent`` attack vector usable.
    """
    vuln = finding.vuln
    vector = (vuln.attack_vector or "network").lower()
    authn = (ingress_authn or "").lower()

    checks = {
        "finding_open": finding.status == "open",
        "service_active": service_status == "active",
        "network_vector": vector == "network" or (allow_adjacent and vector == "adjacent"),
        "auth_satisfied": (not vuln.requires_auth) or authn == "none",
        "reachable_code": bool(finding.reachable_code),
        "no_blocking_control": not blocking_controls,
        "ingress_route_exists": has_ingress_route,
    }
    reasons: list[str] = []
    if not checks["finding_open"]:
        reasons.append(f"finding status is '{finding.status}', not 'open'")
    if not checks["service_active"]:
        reasons.append(f"service {finding.service_id} status is '{service_status}'")
    if not checks["network_vector"]:
        reasons.append(f"attack vector is '{vector}' and the service is not entered from a compromised neighbour")
    if not checks["auth_satisfied"]:
        reasons.append(
            f"exploit requires authentication and the ingress authn is '{authn or 'n/a'}'"
        )
    if not checks["reachable_code"]:
        reasons.append("scanner reports the vulnerable function is not called by this service")
    if not checks["no_blocking_control"]:
        reasons.append("active control blocks it: " + ", ".join(blocking_controls))
    if not checks["ingress_route_exists"]:
        reasons.append(f"no public ingress routes to {finding.service_id}")

    live = all(
        (
            checks["finding_open"],
            checks["service_active"],
            checks["network_vector"],
            checks["auth_satisfied"],
            checks["reachable_code"],
            checks["no_blocking_control"],
        )
    )
    if live:
        reasons.append("all live-exploit predicates hold")
    return ExploitCheck(
        finding_id=finding.finding_id,
        service_id=finding.service_id,
        cve=vuln.cve,
        live=live,
        exploitability=exploitability_of(vuln) if live else 0.0,
        checks=checks,
        reasons=reasons,
        blocking_controls=list(blocking_controls),
        ingress_authn=authn,
    )
