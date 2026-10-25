"""Claim grounding check.

Validates that every claim in a verdict cites steps that exist, every node
it names was touched by a cited step, and every number appears in a cited
step's result. Nothing here trusts the model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.db import query_one

NUMBER_RE = re.compile(r"\d+(?:[, ]\d{3})*(?:\.\d+)?")

# Digits that belong to an identifier are not numeric claims. Without this
# mask, every verdict citing "CVE-2022-23529" failed the check on "2022"
# and "23529", which appear in no tool result by construction.
IDENTIFIER_RE = re.compile(
    r"\b(?:CVE|CWE|GHSA|CAPEC|OSV|RHSA|DSA|ALAS|SNYK|PYSEC|INV|AP)[-_][0-9A-Za-z][0-9A-Za-z._-]*",
    re.IGNORECASE,
)

STEP_QUERY = """
SELECT id, n, touched_ids, result, summary, tool
FROM steps
WHERE investigation_id = ?
ORDER BY n
"""


@dataclass(slots=True)
class ClaimReport:
    claim_id: str
    ok: bool
    failures: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"claim_id": self.claim_id, "grounded": self.ok, "failures": list(self.failures)}


@dataclass(slots=True)
class GroundingReport:
    grounded: bool
    claims: list[ClaimReport] = field(default_factory=list)
    cypher: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[dict[str, Any]]:
        return [c.as_dict() for c in self.claims if not c.ok]

    def as_dict(self) -> dict[str, Any]:
        return {
            "grounded": self.grounded,
            "claims": [c.as_dict() for c in self.claims],
            "grounded_claim_count": sum(1 for c in self.claims if c.ok),
            "claim_count": len(self.claims),
        }


def _numbers(text: str) -> list[float]:
    out: list[float] = []
    for raw in NUMBER_RE.findall(text or ""):
        cleaned = raw.replace(",", "").replace(" ", "")
        try:
            out.append(float(cleaned))
        except ValueError:
            continue
    return out


def _decimals(raw: str) -> int:
    return len(raw.split(".")[1]) if "." in raw else 0


def _number_supported(raw: str, value: float, evidence: list[float]) -> bool:
    places = _decimals(raw)
    tolerance = max(0.5 * (10 ** -places), abs(value) * 0.005)
    for candidate in evidence:
        if round(candidate, places) == round(value, places):
            return True
        if abs(candidate - value) <= tolerance:
            return True
        if abs(candidate * 100.0 - value) <= max(0.5, abs(value) * 0.01):
            return True
    return False


def load_steps(investigation_id: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    rows = query_one(STEP_QUERY, (investigation_id,), many=True) or []
    steps: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            touched = json.loads(str(row.get("touched_ids") or "[]"))
        except json.JSONDecodeError:
            touched = []
        steps[str(row["id"])] = {
            "id": str(row["id"]),
            "n": int(row.get("n") or 0),
            "tool": str(row.get("tool") or ""),
            "touched": [str(t) for t in touched],
            "result": str(row.get("result") or ""),
            "summary": str(row.get("summary") or ""),
        }
    return steps, [STEP_QUERY]


def check_claims(
    investigation_id: str, claims: list[dict[str, Any]]
) -> GroundingReport:
    """Validate every claim against the steps recorded for this investigation."""
    steps, cypher = load_steps(investigation_id)
    reports: list[ClaimReport] = []

    for index, claim in enumerate(claims, start=1):
        claim_id = str(claim.get("id") or f"C{index}")
        text = str(claim.get("text") or "")
        cites = [str(c) for c in (claim.get("cites") or [])]
        node_ids = [str(n) for n in (claim.get("node_ids") or [])]
        failures: list[str] = []

        if not cites:
            failures.append("claim has no citation; every claim must cite at least one step")
        known = [c for c in cites if c in steps]
        for missing in [c for c in cites if c not in steps]:
            failures.append(f"cited step {missing} does not belong to investigation {investigation_id}")

        touched: set[str] = set()
        evidence_text_parts: list[str] = []
        for step_id in known:
            step = steps[step_id]
            touched |= set(step["touched"])
            evidence_text_parts.append(step["result"])
            evidence_text_parts.append(step["summary"])
        evidence_text = "\n".join(evidence_text_parts)
        evidence_numbers = _numbers(evidence_text)

        for node_id in node_ids:
            if node_id not in touched:
                failures.append(
                    f"node {node_id} is not in the touched_ids of any cited step"
                )

        if known:
            # Mask identifiers before extracting numbers from the claim text.
            masked = IDENTIFIER_RE.sub(" ", text)
            for raw in NUMBER_RE.findall(masked):
                cleaned = raw.replace(",", "").replace(" ", "")
                try:
                    value = float(cleaned)
                except ValueError:
                    continue
                if node_ids and any(raw in nid for nid in node_ids):
                    continue
                if not _number_supported(cleaned, value, evidence_numbers):
                    failures.append(
                        f"number {raw} does not appear in the result of any cited step"
                    )

        reports.append(ClaimReport(claim_id=claim_id, ok=not failures, failures=failures))

    return GroundingReport(
        grounded=all(c.ok for c in reports) and bool(reports),
        claims=reports,
        cypher=cypher,
    )