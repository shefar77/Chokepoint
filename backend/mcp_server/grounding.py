"""Claim grounding check (PRD 9.5).

A verdict claim is grounded when its citations exist in the investigation,
every node it names was actually touched by a cited step, and every number it
states appears in a cited step's result. Nothing here trusts the model.
"""

from __future__ import annotations

from app.graph.grounding import ClaimReport, GroundingReport, check_claims

__all__ = [
    "ClaimReport",
    "GroundingReport",
    "check_claims",
]
