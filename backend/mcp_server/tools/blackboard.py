"""Blackboard tools (PRD 8.4).

Agents never read each other's text. They post to the graph and read the graph
back, which is what makes the graph the shared context.

All database operations use SQLite via repositories - no FalkorDB Cypher queries.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import Field

from app.repositories.blackboard import BlackboardRepository
from app.repositories.steps import StepRepository
from app.repositories.verdicts import VerdictRepository
from app.repositories.messages import MessageRepository
from app.graph.projection import load_projection
from app.graph.attack import Modifications
from app.graph import envelope, error_envelope
from . import require_role

log = logging.getLogger("chokepoint.tools.blackboard")

CHALLENGE_KINDS = (
    "control_present",
    "edge_dead",
    "service_inactive",
    "auth_required",
    "unreachable_code",
    "prior_lesson",
)


def _known_steps(investigation_id: str, step_ids: list[str]) -> list[str]:
    return StepRepository.get_existing_step_ids(investigation_id, step_ids)


def post_hypothesis(
    role: Annotated[str, Field(description="Calling agent role; must be 'scout'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    claim: Annotated[str, Field(description="One falsifiable, concrete sentence.")],
    about_ids: Annotated[
        list[str], Field(description="Nodes or findings this claim is about.")
    ] = [],
    based_on_step_ids: Annotated[
        list[str], Field(description="Step ids supporting this claim.")
    ] = [],
    confidence: Annotated[float, Field(ge=0.0, le=1.0, description="Your confidence, 0 to 1.")] = 0.8,
) -> dict[str, Any]:
    """Write a falsifiable claim to the blackboard so the Skeptic can attack it."""
    started = time.perf_counter()
    require_role(role, "post_hypothesis")

    if not claim.strip():
        return error_envelope("post_hypothesis refused", detail="claim must not be empty")

    about = [a for a in dict.fromkeys(about_ids) if a][:20]
    known = _known_steps(investigation_id, [s for s in dict.fromkeys(based_on_step_ids) if s])
    unknown = [s for s in dict.fromkeys(based_on_step_ids) if s not in known]

    try:
        count = BlackboardRepository.next_hypothesis_number(investigation_id)
        hid = f"{investigation_id}-H{count}"
        BlackboardRepository.create_hypothesis(
            investigation_id=investigation_id,
            hypothesis_id=hid,
            agent=role,
            claim=claim.strip(),
            confidence=confidence,
            about_ids=about,
            based_on_step_ids=known,
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("post_hypothesis failed", detail=str(exc))

    data = {
        "hypothesis_id": hid,
        "status": "open",
        "about_ids_linked": len(about),
        "based_on_step_ids": known,
        "ignored_step_ids": unknown,
        "claim": claim.strip(),
        "confidence": round(float(confidence), 2),
    }
    summary = f"Hypothesis {hid} posted (confidence {round(float(confidence), 2)}), citing {len(known)} step(s)."
    if unknown:
        summary += f" {len(unknown)} cited step id(s) did not exist and were dropped."
    return envelope(
        summary=summary,
        data=data,
        cypher=[],
        touched_ids=[hid, *about],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def post_challenge(
    role: Annotated[str, Field(description="Calling agent role; must be 'skeptic'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    hypothesis_id: Annotated[str, Field(description="Hypothesis id to challenge.")],
    kind: Annotated[str, Field(description="Challenge kind (e.g. control_present, edge_dead).")],
    claim: Annotated[str, Field(description="The challenge claim.")],
    based_on_step_ids: Annotated[
        list[str], Field(description="Step ids supporting this challenge.")
    ] = [],
    outcome: Annotated[str, Field(description="Challenge outcome ('upheld' or 'rejected').")] = "open",
) -> dict[str, Any]:
    """Challenge an existing hypothesis on the blackboard with evidence."""
    started = time.perf_counter()
    require_role(role, "post_challenge")

    if not claim.strip():
        return error_envelope("post_challenge refused", detail="claim must not be empty")

    cid = f"{investigation_id}-C{BlackboardRepository.next_challenge_number(investigation_id)}"
    known = _known_steps(investigation_id, [s for s in dict.fromkeys(based_on_step_ids) if s])

    try:
        res = BlackboardRepository.create_challenge(
            investigation_id=investigation_id,
            challenge_id=cid,
            hypothesis_id=hypothesis_id,
            kind=kind,
            claim=claim.strip(),
            outcome=outcome,
            based_on_step_ids=known,
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("post_challenge failed", detail=str(exc))

    data = {
        "challenge_id": cid,
        "hypothesis_id": hypothesis_id,
        "kind": kind,
        "outcome": outcome,
        "claim": claim.strip(),
        "based_on_step_ids": known,
        "hypothesis_status": (res or {}).get("hypothesis_status", "open"),
    }
    return envelope(
        summary=f"Challenge {cid} on {hypothesis_id} posted ({outcome}).",
        data=data,
        cypher=[],
        touched_ids=[cid, hypothesis_id],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def list_blackboard(
    investigation_id: Annotated[str, Field(description="The investigation id.")],
) -> dict[str, Any]:
    """Read back all hypotheses, challenges, steps, and verdicts on the blackboard."""
    started = time.perf_counter()
    data = BlackboardRepository.get_blackboard(investigation_id)
    return envelope(
        summary=(
            f"Blackboard {investigation_id}: {data['counts']['hypotheses']} hypotheses "
            f"({data['counts']['open_hypotheses']} open), {data['counts']['challenges']} challenges "
            f"({data['counts']['upheld_challenges']} upheld), {data['counts']['verdicts']} verdicts."
        ),
        data=data,
        cypher=[],
        touched_ids=[h["id"] for h in data["hypotheses"]] + [c["id"] for c in data["challenges"]],
        rows=data["counts"]["hypotheses"] + data["counts"]["challenges"],
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def register(mcp: Any) -> None:
    mcp.tool(name="post_hypothesis", description="Write a falsifiable claim to the blackboard so the Skeptic can attack it.")(
        post_hypothesis
    )
    mcp.tool(name="post_challenge", description="Challenge an existing hypothesis on the blackboard with evidence.")(
        post_challenge
    )
    mcp.tool(name="list_blackboard", description="Read back all hypotheses, challenges, steps, and verdicts on the blackboard.")(
        list_blackboard
    )
