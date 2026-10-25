"""Verdict, action and lesson writes (PRD 8.5).

All database operations use SQLite via repositories - no FalkorDB Cypher queries.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.repositories.verdicts import VerdictRepository
from app.repositories.actions import ActionRepository
from app.repositories.findings import FindingRepository
from app.repositories.messages import MessageRepository
from app.repositories.blackboard import BlackboardRepository
from app.repositories.lessons import LessonRepository
from app.graph.projection import load_projection
from app.graph.grounding import check_claims
from app.graph.attack import enumerate_attack_paths, live_exploits, Modifications
from app.graph import envelope, error_envelope
from app.memory.embeddings import embedder
from . import require_role

log = logging.getLogger("chokepoint.tools.actions")

VERDICT_KINDS = ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS")
DOWNGRADED = ("ACCEPT", "SUPPRESS")


class Claim(BaseModel):
    """One sentence of a verdict rationale, with its citations."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Short claim id, for example 'C1'.")
    text: str = Field(description="One short, concrete sentence in plain language.")
    cites: list[str] = Field(default_factory=list, description="Step ids from this investigation.")
    node_ids: list[str] = Field(
        default_factory=list, description="Graph node ids this claim names; each must be touched by a cited step."
    )


def _finding_services(finding_ids: list[str]) -> dict[str, str]:
    if not finding_ids:
        return {}
    proj = load_projection()
    res = {}
    for fid in finding_ids:
        f = proj.findings.get(fid, {})
        res[fid] = f.get("service_id") or f.get("source_symbol") or ""
    return res


def _safety_valve(
    finding_ids: list[str], kind: str, claims: list[Claim]
) -> tuple[str, dict[str, Any]]:
    """Lessons may not downgrade a live exploit that reaches a crown jewel (PRD 10)."""
    if kind not in DOWNGRADED:
        return kind, {"applied": False, "reason": "verdict is not a downgrade"}
    proj = load_projection()
    paths = enumerate_attack_paths(proj, top_k=0)
    on_path_services = {s for p in paths for s in p.services}
    lateral = live_exploits(proj, Modifications(), as_entry=False)
    cited_nodes = {n for claim in claims for n in claim.node_ids}

    blocked: list[dict[str, Any]] = []
    for finding_id in finding_ids:
        facts = proj.findings.get(finding_id, {})
        service_id = facts.get("service_id") or facts.get("source_symbol") or ""
        if service_id not in on_path_services:
            continue
        if not any(c.finding_id == finding_id for c in lateral.get(service_id, [])):
            continue
        lessons = LessonRepository.get_by_graph_proximity([service_id])
        covering = [str(row["lesson_id"]) for row in lessons if str(row["lesson_id"]) in cited_nodes]
        if covering:
            continue
        targets = sorted({p.target for p in paths if service_id in p.services})
        blocked.append(
            {
                "finding_id": finding_id,
                "service_id": service_id,
                "crown_jewels_reached": targets,
                "lessons_scoping_this_service": [str(row["lesson_id"]) for row in lessons],
            }
        )
    if not blocked:
        return kind, {"applied": False, "reason": "no live exploit with a crown-jewel path in this group"}
    return "FIX_NOW", {
        "applied": True,
        "reason": (
            "a live exploit in this group reaches a crown jewel and no cited lesson scopes the "
            "affected service, so the verdict was raised to FIX_NOW"
        ),
        "blocked": blocked,
    }


def record_verdict(
    role: Annotated[str, Field(description="Calling agent role; must be 'scribe'.")],
    investigation_id: Annotated[str, Field(description="Current investigation id.")],
    finding_ids: Annotated[list[str], Field(description="Findings this verdict covers.")],
    kind: Annotated[
        Literal["FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS"], Field(description="The decision.")
    ],
    confidence: Annotated[float, Field(ge=0.0, le=1.0, description="Confidence, 0 to 1.")],
    claims: Annotated[list[Claim], Field(description="Every rationale sentence with its citations.")],
) -> dict[str, Any]:
    """Adjudicate a finding group. Runs the grounding check and the lesson safety valve."""
    started = time.perf_counter()
    require_role(role, "record_verdict")

    if not finding_ids:
        return error_envelope("record_verdict refused", detail="finding_ids must not be empty")
    if not claims:
        return error_envelope("record_verdict refused", detail="a verdict needs at least one claim")

    try:
        claim_dicts = [c.model_dump() for c in claims]
        report = check_claims(investigation_id, claim_dicts)
        final_kind, valve = _safety_valve(list(finding_ids), kind, list(claims))

        count = VerdictRepository.next_number(investigation_id)
        vid = f"{investigation_id}-V{count}"

        evidence: list[str] = []
        proj = load_projection()
        paths = enumerate_attack_paths(proj, top_k=0)
        wanted = set(finding_ids)
        for p in paths:
            # Match on the findings the path actually carries, not on service ids.
            if any(f in wanted for f in p.finding_ids()):
                evidence.append(p.id)

        VerdictRepository.create(
            verdict_id=vid,
            investigation_id=investigation_id,
            finding_ids=list(finding_ids),
            kind=final_kind,
            requested_kind=kind,
            confidence=confidence,
            grounded=bool(report.grounded),
            safety_valve_applied=bool(valve.get("applied")),
            safety_valve_reason=str(valve.get("reason", "")),
            claims=claim_dicts,
            evidence_path_ids=evidence,
            grounding=report.as_dict(),
        )
    except Exception as exc:  # noqa: BLE001
        return error_envelope("record_verdict failed", detail=str(exc))

    services = _finding_services(list(finding_ids))
    data = {
        "verdict_id": vid,
        "kind": final_kind,
        "requested_kind": kind,
        "confidence": round(float(confidence), 2),
        "grounded": bool(report.grounded),
        "grounding": report.as_dict(),
        "safety_valve": valve,
        "findings_linked": len(finding_ids),
        "evidence_path_ids": evidence,
        "services": sorted(set(services.values())),
        "headline": claims[0].text,
    }
    summary = f"Verdict {vid}: {final_kind} on {len(finding_ids)} finding(s), "
    summary += "all claims grounded." if report.grounded else (
        f"{len(report.failures)} claim(s) failed the grounding check: "
        + "; ".join(f["failures"][0] for f in report.failures if f["failures"])[:300]
    )
    if valve.get("applied"):
        summary += " Safety valve raised the verdict to FIX_NOW: lesson considered, not applied."
    return envelope(
        summary=summary,
        data=data,
        cypher=[],
        touched_ids=[vid, *finding_ids, *sorted(set(services.values())), *evidence],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def propose_action(
    role: Annotated[str, Field(description="Calling agent role; must be 'scribe'.")],
    verdict_id: Annotated[str, Field(description="Verdict id this action implements.")],
    kind: Annotated[
        Literal["ticket", "suppress", "virtual_patch_request"], Field(description="Action kind.")
    ],
    title: Annotated[str, Field(description="Action title.")],
    body_md: Annotated[str, Field(description="Action body in markdown.")],
    team: Annotated[str, Field(description="Owning team name or id.")] = "",
    slack_channel: Annotated[str, Field(description="Slack channel to post to.")] = "",
    on_call: Annotated[list[str], Field(description="On-call handles.")] = [],
    finding_ids: Annotated[list[str], Field(description="Findings covered.")] = [],
) -> dict[str, Any]:
    """Propose a concrete remediation action based on an adjudicated verdict."""
    started = time.perf_counter()
    require_role(role, "propose_action")
    verdict = VerdictRepository.get(verdict_id)
    if verdict is None:
        # Falling back to a placeholder investigation id produced a raw
        # IntegrityError from two foreign keys instead of a usable message.
        return error_envelope(
            "propose_action refused",
            detail=(
                f"no verdict {verdict_id!r}; record_verdict must succeed before an "
                "action can be proposed for it"
            ),
        )
    inv_id = str(verdict.get("investigation_id") or "")
    num = ActionRepository.next_number(inv_id)
    aid = f"{inv_id}-A{num}"
    ActionRepository.create(
        action_id=aid,
        investigation_id=inv_id,
        verdict_id=verdict_id,
        kind=kind,
        title=title,
        body_md=body_md,
        team=team or "",
        slack_channel=slack_channel or "",
        on_call=list(on_call or []),
        finding_ids=list(finding_ids or (verdict.get("finding_ids", []) if verdict else [])),
    )
    data = {
        "action_id": aid,
        "verdict_id": verdict_id,
        "kind": kind,
        "title": title,
        "status": "proposed",
    }
    return envelope(
        summary=f"Action {aid} proposed ({kind}): '{title}'.",
        data=data,
        cypher=[],
        touched_ids=[aid, verdict_id],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def record_lesson(
    text: Annotated[str, Field(description="The lesson statement in plain language.")],
    scope_kind: Annotated[str, Field(description="Scope kind, e.g. 'service', 'package', 'cve'.")],
    scope_value: Annotated[str, Field(description="The scope identifier, e.g. service id or CVE.")],
    effect: Annotated[str, Field(description="Effect on future verdicts, e.g. 'SUPPRESS', 'ACCEPT'.")],
    strength: Annotated[float, Field(ge=0.0, le=1.0, description="Strength of the lesson, 0.0 to 1.0.")] = 0.8,
    applies_to: Annotated[list[str] | None, Field(description="Node ids this applies to.")] = None,
    role: Annotated[str, Field(description="Calling agent role; must be 'backend'.")] = "backend",
) -> dict[str, Any]:
    """Persist a lesson distilled from analyst feedback or investigation findings."""
    started = time.perf_counter()
    require_role(role, "record_lesson")
    num = LessonRepository.next_number()
    lid = f"L-{num:04d}"
    emb = None
    try:
        vec = embedder().embed(text)
        if vec:
            import struct
            emb = struct.pack(f"{len(vec)}f", *vec)
    except Exception:
        pass
    LessonRepository.create(
        lesson_id=lid,
        text=text,
        scope_kind=scope_kind,
        scope_value=scope_value,
        effect=effect,
        strength=strength,
        embedding=emb,
        applies_to=applies_to or [scope_value],
    )
    data = {
        "lesson_id": lid,
        "text": text,
        "scope_kind": scope_kind,
        "scope_value": scope_value,
        "effect": effect,
        "strength": strength,
    }
    return envelope(
        summary=f"Lesson {lid} recorded: '{text}' (scope {scope_kind}:{scope_value}).",
        data=data,
        cypher=[],
        touched_ids=[lid, *(applies_to or [scope_value])],
        rows=1,
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def register(mcp: Any) -> None:
    mcp.tool(name="record_verdict", description="Record a final verdict on one or more findings with cited claims.")(
        record_verdict
    )
    mcp.tool(name="propose_action", description="Propose a concrete remediation action (ticket, PR, control).")(
        propose_action
    )
    mcp.tool(name="record_lesson", description="Persist a lesson distilled from analyst feedback or investigation findings.")(
        record_lesson
    )
