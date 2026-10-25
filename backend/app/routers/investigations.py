"""Investigation lifecycle: list, start, read and stream."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.events import event_stream
from app.memory.lessons import feedback_for_verdict
from app.models import (
    ActionModel,
    AttackPathModel,
    ChallengeModel,
    ChokepointFix,
    ClaimModel,
    CreateInvestigationRequest,
    CreateInvestigationResponse,
    DiffSummary,
    HypothesisModel,
    InvestigationDetail,
    InvestigationSummary,
    MemoryBrief,
    MemoryHit,
    SimulationResult,
    SimulationSide,
    StepRecord,
    VerdictModel,
)
from app.orchestrator.runner import create_investigation, run_investigation
from app.repositories.investigations import InvestigationRepository
from app.repositories.steps import StepRepository
from app.repositories.blackboard import BlackboardRepository
from app.repositories.verdicts import VerdictRepository
from app.repositories.actions import ActionRepository
from app.repositories.messages import MessageRepository
from app.repositories.feedback import LessonRepository

router = APIRouter(tags=["investigations"])
log = logging.getLogger("chokepoint.investigations")


def _json(raw: Any, default: Any) -> Any:
    try:
        return json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return default


def _summary_from(row: dict[str, Any]) -> InvestigationSummary:
    kinds: dict[str, int] = {}
    verdicts = VerdictRepository.list_for_investigation(row["id"])
    for v in verdicts:
        kind = v.get("kind", "")
        if kind:
            kinds[kind] = kinds.get(kind, 0) + 1
    return InvestigationSummary(
        id=row["id"],
        goal=row.get("goal") or "",
        mode=row.get("mode") or "live",
        status=row.get("status") or "running",
        started_at=row.get("started_at") or "",
        ended_at=row.get("ended_at") or "",
        scan_id=row.get("scan_id") or "",
        model=row.get("model") or "",
        preset=row.get("preset") or "",
        steps=int(row.get("steps") or 0),
        verdict_kinds=kinds,
        duration_ms=float(row.get("duration_ms") or 0.0),
        error=row.get("error") or "",
    )


def _path_model(row: dict[str, Any]) -> AttackPathModel:
    nodes = row.get("nodes") or _json(row.get("nodes_json"), [])
    edges = row.get("edges") or _json(row.get("edges_json"), [])
    weights = row.get("components") or _json(row.get("weight_json"), {})
    score = float(row.get("score") or 0.0)
    return AttackPathModel(
        id=str(row.get("id", "")),
        score=score,
        score_pct=round(score * 100, 1),
        hops=int(row.get("hops") or 0),
        entry=str(row.get("entry") or ""),
        target=str(row.get("target") or ""),
        entry_ingress=str(row.get("entry_ingress") or ""),
        entry_authn=str(row.get("entry_authn") or ""),
        target_name=str(row.get("target_name") or ""),
        target_classification=str(row.get("target_classification") or ""),
        target_records=int(row.get("target_records") or 0),
        components=weights if isinstance(weights, dict) else {},
        nodes=[n for n in nodes if isinstance(n, dict)],
        edges=[e for e in edges if isinstance(e, dict)],
        live_exploits=[e for e in (row.get("live_exploits") or _json(row.get("exploits_json"), [])) if isinstance(e, dict)],
        mitigating_controls=[str(c) for c in (row.get("mitigating_controls") or _json(row.get("controls_json"), []))],
        reachability_verified=bool(row.get("reachability_verified")),
        evidence_note=str(row.get("evidence_note") or ""),
    )


def _verdict_model(row: dict[str, Any]) -> VerdictModel:
    # VerdictRepository already decodes the `claims` column into a list. Older
    # code looked for a `rationale_json` column that the schema never had, so
    # every verdict rendered with an empty headline and no claims.
    claim_rows = row.get("claims")
    if isinstance(claim_rows, str):
        claim_rows = _json(claim_rows, [])
    claim_rows = claim_rows or []
    grounding = _json(row.get("grounding_json"), {}) or {}
    valve = {"reason": str(row.get("safety_valve_reason") or "")}
    by_id = {
        str(c.get("claim_id")): c
        for c in (grounding.get("claims") or [])
        if isinstance(c, dict)
    }
    claims = []
    for claim in claim_rows:
        if not isinstance(claim, dict):
            continue
        report = by_id.get(str(claim.get("id")), {})
        claims.append(
            ClaimModel(
                id=str(claim.get("id") or ""),
                text=str(claim.get("text") or claim.get("rationale") or ""),
                cites=[str(c) for c in claim.get("cites") or []],
                node_ids=[str(n) for n in claim.get("node_ids") or []],
                grounded=bool(report.get("grounded", row.get("grounded", False))),
                failures=[str(f) for f in report.get("failures") or []],
            )
        )
    requested = str(row.get("requested_kind") or "")
    return VerdictModel(
        id=str(row["id"]),
        kind=str(row.get("kind") or "SCHEDULE"),
        requested_kind=requested if requested in ("FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS") else None,
        confidence=float(row.get("confidence") or 0.0),
        grounded=bool(row.get("grounded")),
        safety_valve=bool(row.get("safety_valve")),
        safety_valve_reason=str(valve.get("reason") or ""),
        created_at=str(row.get("created_at") or ""),
        headline=str(row.get("headline") or "") or (claims[0].text if claims else ""),
        finding_ids=[str(f) for f in row.get("finding_ids") or [] if f],
        services=[str(s) for s in row.get("services") or [] if s],
        claims=claims,
        evidence_path_ids=[str(p) for p in row.get("evidence_path_ids") or [] if p],
        feedback=feedback_for_verdict(str(row["id"])),
    )


def _detail(investigation_id: str) -> InvestigationDetail:
    inv = InvestigationRepository.get(investigation_id)
    if inv is None:
        raise KeyError(investigation_id)

    summary = _summary_from(inv)

    # Steps
    steps = [
        StepRecord(
            id=str(row["id"]),
            n=int(row.get("n") or 0),
            agent=str(row.get("agent") or "scout"),
            tool=str(row.get("tool") or ""),
            args=_json(row.get("args"), {}),
            cypher=[str(c) for c in _json(row.get("cypher"), [])],
            rows=int(row.get("rows") or 0),
            latency_ms=float(row.get("latency_ms") or 0.0),
            summary=str(row.get("summary") or ""),
            touched_ids=[str(t) for t in _json(row.get("touched_ids"), [])],
            engine=str(row.get("engine") or "networkx"),
            ok=bool(row.get("ok")),
            result=_json(row.get("result"), {}),
        )
        for row in StepRepository.list_for_investigation(investigation_id)
    ]

    # Attack paths - reconstructed from the investigation's snapshot
    path_rows = InvestigationRepository.get_paths_for_investigation(investigation_id)
    paths = [_path_model(row) for row in path_rows]

    # Hypotheses and challenges from blackboard
    board = BlackboardRepository.get_blackboard(investigation_id)
    hypotheses = [
        HypothesisModel(
            id=str(row["id"]),
            agent=str(row.get("agent") or "scout"),
            claim=str(row.get("claim") or ""),
            status=str(row.get("status") or "open"),
            confidence=float(row.get("confidence") or 0.0),
            about_ids=[str(a) for a in row.get("about_ids", []) if a],
            based_on_step_ids=[str(s) for s in row.get("based_on_step_ids", []) if s],
        )
        for row in board.get("hypotheses", [])
    ]
    challenges = [
        ChallengeModel(
            id=str(row["id"]),
            kind=str(row.get("kind") or ""),
            claim=str(row.get("claim") or ""),
            # An unresolved challenge is "open", not "rejected": collapsing the
            # two made every posted challenge read as dismissed.
            outcome=(
                str(row.get("outcome") or row.get("status") or "open")
                if str(row.get("outcome") or row.get("status") or "open")
                in ("upheld", "rejected", "supported", "falsified", "open")
                else "open"
            ),
            hypothesis_id=str(row.get("hypothesis_id") or ""),
            hypothesis_claim=str(row.get("hypothesis_claim") or ""),
            based_on_step_ids=[str(s) for s in row.get("based_on_step_ids", []) if s],
        )
        for row in board.get("challenges", [])
    ]

    # Verdicts
    verdicts = [_verdict_model(v) for v in VerdictRepository.list_for_investigation(investigation_id)]

    # Actions
    actions = [
        ActionModel(
            id=str(row["id"]),
            kind=str(row.get("kind") or "ticket"),
            status=str(row.get("status") or "proposed"),
            title=str(row.get("title") or ""),
            body_md=str(row.get("body_md") or ""),
            created_at=str(row.get("created_at") or ""),
            verdict_id=str(row.get("verdict_id") or ""),
            verdict_kind=str(row.get("verdict_kind") or ""),
            team=str(row.get("team") or ""),
            slack_channel=str(row.get("slack_channel") or ""),
            on_call=[str(p) for p in row.get("on_call", []) if p],
            finding_ids=[str(f) for f in row.get("finding_ids") or [] if f],
            outbox_path=str(row.get("outbox_path") or ""),
            delivery=[str(d) for d in row.get("delivery", [])],
        )
        for row in ActionRepository.list_for_investigation(investigation_id)
    ]

    # Lessons used
    lessons_used = [
        MemoryHit(
            lesson_id=str(row["lesson_id"]),
            text=str(row.get("text") or ""),
            effect=str(row.get("effect") or ""),
            scope_kind=str(row.get("scope_kind") or ""),
            scope_value=str(row.get("scope_value") or ""),
            strength=float(row.get("strength") or 0.0),
            uses=int(row.get("uses") or 0),
            why_retrieved="graph",
        )
        for row in MessageRepository.list_lessons_used(investigation_id)
    ]

    # Memory brief from investigation snapshot
    memory_raw = _json(inv.get("memory_json"), {})
    diff_raw = (memory_raw.get("diff") if isinstance(memory_raw, dict) else {}) or {}
    brief = MemoryBrief(
        subjects=[str(s) for s in (memory_raw.get("subjects") or [])],
        retrieval=str(memory_raw.get("retrieval") or "graph + keyword"),
        vector_search=bool(memory_raw.get("vector_search")),
        lessons=[
            MemoryHit(**{k: v for k, v in lesson.items() if k in MemoryHit.model_fields})
            for lesson in (memory_raw.get("lessons") or [])
            if isinstance(lesson, dict)
        ],
        past_verdicts=[v for v in (memory_raw.get("past_verdicts") or []) if isinstance(v, dict)],
        diff=DiffSummary(**{k: v for k, v in diff_raw.items() if k in DiffSummary.model_fields}),
        note=str(memory_raw.get("note") or ""),
    )

    # Chokepoints
    chokepoints = [
        ChokepointFix(**{k: v for k, v in fix.items() if k in ChokepointFix.model_fields})
        for fix in _json(inv.get("chokepoints_json"), [])
        if isinstance(fix, dict)
    ]

    # Simulation
    simulation_raw = _json(inv.get("simulation_json"), {})
    simulation: SimulationResult | None = None
    if isinstance(simulation_raw, dict) and simulation_raw.get("before"):
        delta = simulation_raw.get("delta") or {}
        simulation = SimulationResult(
            before=SimulationSide(
                **{
                    k: v
                    for k, v in (simulation_raw.get("before") or {}).items()
                    if k in SimulationSide.model_fields
                }
            ),
            after=SimulationSide(
                **{
                    k: v
                    for k, v in (simulation_raw.get("after") or {}).items()
                    if k in SimulationSide.model_fields
                }
            ),
            paths_removed=int(delta.get("paths_removed") or 0),
            weight_removed=float(delta.get("weight_removed") or 0.0),
            risk_removed_pct=float(delta.get("risk_removed_pct") or 0.0),
            crown_jewels_cut=[str(c) for c in delta.get("crown_jewels_cut") or []],
            fixes_applied=[f for f in simulation_raw.get("fixes_applied") or [] if isinstance(f, dict)],
        )

    # Agent messages from event log
    messages: list[dict[str, str]] = []
    for row in MessageRepository.list_for_investigation(investigation_id):
        text = str(row.get("text") or "")
        if text:
            messages.append({"agent": str(row.get("agent") or ""), "text": text})

    # Phase from investigation status
    phase = None
    if inv.get("status") == "running":
        # Could infer from the steps
        pass

    # Baseline weight from chokepoints
    baseline_weight = 0.0
    for fix in chokepoints:
        if fix.cumulative_risk_removed_pct > 0 and fix.risk_removed > 0:
            baseline_weight = round(fix.risk_removed / (fix.cumulative_risk_removed_pct / 100.0), 4)
            break

    return InvestigationDetail(
        summary=summary,
        phase=phase,
        steps=steps,
        paths=paths,
        hypotheses=hypotheses,
        challenges=challenges,
        verdicts=verdicts,
        actions=actions,
        memory_brief=brief,
        lessons_used=lessons_used,
        chokepoints=chokepoints,
        chokepoint_baseline_weight=baseline_weight,
        simulation=simulation,
        agent_messages=messages,
    )


@router.get("/investigations", response_model=list[InvestigationSummary])
async def list_investigations() -> list[InvestigationSummary]:
    rows = await asyncio.to_thread(lambda: InvestigationRepository.list_all())
    return [_summary_from(row) for row in rows]


@router.post("/investigations", response_model=CreateInvestigationResponse, status_code=201)
async def start_investigation(request: CreateInvestigationRequest) -> CreateInvestigationResponse:
    created = await asyncio.to_thread(create_investigation, request.goal, request.preset)
    task = asyncio.create_task(run_investigation(created["id"], request.goal, request.preset))
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
    return CreateInvestigationResponse(
        id=created["id"],
        status="running",
        mode=created["mode"],
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(investigation_id: str) -> InvestigationDetail:
    try:
        return await asyncio.to_thread(_detail, investigation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"no investigation {investigation_id}") from exc


@router.get("/investigations/{investigation_id}/stream")
async def stream(investigation_id: str) -> StreamingResponse:
    inv = await asyncio.to_thread(lambda: InvestigationRepository.get(investigation_id))
    if not inv:
        raise HTTPException(status_code=404, detail=f"no investigation {investigation_id}")
    status = inv.get("status", "running")
    return StreamingResponse(
        event_stream(investigation_id, is_finished=status in ("done", "failed")),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


_BACKGROUND: set[asyncio.Task[None]] = set()