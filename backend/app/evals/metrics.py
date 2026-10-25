"""Evaluation against the planted ground truth (PRD 13).

Ground truth lives on disk, never in the graph. Both baselines and the agent
column are ranked with the same deterministic scoring the tools use, so the
comparison is apples to apples.

The evaluation uses the SecurityProjection from the new graph layer and
the deterministic scoring from app.graph.scoring, not FalkorDB queries.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import settings
from app.db import query_one
from app.graph.projection import load_projection
from app.graph.solver import find_chokepoints as solve_chokepoints
from app.graph.scoring import (
    evaluate_finding,
    score_path,
    ExploitCheck,
    ScoreBreakdown,
    exploitability_of,
)
from app.graph.attack import enumerate_attack_paths, live_exploits, Modifications, total_weight
from app.repositories.findings import FindingRepository
from app.models import (
    ChokepointFix,
    EvalResponse,
    EvalRow,
    MethodMetrics,
)

log = logging.getLogger("chokepoint.evals")

TOP_N = 10
RECALL_AT = 20
COVERAGE_TARGET = 0.90
BASELINE_FIX_CAP = 30
ROW_CAP = 140

CAPTION = (
    "Ground truth is planted in a synthetic estate and read from seed/ground_truth.json, which is "
    "never written into the graph. Both baselines rank the same open findings with the same data the "
    "agent sees; only the ordering differs."
)


def _latest_verdicts(investigation_id: str) -> dict[str, str]:
    """Read verdicts for an investigation from the investigation snapshot."""
    row = query_one(
        "SELECT snapshot_json FROM investigations WHERE id = ?",
        (investigation_id,),
    )
    if not row or not row["snapshot_json"]:
        return {}
    try:
        snapshot = json.loads(row["snapshot_json"])
    except json.JSONDecodeError:
        return {}
    # The snapshot stores verdicts as a flat dict of finding_id -> kind
    # But we need to reconstruct from the investigation's stored data
    # For now, read from the verdicts table via repositories
    from app.repositories.verdicts import VerdictRepository
    verdicts = VerdictRepository.list_for_investigation(investigation_id)
    res: dict[str, str] = {}
    for v in verdicts:
        for fid in v.get("finding_ids", []):
            res[str(fid)] = v.get("kind", "")
    return res


def _grounded_rate(investigation_id: str) -> float | None:
    """Share of verdict claims that passed the grounding check.

    This used to import a non-existent `app.grounding` module and then return
    None regardless, so the metric was always null.
    """
    if not investigation_id:
        return None
    from app.graph.grounding import check_claims
    from app.repositories.verdicts import VerdictRepository

    total = 0
    grounded = 0
    for verdict in VerdictRepository.list_for_investigation(investigation_id):
        claims = verdict.get("claims") or []
        if not isinstance(claims, list) or not claims:
            continue
        try:
            report = check_claims(investigation_id, claims)
        except Exception:  # noqa: BLE001 - a bad verdict must not fail the eval
            continue
        total += len(report.claims)
        grounded += sum(1 for c in report.claims if c.ok)
    if total == 0:
        return None
    return round(grounded / total, 3)


def _mean_tool_calls(investigation_id: str) -> float | None:
    """Count tool calls from investigation steps."""
    from app.repositories.steps import StepRepository
    steps = StepRepository.list_for_investigation(investigation_id)
    if not steps:
        return None
    counts = [int(s.get("n") or 0) for s in steps]
    if not counts:
        return None
    return round(sum(counts) / len(counts), 1)


def _fixes_to_target(projection: Any, ranked: list[str], baseline_weight: float) -> int:
    """How many findings from this ranking must be fixed to remove 90% of weight."""
    if baseline_weight <= 0:
        return 0
    mods = Modifications()
    for index, finding_id in enumerate(ranked[:BASELINE_FIX_CAP], start=1):
        mods.removed_findings.add(finding_id)
        remaining = total_weight(enumerate_attack_paths(projection, mods=mods, top_k=0))
        if baseline_weight - remaining >= COVERAGE_TARGET * baseline_weight:
            return index
    return min(len(ranked), BASELINE_FIX_CAP)


def run_evaluation() -> EvalResponse:
    """Compute the three method columns and the per-finding table."""
    # Read ground truth from disk
    from app.seed.loader import read_ground_truth
    truth = read_ground_truth()
    exploitable = {str(f) for f in truth.get("exploitable_findings") or []}
    decoys = {str(f) for f in truth.get("decoys") or []}

    # Load the new graph projection
    projection = load_projection()
    paths = enumerate_attack_paths(projection, top_k=0)
    baseline_weight = total_weight(paths)
    lateral = live_exploits(projection, Modifications(), as_entry=False)
    on_path_services = {s for p in paths for s in p.services}

    best_score: dict[str, float] = {}
    for path in paths:
        for exploit in path.live_exploits:
            finding_id = str(exploit["finding_id"])
            best_score[finding_id] = max(best_score.get(finding_id, 0.0), path.breakdown.score)

    open_findings = {
        fid: facts for fid, facts in projection.findings.items() if facts.get("status") == "open"
    }
    present_exploitable = exploitable & set(open_findings)
    present_decoys = decoys & set(open_findings)

    # CVSS ranking (severity-first baseline)
    cvss_ranked = sorted(
        open_findings,
        key=lambda fid: (
            -open_findings[fid].get("cvss", 0.0),
            -open_findings[fid].get("epss", 0.0),
            fid,
        ),
    )
    # KEV/EPSS ranking
    kev_ranked = sorted(
        open_findings,
        key=lambda fid: (
            0 if open_findings[fid].get("kev", False) else 1,
            -open_findings[fid].get("epss", 0.0),
            -open_findings[fid].get("cvss", 0.0),
            fid,
        ),
    )

    # Verdicts from the latest completed investigation
    # Read investigation list to find latest completed
    from app.repositories.investigations import InvestigationRepository
    latest_inv = InvestigationRepository.get_latest_completed()
    investigation_id = latest_inv["id"] if latest_inv else ""
    verdicts = _latest_verdicts(investigation_id)
    latest = latest_inv or {}
    fix_now = [fid for fid, kind in verdicts.items() if kind == "FIX_NOW" and fid in open_findings]
    chokepoint_ranked = sorted(fix_now, key=lambda fid: (-best_score.get(fid, 0.0), fid))

    # Chokepoint fixes (greedy set cover)
    agent_fixes_raw = solve_chokepoints(projection, max_fixes=8).fixes
    agent_fixes = [
        ChokepointFix(
            rank=i,
            kind=fix.get("kind", ""),
            label=fix.get("label", ""),
            cost=fix.get("cost", 0.0),
            package_id=fix.get("package_id", ""),
            service_id=fix.get("service_id", ""),
            edge_from=fix.get("edge_from", ""),
            edge_to=fix.get("edge_to", ""),
            control_type=fix.get("control_type", ""),
            risk_removed=fix.get("risk_removed", 0.0),
            paths_removed=fix.get("paths_removed", 0),
            cumulative_risk_removed_pct=fix.get("cumulative_risk_removed_pct", 0.0),
            paths_remaining=fix.get("paths_remaining", 0),
        )
        for i, fix in enumerate(agent_fixes_raw, start=1)
        if isinstance(fix, dict)
    ]
    agent_fix_count = len(agent_fixes) if agent_fixes_raw else 0
    for index, fix in enumerate(agent_fixes_raw, start=1):
        if fix.get("cumulative_risk_removed_pct", 0) >= COVERAGE_TARGET * 100:
            agent_fix_count = index
            break

    def metrics(method: str, label: str, ranked: list[str], *, agent: bool = False) -> MethodMetrics:
        head = ranked[:TOP_N]
        denominator = max(1, len(head))
        correct = sum(1 for fid in head if fid in present_exploitable)
        # Recall at a fixed depth: every baseline ranks the whole queue, so
        # recall over the full list would be 1.0 for all of them and say nothing.
        reached = [fid for fid in ranked[:RECALL_AT] if fid in present_exploitable]
        recall = len(reached) / len(present_exploitable) if present_exploitable else 0.0
        return MethodMetrics(
            method=method,
            label=label,
            precision_at_10=round(correct / denominator, 3),
            recall=round(recall, 3),
            decoys_in_top10=sum(1 for fid in head if fid in present_decoys),
            fixes_to_90pct=(
                agent_fix_count if agent else _fixes_to_target(projection, ranked, baseline_weight)
            ),
            ranked=head,
            grounded_claim_rate=_grounded_rate(investigation_id) if agent else None,
            mean_tool_calls=_mean_tool_calls(investigation_id) if agent else None,
        )

    methods = [
        metrics("cvss", "CVSS-first", cvss_ranked),
        metrics("kev_epss", "KEV/EPSS-first", kev_ranked),
        metrics("chokepoint", "CHOKEPOINT", chokepoint_ranked, agent=True),
    ]

    # Build per-finding table rows
    from app.repositories.findings import FindingRepository
    findings_db = FindingRepository.list_for_scan(projection.scan_id)
    findings_by_id = {f.get("finding_id"): f for f in findings_db if isinstance(f, dict)}

    cvss_rank = {fid: idx for idx, fid in enumerate(cvss_ranked, start=1)}
    kev_rank = {fid: idx for idx, fid in enumerate(kev_ranked, start=1)}

    rows = []
    for fid in cvss_ranked:
        facts = findings_by_id.get(fid) or open_findings.get(fid)
        if not facts:
            continue
        rows.append(
            EvalRow(
                finding_id=fid,
                service_id=facts.get("service_id", ""),
                cve=facts.get("cve", ""),
                cvss=float(facts.get("cvss", 0.0)),
                epss=float(facts.get("epss", 0.0)),
                kev=bool(facts.get("kev", False)),
                ground_truth=(
                    "exploitable" if fid in exploitable else "decoy" if fid in decoys else "unlabelled"
                ),
                cvss_rank=cvss_rank.get(fid, 0),
                kev_rank=kev_rank.get(fid, 0),
                chokepoint_verdict=verdicts.get(fid, ""),
                on_attack_path=fid in best_score,
                best_path_score_pct=round(best_score.get(fid, 0.0) * 100, 1),
            )
        )
    rows.sort(key=lambda r: (r.ground_truth != "exploitable", -r.best_path_score_pct, r.cvss_rank))

    ready = bool(investigation_id and chokepoint_ranked)
    message = (
        ""
        if ready
        else (
            "No completed investigation has produced FIX_NOW verdicts yet. Run 'Triage the latest "
            "scan' and reload this page to fill the CHOKEPOINT column."
        )
    )
    live_on_path = sum(len(lateral.get(service, [])) for service in on_path_services)
    return EvalResponse(
        methods=methods,
        rows=rows[:ROW_CAP],
        investigation_id=investigation_id,
        exploitable_count=len(present_exploitable),
        decoy_count=len(present_decoys),
        chokepoint_fixes=[str(f) for f in truth.get("chokepoint_fixes") or []],
        agent_fixes=agent_fixes,
        caption=(
            f"{CAPTION} {len(paths)} attack paths carry {round(baseline_weight, 3)} weighted risk and "
            f"{live_on_path} live exploits sit on them."
        ),
        ready=ready,
        message=message,
    )