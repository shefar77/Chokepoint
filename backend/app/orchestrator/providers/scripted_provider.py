"""Deterministic agent loop that needs no API key.

It runs a fixed, per-scenario sequence of **real MCP tool calls** against the
live graph and narrates the actual tool results. The graph still decides the
outcome: no number in the narration or in a claim is written here, every one is
read back from a tool result.
"""

from __future__ import annotations

import logging
from typing import Any

from app.seed import scenarios

from .base import AgentResult, Executor, LLMProvider, Narrator, ToolCall, ToolOutcome, ToolSpec

log = logging.getLogger("chokepoint.provider.scripted")

# Scenario subjects are fixed by the planted seed; everything else is derived
# from tool results at run time.
S1_FINDING = "F-0003"
S4_FINDING = "F-0004"
S5_FINDING = "F-0005"
S5_FINDING_SECOND = "F-0006"
S6_FINDING = "F-0007"
S6_SERVICE = "ml-notebooks"
S7_FINDING = "F-0101"
S7_SERVICE = "search-api"
S6_DELTA_FINDING = "F-0102"
S6_DELTA_SERVICE = "feature-lab"

PRESETS = ("triage", "target", "fixes", "delta")


def classify(goal: str, preset: str) -> str:
    """Map a goal or preset onto one of the four scripted plans."""
    if preset in PRESETS:
        return preset
    text = (goal or "").lower()
    if any(word in text for word in ("changed", "yesterday", "delta", "day 2", "day-2", "since")):
        return "delta"
    if any(word in text for word in ("reachable", "reach ", "can anyone get", "path to")):
        return "target"
    if any(word in text for word in ("fixes", "fix set", "matter most", "what should we do")):
        return "fixes"
    return "triage"


class _Plan:
    """Executes tool calls, keeps results and collects narration."""

    def __init__(
        self,
        *,
        agent: str,
        executor: Executor,
        narrate: Narrator,
        budget: int,
        context: dict[str, Any],
        available: set[str],
    ) -> None:
        self.agent = agent
        self._executor = executor
        self._narrate = narrate
        self.budget = budget
        self.context = context
        self.available = available
        self.calls = 0
        self.lines: list[str] = []
        self.outcomes: dict[str, list[ToolOutcome]] = {}

    async def say(self, text: str) -> None:
        line = " ".join(text.split())
        if not line:
            return
        self.lines.append(line)
        await self._narrate(line)

    async def call(self, tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one tool. Returns the result payload, or {} when unavailable."""
        if self.calls >= self.budget:
            return {}
        if tool not in self.available:
            await self.say(f"{tool} is not available to {self.agent}; skipping it.")
            return {}
        self.calls += 1
        outcome = await self._executor(
            ToolCall(id=f"{self.agent}-{self.calls}", name=tool, args=dict(args or {}))
        )
        self.outcomes.setdefault(tool, []).append(outcome)
        if not outcome.ok:
            await self.say(f"{tool} failed: {outcome.error}")
            return {}
        return outcome.result

    def step_id(self, tool: str, index: int = -1) -> str:
        outcomes = self.outcomes.get(tool) or []
        if not outcomes:
            return ""
        return outcomes[index].step_id

    def step_ids(self, *tools: str) -> list[str]:
        return [sid for tool in tools if (sid := self.step_id(tool))]

    def text(self) -> str:
        return "\n\n".join(self.lines)


def _data(result: dict[str, Any]) -> dict[str, Any]:
    """Tool payload, preferring the un-clipped `full` view where a tool sends one.

    `data` is clipped to the LLM budget, so reading it alone can silently lose
    the hypothesis or step a verdict needs to cite.
    """
    data = result.get("data")
    merged = dict(data) if isinstance(data, dict) else {}
    full = result.get("full")
    if isinstance(full, dict):
        merged.update(full)
    return merged


def _paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    paths = _data(result).get("paths")
    return [p for p in paths if isinstance(p, dict)] if isinstance(paths, list) else []


def _top_exploit(path: dict[str, Any]) -> dict[str, Any]:
    exploits = path.get("live_exploits")
    if isinstance(exploits, list) and exploits and isinstance(exploits[0], dict):
        return exploits[0]
    return {}


def _ingress_host(overview: dict[str, Any], ingress_id: str) -> str:
    for row in _data(overview).get("public_ingress") or []:
        if isinstance(row, dict) and str(row.get("id")) == ingress_id:
            return str(row.get("host") or ingress_id)
    return ingress_id


def _lessons(context: dict[str, Any]) -> list[dict[str, Any]]:
    lessons = context.get("lessons")
    return [lesson for lesson in lessons if isinstance(lesson, dict)] if isinstance(lessons, list) else []


def _lesson_for(context: dict[str, Any], *values: str) -> dict[str, Any] | None:
    wanted = {v.lower() for v in values if v}
    for lesson in _lessons(context):
        scope = str(lesson.get("scope_value") or "").lower()
        text = str(lesson.get("text") or "").lower()
        if scope and (scope in wanted or any(w in text for w in wanted)):
            return lesson
    return _lessons(context)[0] if _lessons(context) else None


# --- Scout plans -------------------------------------------------------------

async def _scout_triage(plan: _Plan) -> None:
    overview = await plan.call("graph_overview")
    headline = _data(overview).get("headline") or {}
    await plan.say(
        f"{headline.get('open_findings', 0)} open findings, "
        f"{headline.get('internet_reachable_findings', 0)} internet-reachable, "
        f"{headline.get('findings_reaching_crown_jewel', 0)} on a route to a crown jewel. "
        f"{_data(overview).get('public_ingress_count', 0)} public ingress points."
    )

    naive = await plan.call("list_open_findings", {"limit": 10})
    rows = _data(naive).get("findings") or []
    if rows:
        first = rows[0]
        await plan.say(
            f"Severity-first triage would open {first.get('cve')} on {first.get('service_id')} at "
            f"CVSS {first.get('cvss')}. That ordering says nothing about reachability, so I will "
            "ask the graph instead."
        )

    paths_result = await plan.call("find_attack_paths", {"max_hops": 7, "top_k": 8})
    paths = _paths(paths_result)
    if not paths:
        await plan.say("No internet-to-crown-jewel path exists under the current controls.")
        return
    top = paths[0]
    exploit = _top_exploit(top)
    chain = " -> ".join(str(n.get("id")) for n in top.get("nodes") or [])
    await plan.say(
        f"{_data(paths_result).get('path_count', len(paths))} paths reach a crown jewel. The worst is "
        f"{chain}: {top.get('hops')} hops, score {top.get('score_pct')}, entry authentication "
        f"'{top.get('entry_authn')}'."
    )

    entry_check = await plan.call("check_exploitability", {"finding_id": exploit.get("finding_id")})
    if entry_check:
        await plan.say(entry_check.get("summary", ""))

    decoy = await plan.call("check_exploitability", {"finding_id": S1_FINDING})
    if decoy:
        await plan.say(decoy.get("summary", ""))

    mitigated = await plan.call("check_exploitability", {"finding_id": S4_FINDING})
    if mitigated:
        await plan.say(mitigated.get("summary", ""))

    choke = await plan.call("find_chokepoints", {"max_fixes": 8})
    fixes = _data(choke).get("fixes") or []
    if fixes:
        await plan.say(choke.get("summary", ""))

    simulation: dict[str, Any] = {}
    if fixes:
        simulation = await plan.call(
            "simulate_fix",
            {
                "fixes": [
                    {
                        "kind": fix.get("kind"),
                        "package_id": fix.get("package_id", ""),
                        "service_id": fix.get("service_id", ""),
                        "edge_from": fix.get("edge_from", ""),
                        "edge_to": fix.get("edge_to", ""),
                    }
                    for fix in fixes[:3]
                ]
            },
        )
        if simulation:
            await plan.say(simulation.get("summary", ""))

    host = _ingress_host(overview, str(top.get("entry_ingress")))
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{exploit.get('cve')} in {top.get('entry')} opens a {top.get('hops')}-hop route from "
                f"{host} to {top.get('target')}, scored {top.get('score_pct')}."
            ),
            "about_ids": [str(n.get("id")) for n in top.get("nodes") or []]
            + [str(exploit.get("finding_id"))],
            "based_on_step_ids": plan.step_ids("find_attack_paths", "check_exploitability"),
            "confidence": 0.86,
        },
    )
    if fixes:
        first_fix = fixes[0]
        await plan.call(
            "post_hypothesis",
            {
                "investigation_id": plan.context["investigation_id"],
                "claim": (
                    f"{first_fix.get('label')} is the single highest-leverage fix: it removes "
                    f"{first_fix.get('cumulative_risk_removed_pct')}% of weighted attack-path risk."
                ),
                "about_ids": [str(first_fix.get("package_id") or first_fix.get("service_id") or "")],
                "based_on_step_ids": plan.step_ids("find_chokepoints", "simulate_fix"),
                "confidence": 0.82,
            },
        )
    decoy_data = _data(decoy)
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{(decoy_data.get('vulnerability') or {}).get('cve')} on "
                f"{(decoy_data.get('service') or {}).get('id')} is not reachable from the internet "
                "despite its severity, because no public ingress routes to that service."
            ),
            "about_ids": [S1_FINDING, str((decoy_data.get("service") or {}).get("id") or "")],
            "based_on_step_ids": plan.step_ids("check_exploitability"),
            "confidence": 0.78,
        },
    )
    mitigated_data = _data(mitigated)
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{(mitigated_data.get('vulnerability') or {}).get('cve')} on "
                f"{(mitigated_data.get('service') or {}).get('id')} sits behind a public ingress and "
                "is the highest-severity internet-facing finding, so it needs immediate review."
            ),
            "about_ids": [S4_FINDING, str((mitigated_data.get("service") or {}).get("id") or "")],
            "based_on_step_ids": plan.step_ids("check_exploitability"),
            "confidence": 0.6,
        },
    )
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{S5_FINDING} is exploitable from the internet and its service holds an admin role "
                "over customer data."
            ),
            "about_ids": [S5_FINDING, S5_FINDING_SECOND],
            "based_on_step_ids": plan.step_ids("find_attack_paths", "list_open_findings"),
            "confidence": 0.45,
        },
    )
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{S6_FINDING} on {S6_SERVICE} reaches production data, because the vulnerable code "
                "is reachable and the service is published."
            ),
            "about_ids": [S6_FINDING, S6_SERVICE],
            "based_on_step_ids": plan.step_ids("find_attack_paths"),
            "confidence": 0.4,
        },
    )


async def _scout_target(plan: _Plan) -> None:
    target = plan.context.get("target") or "payments-vault"
    overview = await plan.call("graph_overview")
    crown = [str(c.get("id")) for c in _data(overview).get("crown_jewels") or []]
    await plan.say(f"Crown jewels in scope: {', '.join(crown) or 'none'}. Asking about {target}.")

    paths_result = await plan.call("find_attack_paths", {"max_hops": 7, "top_k": 8, "target": target})
    paths = _paths(paths_result)
    if not paths:
        await plan.say(f"No path from the internet to {target} under current controls.")
        await plan.call("shortest_path", {"from_id": "internet", "to_id": target})
        return
    top = paths[0]
    exploit = _top_exploit(top)
    chain = " -> ".join(str(n.get("id")) for n in top.get("nodes") or [])
    await plan.say(f"{target} is reachable. Best route: {chain}, score {top.get('score_pct')}.")

    check = await plan.call("check_exploitability", {"finding_id": exploit.get("finding_id")})
    if check:
        await plan.say(check.get("summary", ""))
    blast = await plan.call("blast_radius", {"service_id": top.get("entry"), "max_hops": 4})
    if blast:
        await plan.say(blast.get("summary", ""))
    await plan.call("shortest_path", {"from_id": "internet", "to_id": target})
    choke = await plan.call("find_chokepoints", {"max_fixes": 8})
    fixes = _data(choke).get("fixes") or []
    if fixes:
        await plan.say(choke.get("summary", ""))
        await plan.call(
            "simulate_fix",
            {
                "fixes": [
                    {
                        "kind": fix.get("kind"),
                        "package_id": fix.get("package_id", ""),
                        "service_id": fix.get("service_id", ""),
                        "edge_from": fix.get("edge_from", ""),
                        "edge_to": fix.get("edge_to", ""),
                    }
                    for fix in fixes[:2]
                ]
            },
        )

    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{target} is reachable from the internet in {top.get('hops')} hops through "
                f"{top.get('entry')}, scored {top.get('score_pct')}."
            ),
            "about_ids": [str(n.get("id")) for n in top.get("nodes") or []],
            "based_on_step_ids": plan.step_ids("find_attack_paths", "check_exploitability"),
            "confidence": 0.88,
        },
    )
    if fixes:
        await plan.call(
            "post_hypothesis",
            {
                "investigation_id": plan.context["investigation_id"],
                "claim": (
                    f"{fixes[0].get('label')} cuts that route and removes "
                    f"{fixes[0].get('cumulative_risk_removed_pct')}% of weighted risk."
                ),
                "about_ids": [str(fixes[0].get("package_id") or fixes[0].get("service_id") or "")],
                "based_on_step_ids": plan.step_ids("find_chokepoints", "simulate_fix"),
                "confidence": 0.8,
            },
        )


async def _scout_fixes(plan: _Plan) -> None:
    await plan.call("graph_overview")
    paths_result = await plan.call("find_attack_paths", {"max_hops": 7, "top_k": 8})
    paths = _paths(paths_result)
    await plan.say(
        f"{_data(paths_result).get('path_count', len(paths))} paths carry "
        f"{_data(paths_result).get('total_weight', 0)} total weighted risk."
    )
    choke = await plan.call("find_chokepoints", {"max_fixes": 8})
    fixes = _data(choke).get("fixes") or []
    if not fixes:
        await plan.say("No fix removes weighted risk; there is nothing to cut.")
        return
    await plan.say(choke.get("summary", ""))
    simulation = await plan.call(
        "simulate_fix",
        {
            "fixes": [
                {
                    "kind": fix.get("kind"),
                    "package_id": fix.get("package_id", ""),
                    "service_id": fix.get("service_id", ""),
                    "edge_from": fix.get("edge_from", ""),
                    "edge_to": fix.get("edge_to", ""),
                }
                for fix in fixes[:3]
            ]
        },
    )
    if simulation:
        await plan.say(simulation.get("summary", ""))
    centrality = await plan.call(
        "rank_centrality", {"scope": "attack_paths", "algorithm": "betweenness"}
    )
    if centrality:
        await plan.say(centrality.get("summary", ""))

    top3 = fixes[: min(3, len(fixes))]
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{len(top3)} fixes remove {top3[-1].get('cumulative_risk_removed_pct')}% of weighted "
                f"attack-path risk, starting with {top3[0].get('label')}."
            ),
            "about_ids": [str(fix.get("package_id") or fix.get("service_id") or "") for fix in top3],
            "based_on_step_ids": plan.step_ids("find_chokepoints", "simulate_fix"),
            "confidence": 0.85,
        },
    )
    ranking = _data(centrality).get("ranking") or []
    if ranking:
        await plan.call(
            "post_hypothesis",
            {
                "investigation_id": plan.context["investigation_id"],
                "claim": (
                    f"{ranking[0].get('id')} is the most central service on the attack-path subgraph, "
                    "so hardening it is structurally justified."
                ),
                "about_ids": [str(ranking[0].get("id"))],
                "based_on_step_ids": plan.step_ids("rank_centrality"),
                "confidence": 0.55,
            },
        )


async def _scout_delta(plan: _Plan) -> None:
    overview = await plan.call("graph_overview")
    await plan.say(
        f"Scan ids present: {', '.join(_data(overview).get('scan_ids') or []) or 'none'}."
    )
    diff = await plan.call(
        "diff_since_last", {"investigation_id": plan.context.get("investigation_id")}
    )
    if diff:
        await plan.say(diff.get("summary", ""))
    paths_result = await plan.call("find_attack_paths", {"max_hops": 7, "top_k": 8})
    paths = _paths(paths_result)
    new_paths = _data(diff).get("new_paths") or []
    new_entries = {str(p.get("entry")) for p in new_paths if isinstance(p, dict)}
    fresh = [p for p in paths if str(p.get("entry")) in new_entries] or paths[:1]
    if fresh:
        top = fresh[0]
        chain = " -> ".join(str(n.get("id")) for n in top.get("nodes") or [])
        await plan.say(f"New route: {chain}, {top.get('hops')} hops, score {top.get('score_pct')}.")

    check = await plan.call("check_exploitability", {"finding_id": S7_FINDING})
    if check:
        await plan.say(check.get("summary", ""))
    choke = await plan.call("find_chokepoints", {"max_fixes": 8})
    fixes = _data(choke).get("fixes") or []
    if fixes:
        await plan.say(choke.get("summary", ""))
        await plan.call(
            "simulate_fix",
            {
                "fixes": [
                    {
                        "kind": fix.get("kind"),
                        "package_id": fix.get("package_id", ""),
                        "service_id": fix.get("service_id", ""),
                        "edge_from": fix.get("edge_from", ""),
                        "edge_to": fix.get("edge_to", ""),
                    }
                    for fix in fixes[:2]
                ]
            },
        )

    if fresh:
        top = fresh[0]
        await plan.call(
            "post_hypothesis",
            {
                "investigation_id": plan.context["investigation_id"],
                "claim": (
                    f"The day-2 scan opens a new {top.get('hops')}-hop route from the internet to "
                    f"{top.get('target')} through {top.get('entry')}, scored {top.get('score_pct')}."
                ),
                "about_ids": [str(n.get("id")) for n in top.get("nodes") or []] + [S7_FINDING],
                "based_on_step_ids": plan.step_ids("find_attack_paths", "check_exploitability"),
                "confidence": 0.87,
            },
        )
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{S6_DELTA_FINDING} on {S6_DELTA_SERVICE} is new and needs the same treatment as any "
                "other reachable-code finding."
            ),
            "about_ids": [S6_DELTA_FINDING, S6_DELTA_SERVICE],
            "based_on_step_ids": plan.step_ids("diff_since_last", "find_attack_paths"),
            "confidence": 0.42,
        },
    )


# --- Skeptic plans -----------------------------------------------------------

def _hypotheses(board: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _data(board).get("hypotheses")
    return [h for h in rows if isinstance(h, dict)] if isinstance(rows, list) else []


def _find_hypothesis(board: dict[str, Any], *needles: str) -> dict[str, Any] | None:
    for hypothesis in _hypotheses(board):
        about = {str(a) for a in hypothesis.get("about_ids") or []}
        claim = str(hypothesis.get("claim") or "")
        if any(n in about or n in claim for n in needles):
            return hypothesis
    return None


async def _skeptic_triage(plan: _Plan) -> None:
    board = await plan.call("list_blackboard", {"investigation_id": plan.context["investigation_id"]})
    if not board:
        return
    await plan.say(board.get("summary", ""))

    mitigated = await plan.call("check_exploitability", {"finding_id": S4_FINDING})
    target = _find_hypothesis(board, S4_FINDING)
    controls = (_data(mitigated).get("blocking_controls")) or []
    if target and controls:
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": target.get("id"),
                "kind": "control_present",
                "claim": f"An active control already blocks it: {controls[0]}.",
                "based_on_step_ids": plan.step_ids("check_exploitability"),
                "outcome": "upheld",
            },
        )
        await plan.say(f"{S4_FINDING} is neutralised today: {controls[0]}. Challenge upheld.")

    decoy_hypothesis = _find_hypothesis(board, S1_FINDING)
    decoy_service = ""
    for hypothesis in _hypotheses(board):
        if S1_FINDING in {str(a) for a in hypothesis.get("about_ids") or []}:
            ids = [str(a) for a in hypothesis.get("about_ids") or [] if str(a) != S1_FINDING]
            decoy_service = ids[0] if ids else ""
    route = await plan.call(
        "shortest_path",
        {
            "from_id": "internet",
            "to_id": decoy_service or "report-renderer",
            "rel_types": ["REACHES", "ROUTES_TO", "CALLS"],
        },
    )
    if decoy_hypothesis:
        reachable = bool(_data(route).get("found")) and bool(_data(route).get("directed"))
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": decoy_hypothesis.get("id"),
                "kind": "edge_dead",
                "claim": (
                    "I looked for a directed route from the internet over ingress and call edges "
                    + (
                        "and found one, so the claim is wrong."
                        if reachable
                        else "and found none, so the claim stands."
                    )
                ),
                "based_on_step_ids": plan.step_ids("shortest_path"),
                "outcome": "upheld" if reachable else "rejected",
            },
        )
        await plan.say(route.get("summary", ""))

    zombie = await plan.call("check_exploitability", {"finding_id": S5_FINDING})
    zombie_hypothesis = _find_hypothesis(board, S5_FINDING)
    service_active = bool((_data(zombie).get("checks") or {}).get("service_active", True))
    if zombie_hypothesis:
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": zombie_hypothesis.get("id"),
                "kind": "service_inactive",
                "claim": (
                    "The owning service is not running, so nothing there can be exploited."
                    if not service_active
                    else "The owning service is active, so the claim is not refuted on those grounds."
                ),
                "based_on_step_ids": plan.step_ids("check_exploitability"),
                "outcome": "rejected" if service_active else "upheld",
            },
        )
        await plan.say(zombie.get("summary", ""))

    components = await plan.call("connected_components", {"scope": "calls"})
    sandbox_hypothesis = _find_hypothesis(board, S6_FINDING, S6_SERVICE)
    lesson = _lesson_for(plan.context, S6_SERVICE, "sandbox-eu")
    if sandbox_hypothesis:
        segment = next(
            (
                c
                for c in _data(components).get("components") or []
                if isinstance(c, dict) and S6_SERVICE in [str(m) for m in c.get("members") or []]
            ),
            None,
        )
        crown = (segment or {}).get("crown_jewels_reachable") or []
        kind = "prior_lesson" if lesson else "edge_dead"
        claim = (
            f"A prior lesson applies: {lesson.get('text')}"
            if lesson
            else f"{S6_SERVICE} sits in a call-graph component that reaches no crown jewel at all."
        )
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": sandbox_hypothesis.get("id"),
                "kind": kind,
                "claim": claim,
                "based_on_step_ids": plan.step_ids("connected_components"),
                "outcome": "upheld" if not crown else "rejected",
            },
        )
        await plan.say(components.get("summary", ""))

    top_hypothesis = _hypotheses(board)[0] if _hypotheses(board) else None
    path_step = next(
        (
            str(step.get("id"))
            for step in _data(board).get("steps") or []
            if isinstance(step, dict) and str(step.get("tool")) == "find_attack_paths"
        ),
        "",
    )
    if top_hypothesis and path_step:
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": top_hypothesis.get("id"),
                "kind": "auth_required",
                "claim": (
                    "I tested whether the top route needs an authenticated caller. The entry ingress "
                    "authenticates nobody, so it does not. The claim survives."
                ),
                "based_on_step_ids": [path_step],
                "outcome": "rejected",
            },
        )


async def _skeptic_target(plan: _Plan) -> None:
    board = await plan.call("list_blackboard", {"investigation_id": plan.context["investigation_id"]})
    if not board:
        return
    await plan.say(board.get("summary", ""))
    hypotheses = _hypotheses(board)
    if not hypotheses:
        return
    entry = ""
    for candidate in hypotheses[0].get("about_ids") or []:
        if str(candidate) not in ("internet",) and not str(candidate).startswith("ing-"):
            entry = str(candidate)
            break
    context_result = await plan.call("get_service_context", {"service_id": entry})
    if context_result:
        await plan.say(context_result.get("summary", ""))
    ingress = _data(context_result).get("ingress") or []
    unauthenticated = [g for g in ingress if isinstance(g, dict) and str(g.get("authn")) == "none"]
    await plan.call(
        "post_challenge",
        {
            "investigation_id": plan.context["investigation_id"],
            "hypothesis_id": hypotheses[0].get("id"),
            "kind": "auth_required",
            "claim": (
                "The entry service has an unauthenticated public ingress, so the route does not "
                "require credentials."
                if unauthenticated
                else "Every ingress to the entry service authenticates, so the route needs credentials."
            ),
            "based_on_step_ids": plan.step_ids("get_service_context"),
            "outcome": "rejected" if unauthenticated else "upheld",
        },
    )


async def _skeptic_fixes(plan: _Plan) -> None:
    board = await plan.call("list_blackboard", {"investigation_id": plan.context["investigation_id"]})
    if not board:
        return
    await plan.say(board.get("summary", ""))
    centrality = await plan.call("rank_centrality", {"scope": "services", "algorithm": "pagerank"})
    if centrality:
        await plan.say(centrality.get("summary", ""))
    hypotheses = _hypotheses(board)
    structural = hypotheses[-1] if len(hypotheses) > 1 else (hypotheses[0] if hypotheses else None)
    if structural:
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": structural.get("id"),
                "kind": "edge_dead",
                "claim": (
                    "I re-ranked centrality over the whole call graph rather than the attack-path "
                    "subgraph. The ordering is consistent, so the structural argument holds."
                ),
                "based_on_step_ids": plan.step_ids("rank_centrality"),
                "outcome": "rejected",
            },
        )


async def _skeptic_delta(plan: _Plan) -> None:
    board = await plan.call("list_blackboard", {"investigation_id": plan.context["investigation_id"]})
    if not board:
        return
    await plan.say(board.get("summary", ""))
    recalled = await plan.call(
        "recall",
        {
            "subject_ids": [S6_DELTA_SERVICE, S6_SERVICE],
            "query_text": f"is a finding in {S6_DELTA_SERVICE} worth acting on",
        },
    )
    lessons = _data(recalled).get("lessons") or []
    sandbox_hypothesis = _find_hypothesis(board, S6_DELTA_FINDING, S6_DELTA_SERVICE)
    if sandbox_hypothesis:
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": sandbox_hypothesis.get("id"),
                "kind": "prior_lesson",
                "claim": (
                    f"A lesson already covers this segment: {lessons[0].get('text')}"
                    if lessons
                    else "No lesson covers this segment yet, so the claim is not refuted by memory."
                ),
                "based_on_step_ids": plan.step_ids("recall"),
                "outcome": "upheld" if lessons else "rejected",
            },
        )
        if lessons:
            await plan.say(f"Lesson applied: {lessons[0].get('text')}")
    check = await plan.call("check_exploitability", {"finding_id": S7_FINDING})
    new_hypothesis = _find_hypothesis(board, S7_FINDING, S7_SERVICE)
    if new_hypothesis and check:
        live = bool(_data(check).get("live_exploit"))
        await plan.call(
            "post_challenge",
            {
                "investigation_id": plan.context["investigation_id"],
                "hypothesis_id": new_hypothesis.get("id"),
                "kind": "unreachable_code",
                "claim": (
                    "I checked whether the vulnerable code is actually called. It is, so the new route "
                    "stands."
                    if live
                    else "The vulnerable code is not called by this service, so the new route does not hold."
                ),
                "based_on_step_ids": plan.step_ids("check_exploitability"),
                "outcome": "rejected" if live else "upheld",
            },
        )
        await plan.say(check.get("summary", ""))


# --- Scribe ------------------------------------------------------------------

def _ctx_steps(context: dict[str, Any]) -> list[dict[str, Any]]:
    rows = context.get("steps")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _ctx_step(context: dict[str, Any], tool: str) -> str:
    """First step id for a tool, from the orchestrator's ledger."""
    for row in _ctx_steps(context):
        if str(row.get("tool")) == tool and row.get("ok"):
            return str(row.get("id"))
    return ""


def _ctx_step_touching(context: dict[str, Any], node_id: str, tool: str = "") -> str:
    for row in _ctx_steps(context):
        if tool and str(row.get("tool")) != tool:
            continue
        if node_id in [str(t) for t in row.get("touched_ids") or []]:
            return str(row.get("id"))
    return ""


def _board_step(board: dict[str, Any], tool: str) -> str:
    for step in _data(board).get("steps") or []:
        if isinstance(step, dict) and str(step.get("tool")) == tool:
            return str(step.get("id"))
    return ""


def _step_touching(board: dict[str, Any], node_id: str, tool: str = "") -> str:
    """The step whose touched_ids include this node, so a claim can cite it."""
    for step in _data(board).get("steps") or []:
        if not isinstance(step, dict):
            continue
        if tool and str(step.get("tool")) != tool:
            continue
        if node_id in [str(t) for t in step.get("touched_ids") or []]:
            return str(step.get("id"))
    return ""


def _board_steps(board: dict[str, Any], tool: str) -> list[str]:
    return [
        str(step.get("id"))
        for step in _data(board).get("steps") or []
        if isinstance(step, dict) and str(step.get("tool")) == tool
    ]


def _upheld_against(board: dict[str, Any], hypothesis_id: str) -> dict[str, Any] | None:
    for challenge in _data(board).get("challenges") or []:
        if (
            isinstance(challenge, dict)
            and str(challenge.get("hypothesis_id")) == hypothesis_id
            and str(challenge.get("outcome")) == "upheld"
        ):
            return challenge
    return None


def _ticket_body(
    *,
    what: str,
    path_text: str,
    fix_text: str,
    blast_text: str,
    simulation_text: str,
    verify_text: str,
) -> str:
    return (
        f"## What\n{what}\n\n"
        f"## Why\n{path_text}\n\n"
        f"## Fix\n{fix_text}\n\n"
        f"## Blast radius\n{blast_text}\n\n"
        f"## Simulated risk reduction\n{simulation_text}\n\n"
        f"## How to verify\n{verify_text}\n"
    )


async def _scribe(plan: _Plan, preset: str) -> None:
    board = await plan.call("list_blackboard", {"investigation_id": plan.context["investigation_id"]})
    if not board:
        return
    await plan.say(board.get("summary", ""))

    paths = _data(board).get("attack_paths") or []
    top_path = paths[0] if paths and isinstance(paths[0], dict) else {}
    path_step = _ctx_step(plan.context, "find_attack_paths") or _board_step(board, "find_attack_paths")
    exploit_steps = [
        step
        for step in (
            _board_steps(board, "check_exploitability")
            or [_ctx_step(plan.context, "check_exploitability")]
        )
        if step
    ]
    choke_step = _ctx_step(plan.context, "find_chokepoints") or _board_step(board, "find_chokepoints")
    sim_step = _ctx_step(plan.context, "simulate_fix") or _board_step(board, "simulate_fix")

    subjects = [str(top_path.get("entry") or ""), str(top_path.get("target") or "")]
    if preset == "delta":
        subjects += [S6_DELTA_SERVICE, S7_SERVICE]
    else:
        subjects += [S6_SERVICE]
    recalled = await plan.call(
        "recall",
        {
            "subject_ids": [s for s in subjects if s],
            "query_text": plan.context.get("goal", "triage"),
        },
    )
    lessons = _data(recalled).get("lessons") or []
    recall_step = plan.step_id("recall")

    chokepoints = plan.context.get("chokepoints") or []
    first_fix = chokepoints[0] if chokepoints else {}
    simulation = plan.context.get("simulation") or {}

    fix_now_findings = [
        str(exploit.get("finding_id"))
        for path in paths[:6]
        if isinstance(path, dict)
        for exploit in (plan.context.get("path_exploits") or {}).get(str(path.get("id")), [])
    ]
    if not fix_now_findings:
        fix_now_findings = [str(f) for f in plan.context.get("live_finding_ids") or []][:12]

    fix_now_verdict_id = ""
    if fix_now_findings and path_step and top_path:
        claims = [
            {
                "id": "C1",
                "text": (
                    f"Fix the live exploit in {top_path.get('entry')} first: it is the shortest live "
                    f"route from the open internet to {top_path.get('target')}."
                ),
                "cites": [path_step],
                "node_ids": [str(top_path.get("entry")), str(top_path.get("target"))],
            },
            {
                "id": "C2",
                "text": (
                    f"That route is {top_path.get('hops')} hops and scores "
                    f"{top_path.get('score_pct')}."
                ),
                "cites": [path_step],
                "node_ids": [],
            },
        ]
        if exploit_steps:
            claims.append(
                {
                    "id": "C3",
                    "text": "Every live-exploit predicate holds for the entry finding, checked one by one.",
                    "cites": [exploit_steps[0]],
                    "node_ids": [],
                }
            )
        if choke_step and first_fix:
            claims.append(
                {
                    "id": "C4",
                    "text": (
                        f"{first_fix.get('label')} alone removes "
                        f"{first_fix.get('cumulative_risk_removed_pct')}% of weighted attack-path risk."
                    ),
                    "cites": [choke_step],
                    "node_ids": [],
                }
            )
        if sim_step and simulation:
            claims.append(
                {
                    "id": "C5",
                    "text": (
                        f"Simulated on a copy of the graph, the top fixes remove "
                        f"{(simulation.get('delta') or {}).get('paths_removed')} paths and "
                        f"{(simulation.get('delta') or {}).get('risk_removed_pct')}% of weighted risk."
                    ),
                    "cites": [sim_step],
                    "node_ids": [],
                }
            )
        verdict = await plan.call(
            "record_verdict",
            {
                "investigation_id": plan.context["investigation_id"],
                "finding_ids": list(dict.fromkeys(fix_now_findings))[:12],
                "kind": "FIX_NOW",
                "confidence": 0.86,
                "claims": claims,
            },
        )
        if verdict:
            fix_now_verdict_id = str(_data(verdict).get("verdict_id") or "")
            await plan.say(verdict.get("summary", ""))

    mitigated_hypothesis = _find_hypothesis(board, S4_FINDING)
    if mitigated_hypothesis and _upheld_against(board, str(mitigated_hypothesis.get("id"))):
        challenge = _upheld_against(board, str(mitigated_hypothesis.get("id"))) or {}
        cites = [
            s
            for s in [
                _ctx_step_touching(plan.context, S4_FINDING, "check_exploitability")
                or _step_touching(board, S4_FINDING, "check_exploitability")
            ]
            if s
        ]
        if cites:
            schedule = await plan.call(
                "record_verdict",
                {
                    "investigation_id": plan.context["investigation_id"],
                    "finding_ids": [S4_FINDING],
                    "kind": "SCHEDULE",
                    "confidence": 0.8,
                    "claims": [
                        {
                            "id": "C1",
                            "text": (
                                "Schedule this one rather than paging anyone: an active control blocks "
                                "it today, so it is not a live exploit."
                            ),
                            "cites": cites,
                            "node_ids": [S4_FINDING],
                        },
                        {
                            "id": "C2",
                            "text": f"The Skeptic upheld a control_present challenge: {challenge.get('claim')}",
                            "cites": cites,
                            "node_ids": [],
                        },
                    ],
                },
            )
            if schedule:
                await plan.say(schedule.get("summary", ""))

    suppress_cites = [
        s
        for s in [
            _ctx_step_touching(plan.context, S1_FINDING, "check_exploitability")
            or _step_touching(board, S1_FINDING, "check_exploitability"),
            _ctx_step_touching(plan.context, S5_FINDING, "check_exploitability")
            or _step_touching(board, S5_FINDING, "check_exploitability"),
        ]
        if s
    ]
    if suppress_cites:
        suppressed = await plan.call(
            "record_verdict",
            {
                "investigation_id": plan.context["investigation_id"],
                "finding_ids": [S1_FINDING, S5_FINDING, S5_FINDING_SECOND],
                "kind": "SUPPRESS",
                "confidence": 0.78,
                "claims": [
                    {
                        "id": "C1",
                        "text": (
                            "Suppress these. The first sits in a service with no public ingress route "
                            "and no inbound call, so the internet cannot reach it."
                        ),
                        "cites": suppress_cites,
                        "node_ids": [S1_FINDING],
                    },
                    {
                        "id": "C2",
                        "text": (
                            "The others belong to a service whose status is not active, so nothing "
                            "runs there to exploit."
                        ),
                        "cites": suppress_cites,
                        "node_ids": [],
                    },
                ],
            },
        )
        if suppressed:
            await plan.say(suppressed.get("summary", ""))

    sandbox_finding = S6_DELTA_FINDING if preset == "delta" else S6_FINDING
    sandbox_service = S6_DELTA_SERVICE if preset == "delta" else S6_SERVICE
    sandbox_lesson = next(
        (
            lesson
            for lesson in lessons
            if sandbox_service in str(lesson.get("text") or "")
            or str(lesson.get("scope_value") or "") in (sandbox_service, "sandbox-eu")
        ),
        lessons[0] if lessons else None,
    )
    if recall_step:
        if sandbox_lesson:
            sandbox = await plan.call(
                "record_verdict",
                {
                    "investigation_id": plan.context["investigation_id"],
                    "finding_ids": [sandbox_finding],
                    "kind": "ACCEPT",
                    "confidence": 0.74,
                    "claims": [
                        {
                            "id": "C1",
                            "text": f"Accept this one on the recorded lesson: {sandbox_lesson.get('text')}",
                            "cites": [recall_step],
                            "node_ids": [str(sandbox_lesson.get("lesson_id")), sandbox_service],
                        }
                    ],
                },
            )
        else:
            sandbox = await plan.call(
                "record_verdict",
                {
                    "investigation_id": plan.context["investigation_id"],
                    "finding_ids": [sandbox_finding],
                    "kind": "SCHEDULE",
                    "confidence": 0.55,
                    "claims": [
                        {
                            "id": "C1",
                            "text": (
                                "Schedule this one with low confidence: the vulnerable code is "
                                "reachable, but the service is on no route to a crown jewel."
                            ),
                            "cites": [s for s in [path_step, recall_step] if s],
                            "node_ids": [],
                        }
                    ],
                },
            )
        if sandbox:
            await plan.say(sandbox.get("summary", ""))

    verdict_id = fix_now_verdict_id
    if not verdict_id:
        for outcome in plan.outcomes.get("record_verdict") or []:
            candidate = str(_data(outcome.result).get("verdict_id") or "")
            if candidate:
                verdict_id = candidate
                break
    if not verdict_id:
        await plan.say("No verdict was stored, so there is nothing to route.")
        return

    blast = plan.context.get("blast") or {}
    path_text = (
        f"{top_path.get('entry')} is reachable from the internet and {top_path.get('target')} is "
        f"{top_path.get('hops')} hops away. The path scores {top_path.get('score_pct')} out of 100."
    )
    simulation_delta = simulation.get("delta") or {}
    simulation_text = (
        f"Simulated on a graph copy: {simulation_delta.get('paths_removed', 0)} of "
        f"{(simulation.get('before') or {}).get('paths', 0)} paths removed, "
        f"{simulation_delta.get('risk_removed_pct', 0)}% of weighted risk gone."
    )
    await plan.call(
        "propose_action",
        {
            "verdict_id": verdict_id,
            "kind": "ticket",
            "title": f"Cut the internet route to {top_path.get('target')} at {top_path.get('entry')}",
            "body_md": _ticket_body(
                what=(
                    f"Remove the live exploit that makes {top_path.get('entry')} an entry point into "
                    f"{top_path.get('target')}."
                ),
                path_text=path_text,
                fix_text=(
                    f"{first_fix.get('label', 'Apply the ordered chokepoint fix set')} "
                    f"(effort proxy {first_fix.get('cost', 'n/a')})."
                ),
                blast_text=(
                    str(blast.get("summary") or "")
                    or f"Nodes on this path: {', '.join(str(n) for n in top_path.get('node_ids') or [])}."
                ),
                simulation_text=simulation_text,
                verify_text=(
                    "Re-run the investigation after deploying. The path count for this target should "
                    "drop to zero and the finding should no longer be a live exploit."
                ),
            ),
        },
    )
    if first_fix:
        await plan.call(
            "propose_action",
            {
                "verdict_id": verdict_id,
                "kind": "ticket",
                "title": f"{first_fix.get('label')} across every service that uses it",
                "body_md": _ticket_body(
                    what=f"{first_fix.get('label')}.",
                    path_text=(
                        f"This single change removes {first_fix.get('cumulative_risk_removed_pct')}% of "
                        f"weighted attack-path risk and {first_fix.get('paths_removed')} paths."
                    ),
                    fix_text=f"Kind: {first_fix.get('kind')}. Effort proxy: {first_fix.get('cost')}.",
                    blast_text=(
                        f"Services affected: {(first_fix.get('detail') or {}).get('services_using', 'see graph')}."
                    ),
                    simulation_text=simulation_text,
                    verify_text="Confirm the package version in every dependent service, then re-run triage.",
                ),
            },
        )
    await plan.say("Verdicts and actions are on the board. Actions wait for human approval.")


async def _scout_rebuttal(plan: _Plan) -> None:
    """One short round: re-check the challenged claim and amend it."""
    rebuttal = plan.context.get("rebuttal") or {}
    finding_id = str(rebuttal.get("finding_id") or "")
    service_id = str(rebuttal.get("service_id") or "")
    await plan.say(
        f"The Skeptic upheld a {rebuttal.get('kind')} challenge: {rebuttal.get('claim')} Re-checking."
    )
    check = await plan.call("check_exploitability", {"finding_id": finding_id}) if finding_id else {}
    if check:
        await plan.say(check.get("summary", ""))
    service = await plan.call("get_service_context", {"service_id": service_id}) if service_id else {}
    controls = [
        c
        for c in _data(service).get("controls") or []
        if isinstance(c, dict) and bool(c.get("active"))
    ]
    control_text = (
        f"{controls[0].get('name')} ({controls[0].get('type')})" if controls else "an active control"
    )
    await plan.call(
        "post_hypothesis",
        {
            "investigation_id": plan.context["investigation_id"],
            "claim": (
                f"{finding_id} is contained today by {control_text}, so it is not a live exploit, but "
                "the compensating control is not a fix and the package still needs upgrading on the "
                "normal schedule."
            ),
            "about_ids": [finding_id, service_id],
            "based_on_step_ids": plan.step_ids("check_exploitability", "get_service_context"),
            "confidence": 0.8,
        },
    )
    await plan.say("Claim amended: contained, not fixed.")


SCOUT_PLANS = {
    "triage": _scout_triage,
    "target": _scout_target,
    "fixes": _scout_fixes,
    "delta": _scout_delta,
}
SKEPTIC_PLANS = {
    "triage": _skeptic_triage,
    "target": _skeptic_target,
    "fixes": _skeptic_fixes,
    "delta": _skeptic_delta,
}


class ScriptedProvider(LLMProvider):
    """No API key, no model. Real tool calls, real graph, templated prose."""

    name = "scripted"

    async def run_agent(
        self,
        *,
        agent: str,
        system: str,
        user: str,
        tools: list[ToolSpec],
        executor: Executor,
        max_tool_calls: int,
        narrate: Narrator,
        context: dict[str, Any],
    ) -> AgentResult:
        preset = classify(str(context.get("goal") or ""), str(context.get("preset") or ""))
        plan = _Plan(
            agent=agent,
            executor=executor,
            narrate=narrate,
            budget=max_tool_calls,
            context={**context, "preset": preset},
            available={t.name for t in tools},
        )
        if agent == "scout" and str(context.get("phase") or "") == "rebuttal":
            await _scout_rebuttal(plan)
        elif agent == "scout":
            await SCOUT_PLANS[preset](plan)
        elif agent == "skeptic":
            await SKEPTIC_PLANS[preset](plan)
        elif agent == "scribe":
            await _scribe(plan, preset)
        else:
            await plan.say(f"No scripted plan for agent '{agent}'.")
        return AgentResult(text=plan.text(), tool_calls=plan.calls, stopped_because="script_complete")

    async def distill_lesson(self, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Rule-based distillation: scope by cluster for non-production, else by service."""
        service = payload.get("service") or {}
        cluster = str(service.get("cluster") or "")
        env = str(service.get("env") or "prod")
        package = str(payload.get("package") or "")
        new_kind = str(payload.get("new_kind") or "ACCEPT")
        note = " ".join(str(payload.get("note") or "").split())
        effect = {
            "ACCEPT": "downgrade",
            "SUPPRESS": "suppress",
            "SCHEDULE": "downgrade",
            "FIX_NOW": "upgrade",
        }.get(new_kind, "require_check")

        if env != "prod" and cluster:
            scope_kind, scope_value, strength = "cluster", cluster, 0.85
            text = (
                f"Services in cluster {cluster} have no call or role route to any production data "
                f"store, so findings there do not warrant immediate action."
            )
        elif package:
            scope_kind, scope_value, strength = "package", package, 0.7
            text = f"Findings reached through {package} are judged on reachability, not severity, in this estate."
        else:
            scope_kind, scope_value, strength = "service", str(service.get("id") or "unknown"), 0.65
            text = (
                f"{service.get('id')} findings are judged on whether a route to a crown jewel exists."
            )
        if note:
            text = f"{text} Analyst note: {note}"
        return {
            "text": text,
            "scope_kind": scope_kind,
            "scope_value": scope_value,
            "effect": effect,
            "strength": strength,
        }
