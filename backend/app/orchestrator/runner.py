"""Investigation runner: create and execute real agent-loop investigations.

This module provides:
  - create_investigation(goal, preset) -> dict
  - run_investigation(id, goal, preset) -> None
  - InvestigationRunner class for real codebase security analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.events import bus
from app.repositories.steps import StepRepository
from app.repositories.verdicts import VerdictRepository
from app.repositories.actions import ActionRepository
from app.repositories.blackboard import BlackboardRepository
from app.repositories.investigations import InvestigationRepository
from app.repositories.messages import MessageRepository
from app.repositories.simulations import SimulationRepository

log = logging.getLogger("chokepoint.runner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ms(start: float) -> float:
    return (time.monotonic() - start) * 1000.0


def create_investigation(goal: str, preset: str | None = None) -> dict[str, Any]:
    """Create a new investigation record.

    The mode starts as `pending`: whether the run is LLM-driven or deterministic
    is only known once the provider has been health-checked, and PRD FR-11
    forbids labelling a deterministic run as LLM-driven.
    """
    inv_id = f"INV-{uuid.uuid4().hex[:4].upper()}"
    InvestigationRepository.create(
        investigation_id=inv_id,
        goal=goal or "Triage the latest scan",
        mode="pending",
        preset=preset or "",
    )
    return {"id": inv_id, "mode": "pending", "goal": goal, "preset": preset or ""}


async def run_investigation(
    investigation_id: str,
    goal: str,
    preset: str | None = None,
) -> None:
    """Run investigation in background."""
    runner = InvestigationRunner(investigation_id, goal, preset)
    await runner.run()


class InvestigationRunner:
    """Executes multi-agent security triage on real codebase graphs."""

    def __init__(
        self,
        investigation_id: str,
        goal: str,
        preset: str | None = None,
    ) -> None:
        self.id = investigation_id
        self.goal = goal
        self.preset = preset or ""
        self.step_n = 0
        self.seq = 0
        # tool name -> step ids, so a claim can cite the step that produced it
        self.steps_by_tool: dict[str, list[str]] = {}
        self.paths: list[dict[str, Any]] = []
        self.verdicts: list[dict[str, Any]] = []
        self.actions: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []
        self.error: str | None = None
        self.mode = "pending"
        self.model = ""
        self.degraded = False
        self.chokepoints: list[dict[str, Any]] = []
        self.simulation: dict[str, Any] | None = None

    async def emit_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Emit event on the bus."""
        await bus.emit(self.id, event_type, payload)

    async def narrate(self, agent: str, text: str) -> None:
        """Send a message from an agent and persist it.

        Without the write the narration only existed on the live SSE stream, so
        reopening a finished investigation showed an empty ledger.
        """
        self.seq += 1
        msg = {"agent": agent, "text": text, "seq": self.seq}
        self.messages.append(msg)
        try:
            await asyncio.to_thread(
                MessageRepository.create,
                f"{self.id}-M{self.seq}",
                self.id,
                agent,
                text,
                self.seq,
            )
        except Exception as exc:  # noqa: BLE001 - a dropped message must not stop the run
            log.warning("could not persist agent message for %s: %s", self.id, exc)
        await self.emit_event("agent_message", msg)

    async def call_mcp_tool(self, agent: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool via MCP and emit tool_call and tool_result."""
        self.step_n += 1
        step_id = f"{self.id}-S{self.step_n}"
        self.steps_by_tool.setdefault(tool, []).append(step_id)

        # 1. Emit tool_call
        await self.emit_event("tool_call", {
            "step_id": step_id,
            "n": self.step_n,
            "agent": agent,
            "tool": tool,
            "args": args,
        })

        start = time.perf_counter()
        from app.orchestrator.mcp_client import client as mcp_client
        from app.orchestrator.providers.base import ToolCall

        outcome = await mcp_client.call_tool(agent, ToolCall(id=step_id, name=tool, args=args))
        latency = round((time.perf_counter() - start) * 1000.0, 2)

        result_payload = outcome.result if outcome.ok else {"error": outcome.error}
        summary = outcome.summary or f"{tool} executed"
        rows = outcome.result.get("rows", 0) if isinstance(outcome.result, dict) else 0
        touched = outcome.result.get("touched_ids", []) if isinstance(outcome.result, dict) else []
        cypher = outcome.result.get("cypher", []) if isinstance(outcome.result, dict) else []

        # 2. Persist step to DB
        try:
            StepRepository.create(
                step_id=step_id,
                investigation_id=self.id,
                n=self.step_n,
                agent=agent,
                tool=tool,
                args=args,
                cypher=cypher if isinstance(cypher, list) else [],
                rows=int(rows) if isinstance(rows, (int, float)) else 0,
                latency_ms=latency,
                summary=summary,
                touched_ids=touched if isinstance(touched, list) else [],
                engine="networkx",
                ok=outcome.ok,
                result=result_payload if isinstance(result_payload, dict) else {},
            )
        except Exception as exc:
            log.warning("failed to persist step %s: %s", step_id, exc)

        # 3. Emit tool_result
        await self.emit_event("tool_result", {
            "step_id": step_id,
            "n": self.step_n,
            "agent": agent,
            "tool": tool,
            "ok": outcome.ok,
            "summary": summary,
            "result": result_payload,
            "rows": rows,
            "latency_ms": latency,
            "touched_ids": touched,
            "cypher": cypher,
        })

        return result_payload if isinstance(result_payload, dict) else {}

    async def run(self) -> dict[str, Any]:
        """Execute the multi-agent investigation."""
        start_time = time.monotonic()
        await self.emit_event("run_started", {"status": "running"})

        try:
            from app.config import settings
            from app.orchestrator.mcp_client import client as mcp_client
            await mcp_client.connect()

            provider, model_name, why = await self._select_provider()
            self.mode = "live" if provider else "deterministic"
            self.model = model_name
            InvestigationRepository.update(self.id, mode=self.mode, model=model_name)
            await self.emit_event("mode", {"mode": self.mode, "model": model_name, "reason": why})
            await self.narrate("memory", why)

            if provider is not None:
                produced = await self._run_llm_loop(provider)
                if not produced:
                    # PRD FR-08: a provider failure must leave a traceable event
                    # and a safe degraded result, not an empty "done" run.
                    self.degraded = True
                    await self.emit_event(
                        "degraded",
                        {
                            "reason": (
                                f"the {model_name} agent loop produced no hypothesis, verdict or "
                                "action; falling back to the deterministic pipeline"
                            )
                        },
                    )
                    await self.narrate(
                        "memory",
                        f"The {model_name} agent loop returned nothing usable. "
                        "Continuing with the deterministic pipeline; this run is NOT LLM-reasoned.",
                    )
                    self.mode = "deterministic (LLM failed)"
                    InvestigationRepository.update(self.id, mode=self.mode)
                    await self._run_dynamic_graph_loop()
            else:
                await self._run_dynamic_graph_loop()

            duration = _ms(start_time)
            self._finish("done", duration)
            return {"status": "done", "id": self.id}

        except Exception as exc:  # noqa: BLE001
            log.exception("investigation %s failed: %s", self.id, exc)
            self.error = str(exc)
            duration = _ms(start_time)
            self._finish("failed", duration, error=str(exc))
            return {"status": "failed", "id": self.id, "error": str(exc)}

    async def _select_provider(self) -> tuple[Any, str, str]:
        """Pick a provider, health-checking it first. Returns (provider, model, reason)."""
        from app.config import settings

        if settings.agent_mode.strip().lower() == "scripted":
            return None, "deterministic", (
                "AGENT_MODE=scripted: this run uses the deterministic pipeline over "
                "real MCP tools. No model reasoning is involved."
            )

        if settings.gemini_api_key.strip():
            try:
                from app.orchestrator.providers.gemini_provider import GeminiProvider

                return GeminiProvider(), settings.gemini_model, (
                    f"Running with the hosted model {settings.gemini_model}."
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("Gemini provider unavailable: %s", exc)

        try:
            from app.orchestrator.providers.ollama_provider import OllamaProvider

            op = OllamaProvider()
            if await op._check_health():
                return op, settings.ollama_model, (
                    f"Running with the local model {settings.ollama_model} via Ollama."
                )
            return None, "deterministic", (
                f"Ollama at {settings.ollama_base_url} did not offer "
                f"{settings.ollama_model}: this run uses the deterministic pipeline over "
                "real MCP tools, with no model reasoning."
            )
        except Exception as exc:  # noqa: BLE001
            return None, "deterministic", (
                f"No model provider reachable ({exc.__class__.__name__}): this run uses the "
                "deterministic pipeline over real MCP tools, with no model reasoning."
            )

    async def _run_llm_loop(self, provider: Any) -> bool:
        """Run LLM agent turns. True when the run produced usable output."""
        from app.orchestrator.mcp_client import client as mcp_client

        produced_text = False
        for agent in ("memory", "scout", "skeptic", "scribe"):
            await self.emit_event("phase", {"phase": agent, "status": "start"})
            agent_tools = await mcp_client.tools_for(agent)

            async def narrate(text: str, _agent: str = agent) -> None:
                await self.narrate(_agent, text)

            _role = agent

            async def executor(call: Any, _r: str = agent) -> Any:
                # Report the real outcome: telling the model every call succeeded
                # hides tool errors from the agent that has to reason about them.
                from app.orchestrator.providers.base import ToolOutcome

                res = await self.call_mcp_tool(_r, call.name, call.args)
                failed = isinstance(res, dict) and bool(res.get("error"))
                return ToolOutcome(
                    call_id=call.id,
                    name=call.name,
                    ok=not failed,
                    result=res,
                    error=str(res.get("error")) if failed else "",
                )

            prompt = (
                f"You are the {agent} agent. Analyze the codebase security graph to solve: {self.goal}\n"
                "Use the available tools to inspect the graph, find paths, verify exploitability, and report."
            )
            try:
                result = await provider.run_agent(
                    agent=agent,
                    system=prompt,
                    user=self.goal,
                    tools=agent_tools,
                    executor=executor,
                    max_tool_calls=10,
                    narrate=narrate,
                    context={"preset": self.preset, "goal": self.goal},
                )
                stopped = getattr(result, "stopped_because", "")
                if stopped in ("llm_error", "timeout"):
                    await self.emit_event(
                        "agent_failed", {"agent": agent, "reason": stopped}
                    )
                else:
                    produced_text = produced_text or bool(getattr(result, "text", ""))
            except Exception as exc:  # noqa: BLE001 - one agent must not kill the run
                log.warning("%s agent failed: %s", agent, exc)
                await self.emit_event(
                    "agent_failed",
                    {"agent": agent, "reason": f"{exc.__class__.__name__}: {exc}"},
                )
            await self.emit_event("phase", {"phase": agent, "status": "end"})

        board = BlackboardRepository.get_blackboard(self.id)
        verdicts = VerdictRepository.list_for_investigation(self.id)
        return bool(board.get("hypotheses") or verdicts)

    async def _run_dynamic_graph_loop(self) -> None:
        """Deterministic multi-agent pipeline over the scanned repository.

        Every claim made here is derived from the graph, the findings or a tool
        result. Nothing asserts a control, a call path or a mitigation that was
        not observed (PRD FR-08).
        """
        from app.graph.attack import enumerate_attack_paths
        from app.graph.grounding import check_claims
        from app.graph.projection import load_projection
        from app.graph.solver import find_chokepoints, fix_from_dict, simulate_fixes

        proj = load_projection()

        # -------------------------------------------------------------
        # Phase 1: Memory
        # -------------------------------------------------------------
        await self.emit_event("phase", {"phase": "memory", "status": "start"})
        recall = await self.call_mcp_tool(
            "memory", "recall", {"query_text": self.goal, "subject_ids": [], "limit": 5}
        )
        lesson_count = int((recall.get("data") or {}).get("lesson_count") or 0)
        await self.narrate(
            "memory",
            f"Scan {proj.scan_id}: {len(proj.findings)} findings, {len(proj.packages)} packages, "
            f"{len(proj.nodes)} graph nodes. {lesson_count} prior lesson(s) matched this subject.",
        )
        await self.emit_event("phase", {"phase": "memory", "status": "end"})

        # -------------------------------------------------------------
        # Phase 2: Scout
        # -------------------------------------------------------------
        await self.emit_event("phase", {"phase": "scout", "status": "start"})
        await self.call_mcp_tool("scout", "graph_overview", {})

        attack_paths = enumerate_attack_paths(proj, max_hops=7, top_k=8)
        self.paths = [p.as_dict() for p in attack_paths]
        await self.call_mcp_tool("scout", "find_attack_paths", {"max_hops": 7, "top_k": 8})

        for path in self.paths:
            await self.emit_event("path_found", {"path": path})
            await self.emit_event(
                "graph_highlight",
                {
                    "node_ids": [n["id"] for n in path.get("nodes", [])],
                    "reason": f"Modelled route to {path.get('target_name', 'a data store')}",
                },
            )

        findings_res = await self.call_mcp_tool("scout", "list_open_findings", {"limit": 10})
        findings_list = (findings_res.get("data") or {}).get("findings", [])

        exploit_checks: dict[str, dict[str, Any]] = {}
        for item in findings_list[:4]:
            fid = item.get("finding_id") or item.get("id")
            if not fid:
                continue
            res = await self.call_mcp_tool("scout", "check_exploitability", {"finding_id": fid})
            exploit_checks[str(fid)] = (res.get("data") or {})

        on_path_findings = {fid for p in attack_paths for fid in p.finding_ids()}

        # The hypothesis names the findings that are actually on a modelled path.
        hyp_num = BlackboardRepository.next_hypothesis_number(self.id)
        hyp_id = f"{self.id}-H{hyp_num}"
        on_path_packages = sorted(
            {
                str(proj.findings[fid].get("package_name") or proj.findings[fid].get("file_path") or fid)
                for fid in on_path_findings
                if fid in proj.findings
            }
        )
        if attack_paths:
            claim_text = (
                f"{len(on_path_findings)} finding(s) sit on {len(attack_paths)} modelled "
                f"route(s) from a public entry point to a flagged data store"
                + (f" via {', '.join(on_path_packages[:3])}" if on_path_packages else "")
                + ". The route is modelled from repository structure; it is not observed traffic."
            )
            confidence = 0.6
        else:
            claim_text = (
                f"No route from a public entry point to a flagged data store could be modelled "
                f"for this repository, so none of the {len(proj.findings)} finding(s) is "
                "supported by path evidence. Reachability remains not established."
            )
            confidence = 0.4

        BlackboardRepository.create_hypothesis(
            investigation_id=self.id,
            hypothesis_id=hyp_id,
            agent="scout",
            claim=claim_text,
            confidence=confidence,
            about_ids=sorted(on_path_findings) or sorted(proj.findings)[:3],
            based_on_step_ids=[f"{self.id}-S{n}" for n in range(2, min(self.step_n, 4) + 1)],
        )
        await self.emit_event(
            "hypothesis",
            {
                "id": hyp_id,
                "investigation_id": self.id,
                "kind": "hypothesis",
                "agent": "scout",
                "claim": claim_text,
                "status": "open",
                "confidence": confidence,
                "about_ids": sorted(on_path_findings),
                "based_on_step_ids": [f"{self.id}-S{n}" for n in range(2, min(self.step_n, 4) + 1)],
                "created_at": _now(),
            },
        )
        await self.narrate("scout", claim_text)
        await self.emit_event("phase", {"phase": "scout", "status": "end"})

        # -------------------------------------------------------------
        # Phase 3: Skeptic -- a real falsification attempt
        # -------------------------------------------------------------
        await self.emit_event("phase", {"phase": "skeptic", "status": "start"})
        first_service = next(iter(proj.services), "")
        if first_service:
            await self.call_mcp_tool("skeptic", "blast_radius", {"service_id": first_service})

        # Count the findings whose reachability nothing established. These are
        # the weak point in the Scout's claim, and they are counted, not asserted.
        not_established = [
            fid
            for fid, facts in proj.findings.items()
            if str(facts.get("reachability") or "not_established") != "supported"
        ]
        unmapped = [
            fid
            for fid, facts in proj.findings.items()
            if str(facts.get("mapping_status") or "unmatched") == "unmatched"
        ]
        inferred_hops = sum(
            1
            for p in attack_paths
            for e in p.edges
            if str((proj.graph.get_edge_data(e["source"], e["target"]) or {}).get("provenance", ""))
            == "INFERRED"
        )

        contradicts = bool(not_established) and not on_path_findings
        challenge_claim = (
            f"{len(not_established)} of {len(proj.findings)} finding(s) have reachability "
            f"'not established' -- no scanner or code-graph evidence shows the vulnerable code "
            f"being called. {len(unmapped)} finding(s) are unmapped to any graph entity. "
            f"{inferred_hops} hop(s) on the proposed route(s) are CHOKEPOINT-modelled rather than "
            "extracted from the repository. No mitigating control was observed either way: the "
            "repository carries no control evidence, so controls are unknown, not absent."
        )
        ch_num = BlackboardRepository.next_challenge_number(self.id)
        ch_id = f"{self.id}-C{ch_num}"
        BlackboardRepository.create_challenge(
            investigation_id=self.id,
            challenge_id=ch_id,
            hypothesis_id=hyp_id,
            agent="skeptic",
            claim=challenge_claim,
            confidence=0.6,
            contradicts=contradicts,
            about_ids=[hyp_id],
            based_on_step_ids=[f"{self.id}-S{self.step_n}"],
        )
        await self.emit_event(
            "challenge",
            {
                "id": ch_id,
                "investigation_id": self.id,
                "kind": "challenge",
                "agent": "skeptic",
                "claim": challenge_claim,
                "status": "upheld" if contradicts else "open",
                "outcome": "upheld" if contradicts else "rejected",
                "confidence": 0.6,
                "contradicts": contradicts,
                "about_ids": [hyp_id],
                "based_on_step_ids": [f"{self.id}-S{self.step_n}"],
                "created_at": _now(),
            },
        )
        await self.narrate("skeptic", challenge_claim)
        await self.emit_event("phase", {"phase": "skeptic", "status": "end"})

        # -------------------------------------------------------------
        # Phase 4: Rebuttal -- only what the code graph actually shows
        # -------------------------------------------------------------
        await self.emit_event("phase", {"phase": "rebuttal", "status": "start"})
        code_edges = sum(
            1
            for _s, _d, data in proj.graph.edges(data=True)
            if str(data.get("relation", "")).startswith("CODE_")
        )
        extracted_edges = sum(
            1
            for _s, _d, data in proj.graph.edges(data=True)
            if str(data.get("provenance", "")) == "EXTRACTED"
        )
        if code_edges:
            rebuttal = (
                f"The code graph holds {code_edges} extracted code relationship(s) "
                f"({extracted_edges} edge(s) marked EXTRACTED overall). That supports the "
                "dependency and containment structure, but no call path was traced from an "
                "entry point into the vulnerable library code, so exploitability stays unproven."
            )
        else:
            rebuttal = (
                "No code-level relationships were extracted for this repository, so the route "
                "rests entirely on the CHOKEPOINT estate model. Treat the ranking as a "
                "prioritisation hint, not as path evidence."
            )
        await self.narrate("scout", rebuttal)
        await self.emit_event("phase", {"phase": "rebuttal", "status": "end"})

        # -------------------------------------------------------------
        # Phase 5: Scribe -- verdicts via the real MCP tool and grounding check
        # -------------------------------------------------------------
        await self.emit_event("phase", {"phase": "scribe", "status": "start"})
        await self.call_mcp_tool("scribe", "find_chokepoints", {"max_fixes": 5})
        solution = find_chokepoints(proj, max_fixes=5)
        self.chokepoints = solution.fixes

        # A claim about a finding's rating and its route must cite the steps that
        # returned those numbers: the findings listing and the path enumeration.
        evidence_steps = [
            *self.steps_by_tool.get("list_open_findings", []),
            *self.steps_by_tool.get("find_attack_paths", []),
            *self.steps_by_tool.get("check_exploitability", []),
        ]

        for index, (fid, facts) in enumerate(sorted(proj.findings.items()), start=1):
            cve = str(facts.get("cve") or facts.get("rule_id") or fid)
            cvss = float(facts.get("cvss") or 0.0)
            pkg = str(facts.get("package_name") or facts.get("file_path") or "unknown target")
            reach = str(facts.get("reachability") or "not_established")

            # The disposition follows the evidence, not the iteration index.
            if fid in on_path_findings:
                kind = "FIX_NOW"
                rationale = (
                    f"{cve} on {pkg} is carried by a modelled route to a flagged data store."
                )
            elif cvss >= 7.0:
                kind = "SCHEDULE"
                rationale = (
                    f"{cve} on {pkg} is rated {cvss} by its source but is on no modelled route; "
                    f"reachability is {reach}."
                )
            else:
                kind = "SCHEDULE" if reach != "supported" else "FIX_NOW"
                rationale = (
                    f"{cve} on {pkg} is on no modelled route and is rated {cvss}; "
                    f"reachability is {reach}, which is not the same as unreachable."
                )

            claims = [
                {
                    "id": f"{self.id}-V{index:02d}-C1",
                    "text": rationale,
                    "cites": list(evidence_steps),
                    "node_ids": [],
                }
            ]
            # Run the same grounding check the MCP record_verdict tool uses, so
            # `grounded` reflects a real check instead of a hardcoded True.
            try:
                report = check_claims(self.id, claims)
                grounded = bool(report.grounded)
                grounding = report.as_dict()
            except Exception as exc:  # noqa: BLE001
                log.warning("grounding check failed for %s: %s", fid, exc)
                grounded, grounding = False, {"error": str(exc)}

            v_id = f"{self.id}-V{index:02d}"
            VerdictRepository.create(
                verdict_id=v_id,
                investigation_id=self.id,
                finding_ids=[fid],
                kind=kind,
                requested_kind=kind,
                confidence=0.6 if fid in on_path_findings else 0.4,
                grounded=grounded,
                safety_valve_applied=False,
                safety_valve_reason="",
                claims=claims,
                evidence_path_ids=[
                    p.id for p in attack_paths if fid in p.finding_ids()
                ],
                grounding=grounding,
            )
            verdict_dict = {
                "id": v_id,
                "investigation_id": self.id,
                "finding_ids": [fid],
                "finding_id": fid,
                "kind": kind,
                "confidence": 0.6 if fid in on_path_findings else 0.4,
                "grounded": grounded,
                "headline": f"{kind}: {cve} ({pkg})",
                "cve": cve,
                "rationale": rationale,
                "reachability": reach,
                "created_at": _now(),
            }
            self.verdicts.append(verdict_dict)
            await self.emit_event("verdict", verdict_dict)

        # -------------------------------------------------------------
        # Remediation simulation on an isolated graph copy (PRD 7.1 item 9)
        # -------------------------------------------------------------
        if self.chokepoints:
            try:
                top = self.chokepoints[0]
                fix = fix_from_dict(top, proj)
                if fix is not None:
                    await self.call_mcp_tool(
                        "scout", "simulate_fix", {"fixes": [top]}
                    )
                    self.simulation = simulate_fixes(proj, [fix])
                    self.simulation["fixes_applied"] = [fix.as_dict()]
                    self.simulation["assumptions"] = [
                        "The fix is applied to a deep copy of the graph only; no source file "
                        "and no persisted baseline is changed.",
                        "Removing the finding is modelled as removing it from every path it "
                        "carries; it does not prove the upgrade is correct or complete.",
                    ]
                    await self.emit_event("simulation", self.simulation)
                    try:
                        SimulationRepository.create(
                            simulation_id=f"{self.id}-SIM1",
                            investigation_id=self.id,
                            verdict_id=self.verdicts[0]["id"] if self.verdicts else None,
                            baseline_weight=float(
                                (self.simulation.get("before") or {}).get("total_weight") or 0.0
                            ),
                            baseline_paths=int(
                                (self.simulation.get("before") or {}).get("paths") or 0
                            ),
                            after_weight=float(
                                (self.simulation.get("after") or {}).get("total_weight") or 0.0
                            ),
                            after_paths=int(
                                (self.simulation.get("after") or {}).get("paths") or 0
                            ),
                            fixes=[fix.as_dict()],
                            result=self.simulation,
                        )
                    except Exception as exc:  # noqa: BLE001
                        log.warning("could not persist simulation: %s", exc)
            except Exception as exc:  # noqa: BLE001 - simulation is not critical
                log.warning("simulation failed: %s", exc)
                await self.emit_event("simulation_failed", {"reason": str(exc)})

        # -------------------------------------------------------------
        # Proposed actions for the top chokepoints
        # -------------------------------------------------------------
        for position, fix in enumerate(self.chokepoints[:3], start=1):
            a_id = f"{self.id}-A{position:02d}"
            label = fix.get("label") or f"Remediate {fix.get('package_id', 'finding')}"
            body_md = (
                f"### Proposed remediation\n\n"
                f"**{label}**\n\n"
                f"- Modelled weighted risk removed: {fix.get('risk_removed', 0.0):.3f}\n"
                f"- Modelled routes cut: {fix.get('paths_removed', 0)}\n"
                f"- Cumulative modelled reduction: {fix.get('cumulative_risk_removed_pct', 0.0):.1f}%\n"
                f"- Effort proxy (not an estimate from your backlog): {fix.get('cost', 0.0)}\n\n"
                "This is a graph simulation under the modelled assumptions. It is not applied "
                "to source and does not prove the fix is correct.\n"
            )
            ActionRepository.create(
                action_id=a_id,
                investigation_id=self.id,
                verdict_id=self.verdicts[0]["id"] if self.verdicts else "",
                kind="ticket",
                title=f"Chokepoint fix: {label}",
                body_md=body_md,
                team="unknown (no CODEOWNERS evidence)",
            )
            payload = {
                "id": a_id,
                "investigation_id": self.id,
                "kind": "ticket",
                "status": "proposed",
                "title": f"Chokepoint fix: {label}",
                "body_md": body_md,
                "team": "unknown (no CODEOWNERS evidence)",
                "created_at": _now(),
            }
            self.actions.append(payload)
            await self.emit_event("action_proposed", payload)

        fix_now = sum(1 for v in self.verdicts if v["kind"] == "FIX_NOW")
        summary_text = (
            f"{len(proj.findings)} finding(s) across {len(proj.nodes)} graph entities. "
            f"{len(attack_paths)} modelled route(s) to a flagged data store; "
            f"{len(on_path_findings)} finding(s) sit on one. "
            f"{fix_now} FIX_NOW, {len(self.verdicts) - fix_now} SCHEDULE. "
            f"{len(not_established)} finding(s) have reachability 'not established'. "
            f"Coverage is limited to the scanners that ran; this is a prioritisation, "
            f"not proof of exploitability."
        )
        await self.narrate("scribe", summary_text)
        await self.emit_event("phase", {"phase": "scribe", "status": "end"})

    def _finish(self, status: str, duration_ms: float, error: str = "") -> None:
        """Persist completion and emit run_finished."""
        snapshot = {
            "goal": self.goal,
            "preset": self.preset,
            "mode": self.mode,
            "model": self.model,
            "degraded": self.degraded,
            "paths": self.paths,
            "summary": self.messages[-1]["text"] if self.messages else "Investigation complete.",
            "created_at": _now(),
        }
        try:
            InvestigationRepository.finish(
                self.id,
                status=status,
                duration_ms=duration_ms,
                snapshot=snapshot,
                # chokepoints used to receive the attack-path list, so the
                # dossier's chokepoint table rendered path rows.
                chokepoints=self.chokepoints,
                simulation=self.simulation,
                memory_brief={
                    "subjects": sorted({p.get("entry", "") for p in self.paths if p.get("entry")}),
                    "retrieval": "graph + keyword",
                    "note": (
                        f"mode: {self.mode}"
                        + (" (degraded: the model loop produced nothing)" if self.degraded else "")
                    ),
                },
                error=error,
            )
        except Exception as exc:
            log.warning("failed to update investigation finish: %s", exc)

        asyncio.create_task(
            self.emit_event("run_finished", {
                "status": status,
                "duration_ms": duration_ms,
                "steps": self.step_n,
                "verdicts": len(self.verdicts),
                "paths": len(self.paths),
                "error": error,
            })
        )
