"""Pydantic schemas for the HTTP API and the SSE stream.

The TypeScript types in `frontend/src/api/types.ts` mirror this file field for
field. Change one, change the other.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Phase = Literal["memory", "scout", "skeptic", "rebuttal", "scribe"]
AgentName = Literal["memory", "scout", "skeptic", "scribe", "orchestrator", "system"]
VerdictKind = Literal["FIX_NOW", "SCHEDULE", "ACCEPT", "SUPPRESS"]
ActionKind = Literal["ticket", "suppress", "virtual_patch_request"]
ActionStatus = Literal["proposed", "approved", "executed", "rejected"]
RunStatus = Literal["running", "done", "failed"]
EventType = Literal[
    "run_started",
    "phase",
    "agent_message",
    "tool_call",
    "tool_result",
    "graph_highlight",
    "path_found",
    "hypothesis",
    "challenge",
    "memory_hit",
    "verdict",
    "action_proposed",
    "error",
    "run_finished",
]


class StreamEvent(BaseModel):
    id: str = ""
    investigation_id: str = ""
    n: int = 0
    type: str = ""
    ts: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


# --- health and capabilities -------------------------------------------------

class CapabilityReport(BaseModel):
    procedures_detected: int = 0
    algorithms: dict[str, str] = Field(default_factory=dict)
    native_procedures: list[str] = Field(default_factory=list)


class EmbeddingStatus(BaseModel):
    mode: str
    model: str = ""
    dimension: int = 384
    ready: bool = False
    warning: str = ""


class HealthResponse(BaseModel):
    ok: bool
    graph_ok: bool = True
    graph: str
    node_count: int = 0
    mcp: bool = False
    mcp_url: str = ""
    mcp_tools: int = 0
    agent_mode: str
    configured_agent_mode: str = "scripted"
    model: str
    mode_warning: str = ""
    embeddings: EmbeddingStatus
    capabilities: CapabilityReport
    seed_scale: int
    outbox_dir: str


# --- graph ---------------------------------------------------------------

class GraphNode(BaseModel):
    id: str
    label: str
    props: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    props: dict[str, Any] = Field(default_factory=dict)


class SubgraphResponse(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    truncated: bool = False
    hidden_nodes: int = 0
    latency_ms: float = 0.0


class CrownJewel(BaseModel):
    id: str
    name: str = ""
    kind: str = ""
    classification: str = ""
    records: int = 0


class PublicIngress(BaseModel):
    id: str
    host: str = ""
    authn: str = ""
    waf: bool = False
    service_id: str = ""


class Headline(BaseModel):
    open_findings: int = 0
    internet_reachable_findings: int = 0
    findings_reaching_crown_jewel: int = 0
    attack_paths: int = 0
    crown_jewels_reachable: list[str] = Field(default_factory=list)
    top_path_score_pct: float = 0.0


class GraphOverviewResponse(BaseModel):
    nodes_by_label: dict[str, int] = Field(default_factory=dict)
    relationships_by_type: dict[str, int] = Field(default_factory=dict)
    scan_ids: list[str] = Field(default_factory=list)
    public_ingress_count: int = 0
    public_ingress: list[PublicIngress] = Field(default_factory=list)
    crown_jewels: list[CrownJewel] = Field(default_factory=list)
    headline: Headline = Field(default_factory=Headline)
    latency_ms: float = 0.0


class FindingRow(BaseModel):
    finding_id: str
    service_id: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    attack_vector: str = "network"
    reachable_code: bool = False
    package: str = ""
    version: str = ""
    scan_id: str = ""
    summary: str = ""
    tier: int = 3


class NaiveViewResponse(BaseModel):
    findings: list[FindingRow] = Field(default_factory=list)
    latency_ms: float = 0.0


class SchemaResponse(BaseModel):
    labels: list[dict[str, Any]] = Field(default_factory=list)
    relationship_types: list[dict[str, Any]] = Field(default_factory=list)
    examples: list[dict[str, str]] = Field(default_factory=list)


class CypherRequest(BaseModel):
    query: str = Field(min_length=3, max_length=4000)
    params: dict[str, Any] = Field(default_factory=dict)


class CypherResponse(BaseModel):
    header: list[str] = Field(default_factory=list)
    rows: list[list[Any]] = Field(default_factory=list)
    row_count: int = 0
    latency_ms: float = 0.0
    truncated: bool = False
    query: str = ""


# --- MCP ---------------------------------------------------------------------

class McpToolInfo(BaseModel):
    name: str
    description: str = ""
    group: str = "read"
    roles: list[str] = Field(default_factory=list)
    write: bool = False
    input_schema: dict[str, Any] = Field(default_factory=dict)


class McpToolsResponse(BaseModel):
    server: str = "chokepoint-mcp"
    url: str = "http://localhost:8765/mcp"
    connected: bool = False
    tools: list[McpToolInfo] = Field(default_factory=list)
    error: str = ""


# --- investigation records ---------------------------------------------------

class ScoreComponents(BaseModel):
    exploitability: float = 0.0
    exposure: float = 0.0
    impact: float = 0.0
    length_penalty: float = 0.0
    control_discount: float = 0.0
    score: float = 0.0


class PathNode(BaseModel):
    id: str
    label: str = ""
    name: str = ""


class PathEdge(BaseModel):
    source: str
    target: str
    type: str
    authz: str = ""


class LiveExploit(BaseModel):
    finding_id: str
    service_id: str
    cve: str
    cvss: float = 0.0
    epss: float = 0.0
    kev: bool = False
    package: str = ""
    exploitability: float = 0.0


class AttackPathModel(BaseModel):
    id: str
    score: float = 0.0
    score_pct: float = 0.0
    hops: int = 0
    entry: str = ""
    entry_ingress: str = ""
    entry_authn: str = ""
    target: str = ""
    target_name: str = ""
    target_classification: str = ""
    target_records: int = 0
    components: ScoreComponents = Field(default_factory=ScoreComponents)
    nodes: list[PathNode] = Field(default_factory=list)
    edges: list[PathEdge] = Field(default_factory=list)
    live_exploits: list[LiveExploit] = Field(default_factory=list)
    mitigating_controls: list[str] = Field(default_factory=list)
    # Whether any exploit on this route has reachability evidence. Without it
    # the UI cannot tell a modelled route from a verified one.
    reachability_verified: bool = False
    evidence_note: str = ""


class StepRecord(BaseModel):
    id: str
    n: int
    agent: AgentName
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    cypher: list[str] = Field(default_factory=list)
    rows: int = 0
    latency_ms: float = 0.0
    summary: str = ""
    touched_ids: list[str] = Field(default_factory=list)
    engine: str = "networkx"  # value always networkx
    ok: bool = True
    result: dict[str, Any] | None = None


class HypothesisModel(BaseModel):
    id: str
    agent: str = "scout"
    claim: str = ""
    status: Literal["open", "supported", "falsified", "weakened"] = "open"
    confidence: float = 0.0
    about_ids: list[str] = Field(default_factory=list)
    based_on_step_ids: list[str] = Field(default_factory=list)


class ChallengeModel(BaseModel):
    id: str
    kind: str = ""
    claim: str = ""
    outcome: Literal["upheld", "rejected", "supported", "falsified", "open"] = "rejected"
    hypothesis_id: str = ""
    hypothesis_claim: str = ""
    based_on_step_ids: list[str] = Field(default_factory=list)


class ClaimModel(BaseModel):
    id: str
    text: str
    cites: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    grounded: bool = True
    failures: list[str] = Field(default_factory=list)


class FeedbackModel(BaseModel):
    id: str
    action: Literal["agree", "override"]
    new_kind: VerdictKind | None = None
    note: str = Field(default="", max_length=800)
    by: str = ""
    at: str = ""
    lesson_id: str = ""


class VerdictModel(BaseModel):
    id: str
    kind: VerdictKind
    requested_kind: VerdictKind | None = None
    confidence: float = 0.0
    grounded: bool = False
    safety_valve: bool = False
    safety_valve_reason: str = ""
    created_at: str = ""
    headline: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    claims: list[ClaimModel] = Field(default_factory=list)
    evidence_path_ids: list[str] = Field(default_factory=list)
    feedback: FeedbackModel | None = None


class ActionModel(BaseModel):
    id: str
    kind: ActionKind
    status: ActionStatus
    title: str = ""
    body_md: str = ""
    created_at: str = ""
    verdict_id: str = ""
    verdict_kind: str = ""
    team: str = ""
    slack_channel: str = ""
    on_call: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    outbox_path: str = ""
    delivery: list[str] = Field(default_factory=list)


class MemoryHit(BaseModel):
    lesson_id: str
    text: str = ""
    effect: str = ""
    scope_kind: str = ""
    scope_value: str = ""
    strength: float = 0.0
    uses: int = 0
    why_retrieved: Literal["graph", "vector", "both"] = "graph"
    similarity: float | None = None
    via: str = ""


class DiffSummary(BaseModel):
    baseline_investigation_id: str = ""
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)
    unchanged_findings: int = 0
    new_paths: int = 0
    resolved_paths: int = 0
    changed_paths: int = 0
    current_total_weight: float = 0.0
    previous_total_weight: float = 0.0


class MemoryBrief(BaseModel):
    subjects: list[str] = Field(default_factory=list)
    retrieval: str = "graph + keyword"
    vector_search: bool = False
    lessons: list[MemoryHit] = Field(default_factory=list)
    past_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    diff: DiffSummary = Field(default_factory=DiffSummary)
    note: str = ""


class ChokepointFix(BaseModel):
    rank: int = 0
    kind: str = ""
    label: str = ""
    cost: float = 0.0
    package_id: str = ""
    service_id: str = ""
    edge_from: str = ""
    edge_to: str = ""
    control_type: str = ""
    risk_removed: float = 0.0
    paths_removed: int = 0
    cumulative_risk_removed_pct: float = 0.0
    paths_remaining: int = 0


class SimulationSide(BaseModel):
    paths: int = 0
    total_weight: float = 0.0
    top_score: float = 0.0
    crown_jewels_reachable: list[str] = Field(default_factory=list)


class SimulationResult(BaseModel):
    before: SimulationSide = Field(default_factory=SimulationSide)
    after: SimulationSide = Field(default_factory=SimulationSide)
    paths_removed: int = 0
    weight_removed: float = 0.0
    risk_removed_pct: float = 0.0
    crown_jewels_cut: list[str] = Field(default_factory=list)
    fixes_applied: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    id: str
    goal: str
    mode: str = "live"
    status: RunStatus = "running"
    started_at: str = ""
    ended_at: str = ""
    scan_id: str = ""
    model: str = ""
    preset: str = ""
    steps: int = 0
    verdict_kinds: dict[str, int] = Field(default_factory=dict)
    duration_ms: float = 0.0
    error: str = ""


class InvestigationDetail(BaseModel):
    summary: InvestigationSummary
    phase: Phase | None = None
    steps: list[StepRecord] = Field(default_factory=list)
    paths: list[AttackPathModel] = Field(default_factory=list)
    hypotheses: list[HypothesisModel] = Field(default_factory=list)
    challenges: list[ChallengeModel] = Field(default_factory=list)
    verdicts: list[VerdictModel] = Field(default_factory=list)
    actions: list[ActionModel] = Field(default_factory=list)
    memory_brief: MemoryBrief = Field(default_factory=MemoryBrief)
    lessons_used: list[MemoryHit] = Field(default_factory=list)
    chokepoints: list[ChokepointFix] = Field(default_factory=list)
    chokepoint_baseline_weight: float = 0.0
    simulation: SimulationResult | None = None
    agent_messages: list[dict[str, str]] = Field(default_factory=list)


class CreateInvestigationRequest(BaseModel):
    goal: str = Field(min_length=3, max_length=400)
    preset: str = ""


class CreateInvestigationResponse(BaseModel):
    id: str
    status: RunStatus
    mode: str


# --- feedback, actions, memory ----------------------------------------------

class FeedbackRequest(BaseModel):
    action: Literal["agree", "override"]
    new_kind: VerdictKind | None = None
    note: str = Field(default="", max_length=800)
    by: str = "analyst"


class FeedbackResponse(BaseModel):
    feedback_id: str
    verdict_id: str
    action: str
    lesson: MemoryHit | None = None
    lesson_applies_to: list[str] = Field(default_factory=list)
    message: str = ""


class ActionDecisionResponse(BaseModel):
    action: ActionModel
    message: str = ""


class LessonDetail(BaseModel):
    id: str
    text: str = ""
    scope_kind: str = ""
    scope_value: str = ""
    effect: str = ""
    strength: float = 0.0
    uses: int = 0
    created_at: str = ""
    applies_to: list[GraphNode] = Field(default_factory=list)
    source_feedback: FeedbackModel | None = None
    investigations: list[str] = Field(default_factory=list)


class LessonsResponse(BaseModel):
    lessons: list[LessonDetail] = Field(default_factory=list)
    embeddings: EmbeddingStatus
    note: str = ""


# --- evals -------------------------------------------------------------------

class MethodMetrics(BaseModel):
    method: str
    label: str
    precision_at_10: float = 0.0
    recall: float = 0.0
    decoys_in_top10: int = 0
    fixes_to_90pct: int = 0
    ranked: list[str] = Field(default_factory=list)
    grounded_claim_rate: float | None = None
    mean_tool_calls: float | None = None


class EvalRow(BaseModel):
    finding_id: str
    service_id: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    ground_truth: str
    cvss_rank: int = 0
    kev_rank: int = 0
    chokepoint_verdict: str = ""
    on_attack_path: bool = False
    best_path_score_pct: float = 0.0


class EvalResponse(BaseModel):
    methods: list[MethodMetrics] = Field(default_factory=list)
    rows: list[EvalRow] = Field(default_factory=list)
    investigation_id: str = ""
    exploitable_count: int = 0
    decoy_count: int = 0
    chokepoint_fixes: list[str] = Field(default_factory=list)
    agent_fixes: list[ChokepointFix] = Field(default_factory=list)
    caption: str = ""
    ready: bool = True
    message: str = ""


# --- admin ---------------------------------------------------------------

class SeedRequest(BaseModel):
    scale: int = Field(default=1, ge=1, le=20)


class SeedResponse(BaseModel):
    graph: str
    scale: int
    nodes: int
    relationships: int
    findings: int
    scan_id: str
    seconds: float
    ground_truth_path: str
    indexes: dict[str, str] = Field(default_factory=dict)


class DeltaResponse(BaseModel):
    applied: bool
    scan_id: str
    new_findings: list[str] = Field(default_factory=list)
    new_ingress: list[str] = Field(default_factory=list)
    message: str = ""


# --- codebase scan -----------------------------------------------------------

class ScanUrlRequest(BaseModel):
    url: str
    name: str = ""


class ScanDirectoryRequest(BaseModel):
    path: str
    name: str = ""


class ScanManualRequest(BaseModel):
    filename: str
    name: str = ""



class CodebaseScanResponse(BaseModel):
    ok: bool
    scan_id: str
    project_id: str
    project_name: str
    source_type: str
    source_ref: str
    node_count: int
    edge_count: int
    findings_count: int
    graphify_status: str
    scanner_statuses: dict[str, str] = Field(default_factory=dict)
    summary: str = ""
