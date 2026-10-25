/**
 * Mirror of backend/app/models.py. Field names and SSE payload shapes are
 * identical on both sides; change one, change the other.
 */

export type Phase = 'memory' | 'scout' | 'skeptic' | 'rebuttal' | 'scribe';
export type AgentName = 'scout' | 'skeptic' | 'scribe' | 'orchestrator';
export type VerdictKind = 'FIX_NOW' | 'SCHEDULE' | 'ACCEPT' | 'SUPPRESS';
export type ActionKind = 'ticket' | 'suppress' | 'virtual_patch_request';
export type ActionStatus = 'proposed' | 'approved' | 'executed' | 'rejected';
export type RunStatus = 'running' | 'done' | 'failed';
export type HypothesisStatus = 'open' | 'supported' | 'falsified' | 'weakened';
export type ChallengeOutcome = 'upheld' | 'rejected';
export type WhyRetrieved = 'graph' | 'vector' | 'both';

export interface CapabilityReport {
  procedures_detected: number;
  algorithms: Record<string, string>;
  native_procedures: string[];
}

export interface EmbeddingStatus {
  mode: string;
  model: string;
  dimension: number;
  ready: boolean;
  warning: string;
}

export interface HealthResponse {
  ok: boolean;
  graph_ok?: boolean;
  graph: string;
  node_count: number;
  mcp: boolean;
  mcp_url: string;
  mcp_tools: number;
  agent_mode: string;
  configured_agent_mode: string;
  model: string;
  mode_warning: string;
  embeddings: EmbeddingStatus;
  capabilities: CapabilityReport;
  seed_scale: number;
  outbox_dir: string;
}

export interface GraphNode {
  id: string;
  label: string;
  props: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  props: Record<string, unknown>;
}

export interface SubgraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  hidden_nodes: number;
  latency_ms: number;
}

export interface CrownJewel {
  id: string;
  name: string;
  kind: string;
  classification: string;
  records: number;
}

export interface PublicIngress {
  id: string;
  host: string;
  authn: string;
  waf: boolean;
  service_id: string;
}

export interface Headline {
  open_findings: number;
  internet_reachable_findings: number;
  findings_reaching_crown_jewel: number;
  attack_paths: number;
  crown_jewels_reachable: string[];
  top_path_score_pct: number;
}

export interface GraphOverviewResponse {
  nodes_by_label: Record<string, number>;
  relationships_by_type: Record<string, number>;
  scan_ids: string[];
  public_ingress_count: number;
  public_ingress: PublicIngress[];
  crown_jewels: CrownJewel[];
  headline: Headline;
  latency_ms: number;
}

export interface FindingRow {
  finding_id: string;
  service_id: string;
  cve: string;
  cvss: number;
  epss: number;
  kev: boolean;
  attack_vector: string;
  reachable_code: boolean;
  package: string;
  version: string;
  scan_id: string;
  summary: string;
  tier: number;
}

export interface NaiveViewResponse {
  findings: FindingRow[];
  latency_ms: number;
}

export interface SchemaResponse {
  labels: { label: string; count: number }[];
  relationship_types: { type: string; count: number }[];
  examples: { name: string; description: string; query: string }[];
}

export interface McpToolInfo {
  name: string;
  description: string;
  group: string;
  roles: string[];
  write: boolean;
  input_schema: Record<string, unknown>;
}

export interface McpToolsResponse {
  server: string;
  url: string;
  connected: boolean;
  tools: McpToolInfo[];
  error: string;
}

export interface ScoreComponents {
  exploitability: number;
  exposure: number;
  impact: number;
  length_penalty: number;
  control_discount: number;
  score: number;
}

export interface PathNode {
  id: string;
  label: string;
  name: string;
}

export interface PathEdge {
  source: string;
  target: string;
  type: string;
  authz: string;
}

export interface LiveExploit {
  finding_id: string;
  service_id: string;
  cve: string;
  cvss: number;
  epss: number;
  kev: boolean;
  package: string;
  exploitability: number;
}

export interface AttackPathModel {
  id: string;
  score: number;
  score_pct: number;
  hops: number;
  entry: string;
  entry_ingress: string;
  entry_authn: string;
  target: string;
  target_name: string;
  target_classification: string;
  target_records: number;
  components: ScoreComponents;
  nodes: PathNode[];
  edges: PathEdge[];
  live_exploits: LiveExploit[];
  mitigating_controls: string[];
}

export interface StepRecord {
  id: string;
  n: number;
  agent: AgentName;
  tool: string;
  args: Record<string, unknown>;
  cypher: string[];
  rows: number;
  latency_ms: number;
  summary: string;
  touched_ids: string[];
  engine: string;
  ok: boolean;
  result: Record<string, unknown> | null;
}

export interface CypherResponse {
  header: string[];
  rows: unknown[][];
  row_count: number;
  latency_ms: number;
  truncated: boolean;
  query: string;
}

export interface HypothesisModel {
  id: string;
  agent: string;
  claim: string;
  status: HypothesisStatus;
  confidence: number;
  about_ids: string[];
  based_on_step_ids: string[];
}

export interface ChallengeModel {
  id: string;
  kind: string;
  claim: string;
  outcome: ChallengeOutcome;
  hypothesis_id: string;
  hypothesis_claim: string;
  based_on_step_ids: string[];
}

export interface ClaimModel {
  id: string;
  text: string;
  cites: string[];
  node_ids: string[];
  grounded: boolean;
  failures: string[];
}

export interface FeedbackModel {
  id: string;
  action: 'agree' | 'override';
  new_kind: VerdictKind | null;
  note: string;
  by: string;
  at: string;
  lesson_id: string;
}

export interface VerdictModel {
  id: string;
  kind: VerdictKind;
  requested_kind: VerdictKind | null;
  confidence: number;
  grounded: boolean;
  safety_valve: boolean;
  safety_valve_reason: string;
  created_at: string;
  headline: string;
  finding_ids: string[];
  services: string[];
  claims: ClaimModel[];
  evidence_path_ids: string[];
  feedback: FeedbackModel | null;
}

export interface ActionModel {
  id: string;
  kind: ActionKind;
  status: ActionStatus;
  title: string;
  body_md: string;
  created_at: string;
  verdict_id: string;
  verdict_kind: string;
  team: string;
  slack_channel: string;
  on_call: string[];
  finding_ids: string[];
  outbox_path: string;
  delivery: string[];
}

export interface MemoryHit {
  lesson_id: string;
  text: string;
  effect: string;
  scope_kind: string;
  scope_value: string;
  strength: number;
  uses: number;
  why_retrieved: WhyRetrieved;
  similarity: number | null;
  via: string;
}

export interface DiffSummary {
  baseline_investigation_id: string;
  new_findings: string[];
  resolved_findings: string[];
  unchanged_findings: number;
  new_paths: number;
  resolved_paths: number;
  changed_paths: number;
  current_total_weight: number;
  previous_total_weight: number;
}

export interface MemoryBrief {
  subjects: string[];
  retrieval: string;
  vector_search: boolean;
  lessons: MemoryHit[];
  past_verdicts: Record<string, unknown>[];
  diff: DiffSummary;
  note: string;
}

export interface ChokepointFix {
  rank: number;
  kind: string;
  label: string;
  cost: number;
  package_id: string;
  service_id: string;
  edge_from: string;
  edge_to: string;
  control_type: string;
  risk_removed: number;
  paths_removed: number;
  cumulative_risk_removed_pct: number;
  paths_remaining: number;
}

export interface SimulationSide {
  paths: number;
  total_weight: number;
  top_score: number;
  crown_jewels_reachable: string[];
}

export interface SimulationResult {
  before: SimulationSide;
  after: SimulationSide;
  paths_removed: number;
  weight_removed: number;
  risk_removed_pct: number;
  crown_jewels_cut: string[];
  fixes_applied: Record<string, unknown>[];
}

export interface InvestigationSummary {
  id: string;
  goal: string;
  mode: string;
  status: RunStatus;
  started_at: string;
  ended_at: string;
  scan_id: string;
  model: string;
  preset: string;
  steps: number;
  verdict_kinds: Record<string, number>;
  duration_ms: number;
  error: string;
}

export interface InvestigationDetail {
  summary: InvestigationSummary;
  phase: Phase | null;
  steps: StepRecord[];
  paths: AttackPathModel[];
  hypotheses: HypothesisModel[];
  challenges: ChallengeModel[];
  verdicts: VerdictModel[];
  actions: ActionModel[];
  memory_brief: MemoryBrief;
  lessons_used: MemoryHit[];
  chokepoints: ChokepointFix[];
  chokepoint_baseline_weight: number;
  simulation: SimulationResult | null;
  agent_messages: { agent: string; text: string }[];
}

export interface CreateInvestigationResponse {
  id: string;
  status: RunStatus;
  mode: string;
}

export interface FeedbackResponse {
  feedback_id: string;
  verdict_id: string;
  action: string;
  lesson: MemoryHit | null;
  lesson_applies_to: string[];
  message: string;
}

export interface ActionDecisionResponse {
  action: ActionModel;
  message: string;
}

export interface LessonDetail {
  id: string;
  text: string;
  scope_kind: string;
  scope_value: string;
  effect: string;
  strength: number;
  uses: number;
  created_at: string;
  applies_to: GraphNode[];
  source_feedback: FeedbackModel | null;
  investigations: string[];
}

export interface LessonsResponse {
  lessons: LessonDetail[];
  embeddings: EmbeddingStatus;
  note: string;
}

export interface MethodMetrics {
  method: string;
  label: string;
  precision_at_10: number;
  recall: number;
  decoys_in_top10: number;
  fixes_to_90pct: number;
  ranked: string[];
  grounded_claim_rate: number | null;
  mean_tool_calls: number | null;
}

export interface EvalRow {
  finding_id: string;
  service_id: string;
  cve: string;
  cvss: number;
  epss: number;
  kev: boolean;
  ground_truth: string;
  cvss_rank: number;
  kev_rank: number;
  chokepoint_verdict: string;
  on_attack_path: boolean;
  best_path_score_pct: number;
}

export interface EvalResponse {
  methods: MethodMetrics[];
  rows: EvalRow[];
  investigation_id: string;
  exploitable_count: number;
  decoy_count: number;
  chokepoint_fixes: string[];
  agent_fixes: ChokepointFix[];
  caption: string;
  ready: boolean;
  message: string;
}

export interface SeedResponse {
  graph: string;
  scale: number;
  nodes: number;
  relationships: number;
  findings: number;
  scan_id: string;
  seconds: number;
  ground_truth_path: string;
  indexes: Record<string, string>;
}

export interface DeltaResponse {
  applied: boolean;
  scan_id: string;
  new_findings: string[];
  new_ingress: string[];
  message: string;
}

/* --- SSE events ---------------------------------------------------------- */

interface EventBase {
  ts: string;
  investigation_id: string;
  seq: number;
}

export type StreamEvent =
  | (EventBase & {
      type: 'run_started';
      payload: { goal: string; mode: string; model: string; preset: string; provider: string };
    })
  | (EventBase & { type: 'phase'; payload: { phase: Phase; status: 'start' | 'end' } })
  | (EventBase & { type: 'agent_message'; payload: { agent: AgentName; text: string } })
  | (EventBase & {
      type: 'tool_call';
      payload: {
        step_id: string;
        n: number;
        agent: AgentName;
        tool: string;
        args: Record<string, unknown>;
      };
    })
  | (EventBase & {
      type: 'tool_result';
      payload: {
        step_id: string;
        n: number;
        agent: AgentName;
        tool: string;
        ok: boolean;
        summary: string;
        rows: number;
        latency_ms: number;
        cypher: string[];
        touched_ids: string[];
        engine: string;
      };
    })
  | (EventBase & { type: 'graph_highlight'; payload: { ids: string[]; reason: string } })
  | (EventBase & { type: 'path_found'; payload: { path: AttackPathModel; step_id: string } })
  | (EventBase & { type: 'hypothesis'; payload: HypothesisModel })
  | (EventBase & { type: 'challenge'; payload: ChallengeModel })
  | (EventBase & { type: 'memory_hit'; payload: MemoryHit })
  | (EventBase & {
      type: 'verdict';
      payload: {
        id: string;
        kind: VerdictKind;
        requested_kind: string;
        confidence: number;
        grounded: boolean;
        safety_valve: boolean;
        headline: string;
        finding_ids: string[];
        services: string[];
        claims: ClaimModel[];
        grounding: Record<string, unknown>;
        evidence_path_ids: string[];
      };
    })
  | (EventBase & {
      type: 'action_proposed';
      payload: {
        id: string;
        kind: ActionKind;
        status: ActionStatus;
        title: string;
        verdict_id: string;
        team: string;
        slack_channel: string;
        on_call: string[];
        finding_ids: string[];
      };
    })
  | (EventBase & { type: 'error'; payload: { message: string; step_id: string; phase: string } })
  | (EventBase & {
      type: 'run_finished';
      payload: {
        status: RunStatus;
        duration_ms: number;
        steps: number;
        verdicts: number;
        paths: number;
        error: string;
      };
    });
