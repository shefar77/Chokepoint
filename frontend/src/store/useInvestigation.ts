/**
 * Investigation state: the canonical record from the API, merged with live SSE
 * events while a run is in flight. When the run finishes the record is
 * reloaded so the screen shows exactly what the graph holds.
 */

import { create } from 'zustand';

import { api } from '../api/client';
import { subscribe, type StreamHandle } from '../api/sse';
import type {
  ActionModel,
  AttackPathModel,
  ChallengeModel,
  HypothesisModel,
  InvestigationDetail,
  MemoryHit,
  Phase,
  StepRecord,
  StreamEvent,
  VerdictModel,
} from '../api/types';

export const PHASES: Phase[] = ['memory', 'scout', 'skeptic', 'rebuttal', 'scribe'];

export interface LedgerRow extends StepRecord {
  pending: boolean;
}

export interface AgentLine {
  agent: string;
  text: string;
  seq: number;
}

interface FinishedSummary {
  status: string;
  durationMs: number;
  steps: number;
  verdicts: number;
  paths: number;
  error: string;
}

interface InvestigationState {
  id: string | null;
  loading: boolean;
  error: string | null;
  detail: InvestigationDetail | null;
  running: boolean;
  phase: Phase | null;
  phasesDone: Phase[];
  rows: LedgerRow[];
  paths: AttackPathModel[];
  hypotheses: HypothesisModel[];
  challenges: ChallengeModel[];
  verdicts: VerdictModel[];
  actions: ActionModel[];
  memoryHits: MemoryHit[];
  lines: AgentLine[];
  finished: FinishedSummary | null;
  errors: { message: string; stepId: string; phase: string }[];
  selectedStepId: string | null;
  selectedVerdictId: string | null;
  activeCitationStepId: string | null;
  revealDismissed: boolean;
  load: (id: string) => Promise<void>;
  attach: (id: string) => void;
  detach: () => void;
  selectStep: (stepId: string | null) => void;
  selectVerdict: (verdictId: string | null) => void;
  setActiveCitation: (stepId: string | null) => void;
  dismissReveal: () => void;
  moveSelection: (delta: number) => void;
  replaceAction: (action: ActionModel) => void;
  replaceVerdictFeedback: (verdictId: string) => Promise<void>;
}

let handle: StreamHandle | null = null;

function emptyStep(partial: Partial<LedgerRow>): LedgerRow {
  return {
    id: '',
    n: 0,
    agent: 'scout',
    tool: '',
    args: {},
    cypher: [],
    rows: 0,
    latency_ms: 0,
    summary: '',
    touched_ids: [],
    engine: 'networkx',
    ok: true,
    result: null,
    pending: true,
    ...partial,
  };
}

export const useInvestigation = create<InvestigationState>((set, get) => ({
  id: null,
  loading: false,
  error: null,
  detail: null,
  running: false,
  phase: null,
  phasesDone: [],
  rows: [],
  paths: [],
  hypotheses: [],
  challenges: [],
  verdicts: [],
  actions: [],
  memoryHits: [],
  lines: [],
  finished: null,
  errors: [],
  selectedStepId: null,
  selectedVerdictId: null,
  activeCitationStepId: null,
  revealDismissed: false,

  load: async (id) => {
    set({ loading: true, error: null, id });
    try {
      const detail = await api.investigation(id);
      set((state) => ({
        loading: false,
        detail,
        running: detail.summary.status === 'running',
        phase: detail.phase ?? state.phase,
        rows: detail.steps.length
          ? detail.steps.map((step) => ({ ...step, pending: false }))
          : state.rows,
        paths: detail.paths.length ? detail.paths : state.paths,
        hypotheses: detail.hypotheses.length ? detail.hypotheses : state.hypotheses,
        challenges: detail.challenges.length ? detail.challenges : state.challenges,
        verdicts: detail.verdicts.length ? detail.verdicts : state.verdicts,
        actions: detail.actions.length ? detail.actions : state.actions,
        memoryHits: detail.memory_brief.lessons.length
          ? detail.memory_brief.lessons
          : state.memoryHits,
        lines: detail.agent_messages.length
          ? detail.agent_messages.map((line, index) => ({ ...line, seq: index }))
          : state.lines,
        selectedVerdictId: state.selectedVerdictId ?? detail.verdicts[0]?.id ?? null,
      }));
    } catch (error) {
      set({
        loading: false,
        error: error instanceof Error ? error.message : 'Could not load this investigation.',
      });
    }
  },

  attach: (id) => {
    handle?.close();
    handle = subscribe(
      id,
      (event) => applyEvent(event, set, get),
      (message) => set((state) => ({ errors: [...state.errors, { message, stepId: '', phase: 'stream' }] })),
    );
  },

  detach: () => {
    handle?.close();
    handle = null;
  },

  selectStep: (stepId) => set({ selectedStepId: stepId }),
  selectVerdict: (verdictId) => set({ selectedVerdictId: verdictId }),
  setActiveCitation: (stepId) => set({ activeCitationStepId: stepId }),
  dismissReveal: () => set({ revealDismissed: true }),

  moveSelection: (delta) => {
    const { rows, selectedStepId } = get();
    if (rows.length === 0) return;
    const index = rows.findIndex((row) => row.id === selectedStepId);
    const next = Math.min(rows.length - 1, Math.max(0, (index === -1 ? 0 : index) + delta));
    set({ selectedStepId: rows[next]?.id ?? null });
  },

  replaceAction: (action) =>
    set((state) => ({
      actions: state.actions.map((existing) => (existing.id === action.id ? action : existing)),
    })),

  replaceVerdictFeedback: async (verdictId: string) => {
    const id = get().id;
    if (!id) return;
    try {
      const detail = await api.investigation(id);
      set({
        detail,
        verdicts: detail.verdicts,
        selectedVerdictId: verdictId,
      });
    } catch (error) {
      set({ error: error instanceof Error ? error.message : 'Could not refresh verdicts.' });
    }
  },
}));

type Setter = (
  partial:
    | Partial<InvestigationState>
    | ((state: InvestigationState) => Partial<InvestigationState>),
) => void;

function applyEvent(event: StreamEvent, set: Setter, get: () => InvestigationState): void {
  switch (event.type) {
    case 'run_started':
      set({ running: true, finished: null });
      break;
    case 'phase':
      set((state) => ({
        phase: event.payload.status === 'start' ? event.payload.phase : state.phase,
        phasesDone:
          event.payload.status === 'end' && !state.phasesDone.includes(event.payload.phase)
            ? [...state.phasesDone, event.payload.phase]
            : state.phasesDone,
      }));
      break;
    case 'agent_message':
      set((state) => ({
        lines: [...state.lines, { agent: event.payload.agent, text: event.payload.text, seq: event.seq }],
      }));
      break;
    case 'tool_call':
      set((state) => ({
        rows: [
          ...state.rows,
          emptyStep({
            id: event.payload.step_id,
            n: event.payload.n,
            agent: event.payload.agent,
            tool: event.payload.tool,
            args: event.payload.args,
          }),
        ],
      }));
      break;
    case 'tool_result':
      set((state) => ({
        rows: state.rows.map((row) =>
          row.id === event.payload.step_id
            ? {
                ...row,
                pending: false,
                ok: event.payload.ok,
                summary: event.payload.summary,
                cypher: Array.isArray(event.payload.cypher) ? event.payload.cypher : [],
                rows: event.payload.rows,
                latency_ms: event.payload.latency_ms,
                touched_ids: event.payload.touched_ids,
              }
            : row,
        ),
      }));
      break;
    case 'path_found':
      set((state) => ({
        paths: state.paths.some((path) => path.id === event.payload.path.id)
          ? state.paths.map((path) => (path.id === event.payload.path.id ? event.payload.path : path))
          : [...state.paths, event.payload.path].sort((a, b) => b.score - a.score),
      }));
      break;
    case 'hypothesis':
      set((state) => ({
        hypotheses: state.hypotheses.some((h) => h.id === event.payload.id)
          ? state.hypotheses.map((h) => (h.id === event.payload.id ? { ...h, ...event.payload } : h))
          : [...state.hypotheses, event.payload],
      }));
      break;
    case 'challenge':
      set((state) => ({
        challenges: state.challenges.some((c) => c.id === event.payload.id)
          ? state.challenges
          : [...state.challenges, event.payload],
      }));
      break;
    case 'memory_hit':
      set((state) => ({
        memoryHits: state.memoryHits.some((hit) => hit.lesson_id === event.payload.lesson_id)
          ? state.memoryHits
          : [...state.memoryHits, event.payload],
      }));
      break;
    case 'verdict': {
      // The SSE payload includes raw claims (from tool args) and a grounding report.
      // Merge grounding info into each claim so the UI has grounded/failures.
      const rawClaims = event.payload.claims ?? [];
      const grounding = event.payload.grounding ?? {};
      const groundingClaims = (grounding.claims ?? []) as Array<{
        claim_id: string;
        grounded: boolean;
        failures: string[];
      }>;
      const groundedById = new Map(groundingClaims.map((c) => [c.claim_id, c]));

      const claims: VerdictModel['claims'] = rawClaims.map((claim: any) => ({
        id: claim.id ?? '',
        text: claim.text ?? '',
        cites: claim.cites ?? [],
        node_ids: claim.node_ids ?? [],
        grounded: groundedById.get(claim.id)?.grounded ?? true,
        failures: groundedById.get(claim.id)?.failures ?? [],
      }));

      const incoming: VerdictModel = {
        id: event.payload.id,
        kind: event.payload.kind,
        requested_kind: null,
        confidence: event.payload.confidence,
        grounded: event.payload.grounded,
        safety_valve: event.payload.safety_valve,
        safety_valve_reason: '',
        created_at: event.ts,
        headline: event.payload.headline,
        finding_ids: event.payload.finding_ids,
        services: event.payload.services ?? [],
        claims,
        evidence_path_ids: event.payload.evidence_path_ids,
        feedback: null,
      };
      set((state) => ({
        verdicts: state.verdicts.some((verdict) => verdict.id === incoming.id)
          ? state.verdicts.map((verdict) => (verdict.id === incoming.id ? incoming : verdict))
          : [...state.verdicts, incoming],
        selectedVerdictId: state.selectedVerdictId ?? incoming.id,
      }));
      break;
    }
    case 'action_proposed': {
      const incoming: ActionModel = {
        id: event.payload.id,
        kind: event.payload.kind,
        status: event.payload.status,
        title: event.payload.title,
        body_md: '',
        created_at: event.ts,
        verdict_id: event.payload.verdict_id,
        verdict_kind: '',
        team: event.payload.team,
        slack_channel: event.payload.slack_channel,
        on_call: event.payload.on_call,
        finding_ids: event.payload.finding_ids,
        outbox_path: '',
        delivery: [],
      };
      set((state) => ({
        actions: state.actions.some((action) => action.id === incoming.id)
          ? state.actions
          : [...state.actions, incoming],
      }));
      break;
    }
    case 'error':
      set((state) => ({
        errors: [
          ...state.errors,
          {
            message: event.payload.message,
            stepId: event.payload.step_id,
            phase: event.payload.phase,
          },
        ],
      }));
      break;
    case 'run_finished': {
      set({
        running: false,
        phase: null,
        finished: {
          status: event.payload.status,
          durationMs: event.payload.duration_ms,
          steps: event.payload.steps,
          verdicts: event.payload.verdicts,
          paths: event.payload.paths,
          error: event.payload.error,
        },
      });
      const id = get().id;
      if (id) void get().load(id);
      break;
    }
    default:
      break;
  }
}