/** Thin typed fetch wrapper. One place that knows the API base path. */

import type {
  ActionDecisionResponse,
  CreateInvestigationResponse,
  DeltaResponse,
  EvalResponse,
  FeedbackResponse,
  GraphOverviewResponse,
  HealthResponse,
  InvestigationDetail,
  InvestigationSummary,
  LessonsResponse,
  McpToolsResponse,
  NaiveViewResponse,
  SchemaResponse,
  SeedResponse,
  SubgraphResponse,
  VerdictKind,
} from './types';

export const API_BASE = '/api';

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
      ...init,
    });
  } catch {
    throw new ApiError(
      `Cannot reach the backend at ${API_BASE}${path}. Is the API container running?`,
      0,
    );
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === 'string') detail = body.detail;
    } catch {
      // A non-JSON error body is fine; the status line is enough.
    }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body === undefined ? '{}' : JSON.stringify(body),
  });
}

export const api = {
  health: () => request<HealthResponse>('/health'),
  overview: () => request<GraphOverviewResponse>('/graph/overview'),
  naiveView: (limit = 10) => request<NaiveViewResponse>(`/graph/findings?limit=${limit}`),
  focus: (kind = 'attack_surface') => request<SubgraphResponse>(`/graph/focus?kind=${kind}`),
  subgraph: (ids: string[], hops = 1) =>
    request<SubgraphResponse>(
      `/graph/subgraph?ids=${encodeURIComponent(ids.join(','))}&hops=${hops}`,
    ),
  mcpTools: () => request<McpToolsResponse>('/mcp/tools'),
  investigations: () => request<InvestigationSummary[]>('/investigations'),
  investigation: (id: string) => request<InvestigationDetail>(`/investigations/${id}`),
  startInvestigation: (goal: string, preset = '') =>
    post<CreateInvestigationResponse>('/investigations', { goal, preset }),
  feedback: (verdictId: string, body: { action: 'agree' | 'override'; new_kind?: VerdictKind; note: string }) =>
    post<FeedbackResponse>(`/verdicts/${verdictId}/feedback`, body),
  approveAction: (actionId: string) => post<ActionDecisionResponse>(`/actions/${actionId}/approve`),
  rejectAction: (actionId: string) => post<ActionDecisionResponse>(`/actions/${actionId}/reject`),
  lessons: () => request<LessonsResponse>('/memory/lessons'),
  evals: () => request<EvalResponse>('/evals/run'),
  schema: () => request<SchemaResponse>('/schema'),
  resetSeed: (scale = 1) => post<SeedResponse>('/seed/reset', { scale }),
  applyDelta: () => post<DeltaResponse>('/scan/delta'),
  scanUrl: (url: string, name = '') => post<any>('/codebases/scan-url', { url, name }),
  scanDirectory: (path: string, name = '') => post<any>('/codebases/scan-directory', { path, name }),
  clearDatabase: () => post<any>('/codebases/clear'),
  manualCodebases: () => request<any[]>('/codebases/manual'),
  scanManual: (filename: string, name = '') => post<any>('/codebases/scan-manual', { filename, name }),
  scanUpload: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/codebases/scan-upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.text();
      throw new ApiError(err, res.status);
    }
    return res.json();
  },
  suggestedCodebases: () => request<any[]>('/codebases/suggested'),
  codebaseScans: () => request<any[]>('/codebases/scans'),
};