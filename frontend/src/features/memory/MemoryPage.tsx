/** Memory: what the analyst taught the system, and what it is linked to. */

import { useCallback, useEffect, useMemo, useState } from 'react';

import { api } from '../../api/client';
import type { LessonDetail, LessonsResponse } from '../../api/types';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Loading } from '../../components/Loading';
import { Panel } from '../../components/Panel';
import { Stamp } from '../../components/Stamp';
import { Table, type Column } from '../../components/Table';
import { GraphView } from '../../graph/GraphView';
import { clock, ratio } from '../../lib/format';
import { useGraph } from '../../store/useGraph';

export function MemoryPage() {
  const [data, setData] = useState<LessonsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const graph = useGraph();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.lessons());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not read the memory layer.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const selected = useMemo(
    () => data?.lessons.find((lesson) => lesson.id === selectedId) ?? null,
    [data, selectedId],
  );

  useEffect(() => {
    if (!selected) return;
    const ids = [selected.id, ...selected.applies_to.slice(0, 20).map((node) => node.id)];
    void graph.loadSubgraph(ids, 1);
    // The neighbourhood is reloaded whenever a different lesson is selected.
  }, [selected?.id]);

  const columns: Column<LessonDetail>[] = useMemo(
    () => [
      { key: 'id', head: 'Lesson', mono: true, width: '76px', render: (row) => row.id },
      { key: 'text', head: 'What it learned', render: (row) => row.text },
      {
        key: 'scope',
        head: 'Scope',
        render: (row) => (
          <span className="scope-chips">
            <span className="chip">{row.scope_kind}</span>
            <span className="chip">{row.scope_value}</span>
          </span>
        ),
      },
      {
        key: 'effect',
        head: 'Effect',
        render: (row) => (
          <Stamp tone={row.effect === 'upgrade' ? 'upheld' : 'accept'}>{row.effect}</Stamp>
        ),
      },
      { key: 'strength', head: 'Strength', numeric: true, render: (row) => ratio(row.strength, 2) },
      { key: 'uses', head: 'Uses', numeric: true, render: (row) => String(row.uses) },
      {
        key: 'applies',
        head: 'Applies to',
        numeric: true,
        render: (row) => String(row.applies_to.length),
      },
      {
        key: 'source',
        head: 'Taught by',
        render: (row) =>
          row.source_feedback ? (
            <span className="mono-sm" title={row.source_feedback.note}>
              {row.source_feedback.by} · {clock(row.source_feedback.at)}
            </span>
          ) : (
            <span className="dim">—</span>
          ),
      },
    ],
    [],
  );

  return (
    <main className="page">
      <div className="page-head">
        <h1>Memory</h1>
        <p className="muted">
          Every analyst override becomes a lesson in the same graph as the estate, so the next
          investigation can walk from a service to what you decided about its neighbourhood.
        </p>
      </div>

      <div className="memory-banner">
        <span className="label">How retrieval works</span>
        <p style={{ marginBottom: 0 }}>{data?.note ?? 'Reading the memory layer.'}</p>
        {data ? (
          <p className="mono-sm" style={{ marginBottom: 0 }}>
            embeddings: {data.embeddings.mode}
            {data.embeddings.model ? ` · ${data.embeddings.model}` : ''} · dimension{' '}
            {data.embeddings.dimension} · {data.embeddings.ready ? 'ready' : 'not loaded'}
          </p>
        ) : null}
      </div>

      {error ? <ErrorBlock title="Memory unavailable" message={error} onRetry={load} /> : null}

      <div className="memory-split">
        <Panel number="01" title="Lessons" flush>
          {loading && !data ? (
            <div style={{ padding: 'var(--s-3)' }}>
              <Loading what="reading lessons" />
            </div>
          ) : (
            <div className="table-scroll">
              <Table
                columns={columns}
                rows={data?.lessons ?? []}
                getKey={(row) => row.id}
                selectedKey={selectedId}
                onRowClick={(row) => setSelectedId(row.id)}
                empty={
                  <div style={{ padding: 'var(--s-3)' }}>
                    <EmptyState
                      statement="Nothing has been learned yet."
                      detail="Override a verdict on an investigation with a reason, and the lesson appears here with the nodes it applies to."
                    />
                  </div>
                }
              />
            </div>
          )}
        </Panel>

        <Panel
          number="02"
          title="Neighbourhood"
          right={selected ? <span className="mono-sm">{selected.id}</span> : null}
          flush
        >
          {selected ? (
            <>
              <div style={{ height: 320, display: 'flex', flexDirection: 'column' }}>
                <GraphView
                  nodes={graph.nodes}
                  edges={graph.edges}
                  highlighted={[selected.id]}
                  loading={graph.loading}
                  error={graph.error}
                />
              </div>
              <div style={{ padding: 'var(--s-3)' }}>
                <span className="label">Applies to</span>
                <div className="scope-chips" style={{ marginBottom: 'var(--s-3)' }}>
                  {selected.applies_to.length === 0 ? (
                    <span className="dim">no nodes linked</span>
                  ) : (
                    selected.applies_to.map((node) => (
                      <span className="chip" key={node.id} title={node.label}>
                        {node.id}
                      </span>
                    ))
                  )}
                </div>
                {selected.source_feedback ? (
                  <>
                    <span className="label">Analyst note</span>
                    <p>{selected.source_feedback.note}</p>
                  </>
                ) : null}
                <span className="label">Used by</span>
                <div className="scope-chips">
                  {selected.investigations.length === 0 ? (
                    <span className="dim">not used in an investigation yet</span>
                  ) : (
                    selected.investigations.map((investigation) => (
                      <span className="chip" key={investigation}>
                        {investigation}
                      </span>
                    ))
                  )}
                </div>
              </div>
            </>
          ) : (
            <div style={{ padding: 'var(--s-3)' }}>
              <EmptyState
                statement="Select a lesson."
                detail="The map shows the lesson node and everything it applies to."
              />
            </div>
          )}
        </Panel>
      </div>
    </main>
  );
}
