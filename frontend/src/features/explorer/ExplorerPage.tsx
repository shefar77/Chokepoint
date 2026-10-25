/** Explorer: the schema, a read-only Cypher editor and the same graph the agents see. */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { api } from '../../api/client';
import type { CypherResponse, SchemaResponse } from '../../api/types';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Loading } from '../../components/Loading';
import { Panel } from '../../components/Panel';
import { GraphView } from '../../graph/GraphView';
import { ms, truncate } from '../../lib/format';
import { useHotkeys } from '../../lib/hotkeys';
import { useGraph } from '../../store/useGraph';

const ID_PATTERN = /^[A-Za-z][A-Za-z0-9_.@:-]{1,80}$/;

function collectIds(response: CypherResponse): string[] {
  const ids = new Set<string>();
  for (const row of response.rows) {
    for (const cell of row) {
      if (typeof cell === 'string' && ID_PATTERN.test(cell)) ids.add(cell);
      if (Array.isArray(cell)) {
        for (const item of cell) {
          if (typeof item === 'string' && ID_PATTERN.test(item)) ids.add(item);
        }
      }
    }
  }
  return [...ids].slice(0, 80);
}

export function ExplorerPage() {
  const [schema, setSchema] = useState<SchemaResponse | null>(null);
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<CypherResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [asGraph, setAsGraph] = useState(false);
  const editorRef = useRef<HTMLTextAreaElement | null>(null);
  const graph = useGraph();

  useEffect(() => {
    api
      .schema()
      .then((response) => {
        setSchema(response);
        if (!query && response.examples[0]) setQuery(response.examples[0].query);
      })
      .catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : 'Could not read the schema.');
      });
    // The schema is read once; the first saved example seeds the editor.
  }, []);

  const run = useCallback(async () => {
    if (query.trim().length < 3) return;
    setBusy(true);
    setError(null);
    try {
      const response = await api.runCypher(query.trim());
      setResult(response);
      if (asGraph) {
        const ids = collectIds(response);
        if (ids.length > 0) void graph.loadSubgraph(ids, 0);
      }
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : 'The query failed.');
    } finally {
      setBusy(false);
    }
  }, [asGraph, graph, query]);

  const hotkeys = useMemo(
    () => [
      { key: '/', description: 'Focus the editor', handler: () => editorRef.current?.focus() },
    ],
    [],
  );
  useHotkeys(hotkeys);

  const lineCount = Math.max(query.split('\n').length, 8);

  return (
    <main className="page">
      <div className="page-head">
        <h1>Explorer</h1>
        <p className="muted">
          Read-only Cypher against the same graph the agents query. Writes, index creation and graph
          copies are rejected; results are capped and the query times out.
        </p>
      </div>

      <div className="explorer">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--gutter)' }}>
          <Panel number="01" title="Schema">
            {!schema ? (
              <Loading what="reading schema" />
            ) : (
              <>
                <span className="label">Labels</span>
                <dl className="schema-list" style={{ marginBottom: 'var(--s-3)' }}>
                  {schema.labels.map((entry) => (
                    <div key={entry.label} style={{ display: 'contents' }}>
                      <dt>{entry.label}</dt>
                      <dd>{entry.count}</dd>
                    </div>
                  ))}
                </dl>
                <span className="label">Relationships</span>
                <dl className="schema-list">
                  {schema.relationship_types.map((entry) => (
                    <div key={entry.type} style={{ display: 'contents' }}>
                      <dt>{entry.type}</dt>
                      <dd>{entry.count}</dd>
                    </div>
                  ))}
                </dl>
              </>
            )}
          </Panel>

          <Panel number="02" title="Saved queries">
            <div className="example-list">
              {(schema?.examples ?? []).map((example) => (
                <button
                  type="button"
                  className="example"
                  key={example.name}
                  onClick={() => setQuery(example.query)}
                >
                  <span className="example-name">{example.name}</span>
                  <span className="example-desc">{example.description}</span>
                </button>
              ))}
            </div>
          </Panel>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--gutter)' }}>
          <Panel
            number="03"
            title="Query"
            right={
              <>
                <label className="layer-toggle">
                  <input
                    type="checkbox"
                    checked={asGraph}
                    onChange={() => setAsGraph((value) => !value)}
                  />
                  show as graph
                </label>
                <Button variant="primary" icon="play" small disabled={busy} onClick={() => void run()}>
                  {busy ? 'Running' : 'Run'}
                </Button>
              </>
            }
          >
            <div className="editor-wrap">
              <div className="editor-gutter" aria-hidden="true">
                {Array.from({ length: lineCount }, (_, index) => (
                  <div key={index}>{index + 1}</div>
                ))}
              </div>
              <textarea
                ref={editorRef}
                className="editor-area"
                spellCheck={false}
                value={query}
                rows={lineCount}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
                    event.preventDefault();
                    void run();
                  }
                }}
                placeholder="MATCH (s:Service) RETURN s.id, s.tier LIMIT 10"
              />
            </div>
            <p className="mono-sm" style={{ marginTop: 'var(--s-2)', marginBottom: 0 }}>
              Ctrl or Cmd + Enter runs the query.
            </p>
          </Panel>

          {error ? <ErrorBlock title="Query rejected" message={error} /> : null}

          <Panel
            number="04"
            title="Result"
            right={
              result ? (
                <span className="mono-sm">
                  {result.row_count} row{result.row_count === 1 ? '' : 's'} · {ms(result.latency_ms)}
                  {result.truncated ? ' · capped' : ''}
                </span>
              ) : null
            }
            flush
          >
            {!result ? (
              <div style={{ padding: 'var(--s-3)' }}>
                <EmptyState
                  statement="No query has run yet."
                  detail="Pick a saved query on the left; the first one is the attack-path query the analysis tools use."
                />
              </div>
            ) : asGraph ? (
              <div style={{ height: 420, display: 'flex', flexDirection: 'column' }}>
                <GraphView
                  nodes={graph.nodes}
                  edges={graph.edges}
                  loading={graph.loading}
                  error={graph.error}
                />
              </div>
            ) : (
              <div className="table-scroll" style={{ maxHeight: 420 }}>
                <table className="table">
                  <thead>
                    <tr>
                      {result.header.map((head) => (
                        <th key={head} scope="col">
                          {head}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((row, index) => (
                      <tr key={index}>
                        {row.map((cell, cellIndex) => (
                          <td key={cellIndex} className="id">
                            {typeof cell === 'object' && cell !== null
                              ? truncate(JSON.stringify(cell), 90)
                              : truncate(String(cell), 90)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </main>
  );
}
