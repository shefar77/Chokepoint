/** Evals: CVSS-first, KEV/EPSS-first and CHOKEPOINT on planted ground truth. */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../../api/client';
import type { EvalResponse, EvalRow, MethodMetrics } from '../../api/types';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Loading } from '../../components/Loading';
import { Numeral } from '../../components/Numeral';
import { Panel } from '../../components/Panel';
import { Stamp, VerdictStamp } from '../../components/Stamp';
import { Table, type Column } from '../../components/Table';
import { pct, ratio, score } from '../../lib/format';

function MethodColumn({ metrics, highlight }: { metrics: MethodMetrics; highlight: boolean }) {
  return (
    <Panel
      number={metrics.method === 'cvss' ? '01' : metrics.method === 'kev_epss' ? '02' : '03'}
      title={metrics.label}
      right={highlight ? <Stamp tone="structure">this product</Stamp> : null}
    >
      <div className="metric-hero">
        <Numeral
          value={pct(metrics.precision_at_10 * 100, 0)}
          caption="precision at 10"
          small
          tone={highlight ? 'threat' : 'ink'}
        />
      </div>
      <dl className="metric-rows">
        <dt>recall at 20</dt>
        <dd>{pct(metrics.recall * 100, 0)}</dd>
        <dt>decoys in top 10</dt>
        <dd>{metrics.decoys_in_top10}</dd>
        <dt>fixes to cover 90% of path weight</dt>
        <dd>{metrics.fixes_to_90pct >= 30 ? '30+' : metrics.fixes_to_90pct}</dd>
        {metrics.grounded_claim_rate === null ? null : (
          <>
            <dt>claims grounded</dt>
            <dd>{pct(metrics.grounded_claim_rate * 100, 0)}</dd>
          </>
        )}
        {metrics.mean_tool_calls === null ? null : (
          <>
            <dt>mean tool calls per run</dt>
            <dd>{ratio(metrics.mean_tool_calls, 1)}</dd>
          </>
        )}
      </dl>
      <div className="hairline" />
      <span className="label">Top 10 as ranked</span>
      <div className="scope-chips" style={{ marginTop: 4 }}>
        {metrics.ranked.length === 0 ? (
          <span className="dim">nothing ranked</span>
        ) : (
          metrics.ranked.map((finding) => (
            <span className="chip" key={finding}>
              {finding}
            </span>
          ))
        )}
      </div>
    </Panel>
  );
}

export function EvalsPage() {
  const navigate = useNavigate();
  const [data, setData] = useState<EvalResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.evals());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The evaluation could not run.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runTriage = useCallback(async () => {
    setBusy(true);
    try {
      const created = await api.startInvestigation('Triage the latest scan', 'triage');
      navigate(`/i/${created.id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not start an investigation.');
    } finally {
      setBusy(false);
    }
  }, [navigate]);

  const columns: Column<EvalRow>[] = useMemo(
    () => [
      { key: 'id', head: 'Finding', mono: true, width: '76px', render: (row) => row.finding_id },
      { key: 'cve', head: 'CVE', mono: true, render: (row) => row.cve },
      { key: 'service', head: 'Service', mono: true, render: (row) => row.service_id },
      { key: 'cvss', head: 'CVSS', numeric: true, render: (row) => score(row.cvss) },
      { key: 'epss', head: 'EPSS', numeric: true, render: (row) => ratio(row.epss, 3) },
      { key: 'kev', head: 'KEV', render: (row) => (row.kev ? 'yes' : 'no') },
      {
        key: 'truth',
        head: 'Ground truth',
        render: (row) =>
          row.ground_truth === 'exploitable' ? (
            <Stamp tone="fix_now">exploitable</Stamp>
          ) : row.ground_truth === 'decoy' ? (
            <Stamp tone="suppress">decoy</Stamp>
          ) : (
            <span className="dim">unlabelled</span>
          ),
      },
      { key: 'cvss_rank', head: 'CVSS rank', numeric: true, render: (row) => String(row.cvss_rank) },
      { key: 'kev_rank', head: 'KEV rank', numeric: true, render: (row) => String(row.kev_rank) },
      {
        key: 'verdict',
        head: 'CHOKEPOINT',
        render: (row) =>
          row.chokepoint_verdict ? (
            <VerdictStamp kind={row.chokepoint_verdict} />
          ) : (
            <span className="dim">no verdict</span>
          ),
      },
      {
        key: 'path',
        head: 'Best path',
        numeric: true,
        render: (row) => (row.on_attack_path ? score(row.best_path_score_pct) : '—'),
      },
    ],
    [],
  );

  return (
    <main className="page">
      <div className="page-head">
        <h1>Evaluation</h1>
        <p className="muted">
          The same open findings, ranked three ways, measured against labels planted when the estate
          was generated.
        </p>
      </div>

      {error ? <ErrorBlock title="Evaluation failed" message={error} onRetry={load} /> : null}

      {loading && !data ? (
        <Loading what="running the evaluation" />
      ) : !data ? null : (
        <>
          {!data.ready ? (
            <div className="memory-banner">
              <span className="label">CHOKEPOINT column is empty</span>
              <p style={{ marginBottom: 'var(--s-2)' }}>{data.message}</p>
              <Button variant="primary" icon="play" disabled={busy} onClick={() => void runTriage()}>
                Run the triage now
              </Button>
            </div>
          ) : null}

          <div className="evals-columns">
            {data.methods.map((metrics) => (
              <MethodColumn
                key={metrics.method}
                metrics={metrics}
                highlight={metrics.method === 'chokepoint'}
              />
            ))}
          </div>

          <div className="board-headline">
            <Numeral value={String(data.exploitable_count)} caption="exploitable findings" />
            <Numeral value={String(data.decoy_count)} caption="decoys" tone="safe" />
            <Numeral
              value={String(data.agent_fixes.length)}
              caption="fixes in the agent's set"
              small
            />
            <div className="headline-cell" style={{ minWidth: 260 }}>
              <span className="label">Ground-truth chokepoint</span>
              <span className="mono">{data.chokepoint_fixes.join(', ') || '—'}</span>
              <span className="label" style={{ marginTop: 8 }}>
                Agent picked first
              </span>
              <span className="mono">{data.agent_fixes[0]?.label ?? 'nothing yet'}</span>
            </div>
          </div>

          <Panel number="04" title="Per-finding comparison" flush>
            <div className="table-scroll" style={{ maxHeight: 460 }}>
              <Table
                columns={columns}
                rows={data.rows}
                getKey={(row) => row.finding_id}
                empty={
                  <div style={{ padding: 'var(--s-3)' }}>
                    <EmptyState statement="No open findings to compare." />
                  </div>
                }
              />
            </div>
          </Panel>

          <p className="caption">{data.caption}</p>
        </>
      )}
    </main>
  );
}
