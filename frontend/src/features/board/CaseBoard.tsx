/** The Case Board: the naive view, the graph's view, and the way in. */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { api } from '../../api/client';
import type {
  AttackPathModel,
  FindingRow,
  GraphOverviewResponse,
  InvestigationSummary,
} from '../../api/types';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Numeral } from '../../components/Numeral';
import { Panel } from '../../components/Panel';
import { VerdictStamp } from '../../components/Stamp';
import { Table, type Column } from '../../components/Table';
import { clock, count, ms, relativeTime, score } from '../../lib/format';
import { useHotkeys } from '../../lib/hotkeys';
import { useUI } from '../../store/useUI';
import { BoardGraphView } from './GraphView';
import { NaiveView } from './NaiveView';
import { PRESETS, StartPanel } from './StartPanel';
import { CodebaseSelectorModal } from './CodebaseSelectorModal';

export function CaseBoard() {
  const navigate = useNavigate();
  const setNotice = useUI((state) => state.setNotice);
  const notice = useUI((state) => state.notice);
  const loadHealth = useUI((state) => state.loadHealth);

  const [overview, setOverview] = useState<GraphOverviewResponse | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [findingLatency, setFindingLatency] = useState(0);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [paths, setPaths] = useState<AttackPathModel[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [goal, setGoal] = useState(PRESETS[0]?.goal ?? 'Triage the latest scan');
  const [preset, setPreset] = useState('triage');
  const [busy, setBusy] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [adminBusy, setAdminBusy] = useState(false);
  const [selectorOpen, setSelectorOpen] = useState(false);
  const goalRef = useRef<HTMLDivElement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [overviewData, naive, list] = await Promise.all([
        api.overview(),
        api.naiveView(10),
        api.investigations(),
      ]);
      setOverview(overviewData);
      setFindings(naive.findings);
      setFindingLatency(naive.latency_ms);
      setInvestigations(list);
      const done = list.find((item) => item.status === 'done');
      if (done) {
        const detail = await api.investigation(done.id);
        setPaths(detail.paths);
      } else {
        setPaths([]);
      }
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Could not read the graph.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const start = useCallback(async () => {
    if (goal.trim().length < 3) return;
    setBusy(true);
    setStartError(null);
    try {
      const created = await api.startInvestigation(goal.trim(), preset);
      navigate(`/i/${created.id}`);
    } catch (error) {
      setStartError(error instanceof Error ? error.message : 'Could not start the investigation.');
    } finally {
      setBusy(false);
    }
  }, [goal, navigate, preset]);

  const clearData = useCallback(async () => {
    setAdminBusy(true);
    try {
      await api.clearDatabase();
      setNotice({ tone: 'info', text: 'All codebase graph data and findings cleared.' });
      await load();
      await loadHealth();
    } catch (error) {
      setNotice({ tone: 'bad', text: error instanceof Error ? error.message : 'Clear failed.' });
    } finally {
      setAdminBusy(false);
    }
  }, [load, loadHealth, setNotice]);

  const hotkeys = useMemo(
    () => [
      {
        key: '/',
        description: 'Focus the goal field',
        handler: () => goalRef.current?.querySelector('textarea')?.focus(),
      },
    ],
    [],
  );
  useHotkeys(hotkeys);

  const headline = overview?.headline;
  const columns: Column<InvestigationSummary>[] = useMemo(
    () => [
      {
        key: 'id',
        head: 'Id',
        mono: true,
        width: '88px',
        render: (row) => <Link to={`/i/${row.id}`}>{row.id}</Link>,
      },
      { key: 'goal', head: 'Goal', render: (row) => row.goal },
      {
        key: 'status',
        head: 'Status',
        render: (row) => (
          <span className="mono-sm">
            {row.status}
            {row.mode === 'scripted' ? ' · scripted' : ''}
          </span>
        ),
      },
      {
        key: 'verdicts',
        head: 'Verdicts',
        render: (row) => (
          <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {Object.entries(row.verdict_kinds).length === 0 ? (
              <span className="dim">—</span>
            ) : (
              Object.entries(row.verdict_kinds).map(([kind, n]) => (
                <span key={kind} style={{ display: 'inline-flex', gap: 2, alignItems: 'center' }}>
                  <VerdictStamp kind={kind} />
                  <span className="mono-sm">{n}</span>
                </span>
              ))
            )}
          </span>
        ),
      },
      { key: 'steps', head: 'Steps', numeric: true, render: (row) => String(row.steps) },
      { key: 'duration', head: 'Duration', numeric: true, render: (row) => ms(row.duration_ms) },
      {
        key: 'started',
        head: 'Started',
        render: (row) => (
          <span className="mono-sm" title={relativeTime(row.started_at)}>
            {clock(row.started_at)}
          </span>
        ),
      },
    ],
    [],
  );

  const latestDone = investigations.find((item) => item.status === 'done') ?? null;

  return (
    <main className="page">
      <section className="board-pitch" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 'var(--s-4)', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: '300px' }}>
          <h1 className="statement">Stop ranking vulnerabilities. Start cutting attack paths.</h1>
          <p>
            A CVSS 10 in a batch job with no network path is noise. A CVSS 5 in a session library
            between the internet and the card vault is the breach. Three agents coordinate through one
            Graphify security graph to find the difference, then say which fixes cut the most risk.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--s-2)', alignItems: 'center', marginTop: 'var(--s-2)' }}>
          <Button variant="primary" icon="folder" onClick={() => setSelectorOpen(true)}>
            Choose Codebase
          </Button>
          <Button variant="quiet" icon="trash" disabled={adminBusy} onClick={() => void clearData()}>
            Clear Graph
          </Button>
        </div>
      </section>

      {findings.length === 0 && !loading ? (
        <div className="well" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s-3)', padding: 'var(--s-3) var(--s-4)', marginBottom: 'var(--s-3)' }}>
          <div>
            <strong>No active codebase loaded.</strong>
            <span style={{ marginLeft: 'var(--s-2)', color: 'var(--c-fg-dim)' }}>
              Choose a GitHub repo, select a ZIP in <code>data/codebases/</code>, or upload an archive.
            </span>
          </div>
          <Button variant="primary" small icon="folder" onClick={() => setSelectorOpen(true)}>
            Select Codebase
          </Button>
        </div>
      ) : null}

      {loadError ? <ErrorBlock title="Graph unavailable" message={loadError} onRetry={load} /> : null}
      {notice ? (
        <div
          className={notice.tone === 'bad' ? 'error-block' : 'well'}
          role="status"
          style={{ marginBottom: 'var(--s-4)' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-2)' }}>
            <span className="label">{notice.tone === 'bad' ? 'Failed' : 'Notice'}</span>
            <Button
              icon="x"
              small
              variant="quiet"
              onClick={() => setNotice(null)}
              style={{ marginLeft: 'auto' }}
            >
              Dismiss
            </Button>
          </div>
          <p className="error-detail" style={{ marginBottom: 0 }}>
            {notice.text}
          </p>
        </div>
      ) : null}

      <section className="board-headline">
        <Numeral value={count(headline?.open_findings ?? 0)} caption="open findings" />
        <Numeral
          value={count(headline?.internet_reachable_findings ?? 0)}
          caption="internet-reachable"
          tone="structure"
        />
        <Numeral
          value={count(headline?.findings_reaching_crown_jewel ?? 0)}
          caption="reach a crown jewel"
          tone="threat"
        />
        <Numeral value={count(headline?.attack_paths ?? 0)} caption="attack paths" small />
        <Numeral
          value={score(headline?.top_path_score_pct ?? 0)}
          caption="worst path score"
          small
          tone="threat"
        />
      </section>

      <div className="grid-12">
        <div className="board-split">
          <NaiveView
            findings={findings}
            latencyMs={findingLatency}
            loading={loading}
            error={loadError}
            onRetry={load}
          />
          <BoardGraphView
            paths={paths}
            latest={latestDone}
            loading={loading}
            onStart={() => {
              setPreset('triage');
              setGoal(PRESETS[0]?.goal ?? 'Triage the latest scan');
              void start();
            }}
          />
        </div>

        <div className="board-two-thirds">
          <Panel number="04" title="Recent investigations" flush>
            <div className="table-scroll" style={{ maxHeight: 320 }}>
              <Table
                columns={columns}
                rows={investigations}
                getKey={(row) => row.id}
                empty={
                  <div style={{ padding: 'var(--s-3)' }}>
                    <EmptyState
                      statement="No investigation has run yet."
                      detail="Pick a preset and run one; it takes a few seconds in scripted mode."
                    />
                  </div>
                }
              />
            </div>
          </Panel>
        </div>

        <div className="board-third" ref={goalRef}>
          <StartPanel
            goal={goal}
            preset={preset}
            busy={busy}
            error={startError}
            onGoalChange={(next) => {
              setGoal(next);
              setPreset('');
            }}
            onPresetChange={(key, presetGoal) => {
              setPreset(key);
              setGoal(presetGoal);
            }}
            onStart={() => void start()}
          />
        </div>

        <div className="admin-strip">
          <span className="label">Codebase Intake</span>
          <Button icon="folder" small disabled={adminBusy} onClick={() => setSelectorOpen(true)}>
            Choose / Scan Codebase
          </Button>
          <Button icon="trash" small disabled={adminBusy} onClick={() => void clearData()}>
            Clear Graph & Findings
          </Button>
          <span className="mono-sm" style={{ marginLeft: 'auto' }}>
            scans: {overview?.scan_ids.join(' · ') || 'none'} · crown jewels:{' '}
            {overview?.crown_jewels.length ?? 0} · public ingress:{' '}
            {overview?.public_ingress_count ?? 0}
          </span>
        </div>
      </div>

      <CodebaseSelectorModal
        isOpen={selectorOpen}
        onClose={() => setSelectorOpen(false)}
        onScanComplete={(summary) => {
          setNotice({ tone: 'info', text: summary });
          void load();
          void loadHealth();
        }}
      />
    </main>
  );
}
