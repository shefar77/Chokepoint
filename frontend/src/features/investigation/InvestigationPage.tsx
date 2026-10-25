/**
 * The investigation screen: 01 Brief, 02 Map with the path ribbon, the dossier
 * and 03 Ledger. Live while the run is in flight, replayed afterwards.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';

import { api } from '../../api/client';
import type { ActionModel, AttackPathModel, McpToolInfo } from '../../api/types';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Legend } from '../../components/Legend';
import { Loading } from '../../components/Loading';
import { SectionHead } from '../../components/Rule';
import { Stamp } from '../../components/Stamp';
import { edgeKey } from '../../graph/cyStyle';
import { GraphView } from '../../graph/GraphView';
import { PathRibbon } from '../../graph/PathRibbon';
import { count, ms, pct, ratio } from '../../lib/format';
import { useHotkeys } from '../../lib/hotkeys';
import { useGraph } from '../../store/useGraph';
import { useInvestigation } from '../../store/useInvestigation';
import { useUI } from '../../store/useUI';
import { BriefPane } from './BriefPane';
import { Dossier, useDossierTab, type DossierTab } from './Dossier/Dossier';
import { Ledger } from './Ledger';
import { PhaseTrack } from './PhaseTrack';
import { VerdictReveal } from './VerdictReveal';

function edgeKeysFor(path: AttackPathModel): string[] {
  return path.edges.map((edge) =>
    edgeKey({ id: '', source: edge.source, target: edge.target, type: edge.type, props: {} }),
  );
}

export function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const setNotice = useUI((state) => state.setNotice);

  const store = useInvestigation();
  const graph = useGraph();
  const [tab, setTab] = useDossierTab('verdicts');
  const [tools, setTools] = useState<McpToolInfo[]>([]);
  const [toolsError, setToolsError] = useState('');
  const [expandedStep, setExpandedStep] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [showSimulation, setShowSimulation] = useState(false);
  const graphRef = useRef<HTMLDivElement | null>(null);
  const filterRef = useRef<HTMLInputElement | null>(null);

  const { load, attach, detach } = store;

  useEffect(() => {
    if (!id) return undefined;
    void load(id);
    attach(id);
    return () => detach();
  }, [id, load, attach, detach]);

  useEffect(() => {
    void graph.loadFocus('attack_surface');
    api
      .mcpTools()
      .then((response) => {
        setTools(response.tools);
        setToolsError(response.error);
      })
      .catch((error: unknown) => {
        setToolsError(error instanceof Error ? error.message : 'MCP tool discovery failed.');
      });
    // The focus view and the tool list are read once per screen.
  }, []);

  const pathNodeIds = useMemo(
    () => store.paths.flatMap((path) => path.nodes.map((node) => node.id)),
    [store.paths],
  );

  useEffect(() => {
    if (pathNodeIds.length > 0) void graph.expand(pathNodeIds);
    // Keyed on the id list, not the array identity, so a re-render is not a refetch.
  }, [pathNodeIds.join(',')]);

  const selectedPath = useMemo(
    () => store.paths.find((path) => path.id === graph.selectedPathId) ?? null,
    [graph.selectedPathId, store.paths],
  );

  const toolUsage = useMemo(() => {
    const usage: Record<string, number> = {};
    for (const row of store.rows) usage[row.tool] = (usage[row.tool] ?? 0) + 1;
    return usage;
  }, [store.rows]);

  const filteredRows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return store.rows;
    return store.rows.filter((row) =>
      [row.tool, row.agent, row.summary, row.id].join(' ').toLowerCase().includes(needle),
    );
  }, [filter, store.rows]);

  const selectStepAndHighlight = useCallback(
    (stepId: string) => {
      store.selectStep(stepId);
      setExpandedStep(stepId);
      const row = store.rows.find((candidate) => candidate.id === stepId);
      if (row && row.touched_ids.length > 0) {
        void graph.expand(row.touched_ids);
        graph.highlight(row.touched_ids, `${row.tool} · ${stepId}`);
      }
    },
    [store.rows],
  );

  useEffect(() => {
    const stepId = store.activeCitationStepId;
    if (!stepId) return;
    const row = store.rows.find((candidate) => candidate.id === stepId);
    if (!row) return;
    store.selectStep(stepId);
    if (row.touched_ids.length > 0) {
      graph.highlight(row.touched_ids, `cited by a verdict claim · ${stepId}`);
    }
  }, [store.activeCitationStepId]);

  const hotkeys = useMemo(
    () => [
      { key: 'g', description: 'Focus the graph', handler: () => graphRef.current?.focus() },
      {
        key: 'l',
        description: 'Focus the ledger',
        handler: () => document.getElementById('ledger-scroll')?.scrollIntoView({ block: 'center' }),
      },
      { key: '/', description: 'Filter the ledger', handler: () => filterRef.current?.focus() },
      { key: 'j', description: 'Next row', handler: () => store.moveSelection(1) },
      { key: 'k', description: 'Previous row', handler: () => store.moveSelection(-1) },
      {
        key: 'Enter',
        description: 'Open the row',
        handler: () => {
          if (store.selectedStepId) selectStepAndHighlight(store.selectedStepId);
        },
      },
      {
        key: 'Esc',
        description: 'Clear',
        handler: () => {
          graph.clearHighlight();
          graph.selectNode(null);
          setExpandedStep(null);
          store.setActiveCitation(null);
        },
      },
    ],
    [store.selectedStepId, selectStepAndHighlight],
  );
  useHotkeys(hotkeys);

  const onActionUpdated = useCallback(
    (action: ActionModel, message: string) => {
      store.replaceAction(action);
      setNotice({ tone: 'info', text: message });
      if (id) void load(id);
    },
    [id, load, setNotice],
  );

  const onFeedbackSaved = useCallback(
    (verdictId: string, message: string) => {
      setNotice({ tone: 'info', text: message });
      void store.replaceVerdictFeedback(verdictId);
    },
    [setNotice],
  );

  if (!id) {
    return (
      <main className="page">
        <EmptyState statement="No investigation id in the address." />
      </main>
    );
  }
  if (store.error && !store.detail) {
    return (
      <main className="page">
        <ErrorBlock title="Investigation unavailable" message={store.error} onRetry={() => void load(id)} />
      </main>
    );
  }
  if (!store.detail) {
    return (
      <main className="page">
        <Loading what="reading investigation" />
      </main>
    );
  }

  const summary = store.detail.summary;
  const simulation = store.detail.simulation;
  const beforeWeight = simulation?.before.total_weight ?? 0;
  const afterWeight = simulation?.after.total_weight ?? 0;
  const widest = Math.max(beforeWeight, afterWeight, 0.0001);
  const scribeDone = store.phasesDone.includes('scribe') || summary.status === 'done';

  return (
    <>
      <div className="small-screen-note">
        <span className="label">Best viewed on a larger screen</span>
        <p style={{ marginBottom: 0 }}>
          The three-pane case file needs at least 900px. The ledger below stays readable.
        </p>
      </div>

      <div className="case">
        <div className="case-topbar">
          <span className="case-goal">{summary.goal}</span>
          <span className="mono-sm">{summary.id}</span>
          <Stamp tone={summary.status === 'done' ? 'suppress' : summary.status === 'failed' ? 'upheld' : 'schedule'}>
            {summary.status}
          </Stamp>
          {summary.mode === 'scripted' ? <Stamp tone="structure">scripted run</Stamp> : null}
          <div className="case-topbar-right">
            <PhaseTrack phase={store.phase} done={store.phasesDone} running={store.running} />
            <span className="mono-sm">
              {count(store.rows.length)} steps · {ms(summary.duration_ms)}
            </span>
          </div>
        </div>

        <aside className="pane pane-left">
          <SectionHead number="01" title="Brief" />
          <BriefPane
            brief={store.detail.memory_brief}
            liveLessons={store.memoryHits}
            tools={tools}
            toolUsage={toolUsage}
            lines={store.lines}
            loading={store.loading}
            mcpError={toolsError}
          />
        </aside>

        <section className="pane pane-center">
          <SectionHead
            number="02"
            title="Map"
            right={(['estate', 'paths', 'controls', 'memory'] as const).map((layer) => (
              <label className="layer-toggle" key={layer}>
                <input
                  type="checkbox"
                  checked={graph.layers[layer]}
                  onChange={() => graph.toggleLayer(layer)}
                />
                {layer}
              </label>
            ))}
          />

          <PathRibbon
            paths={store.paths}
            selectedId={graph.selectedPathId}
            onSelect={(path) => {
              if (!path) {
                graph.selectPath(null, [], []);
                return;
              }
              graph.selectPath(
                path.id,
                path.nodes.map((node) => node.id),
                edgeKeysFor(path),
              );
              setTab('evidence');
              void graph.expand(path.nodes.map((node) => node.id));
            }}
          />

          <div className="graph-shell" ref={graphRef} tabIndex={-1}>
            <GraphView
              nodes={graph.layers.estate ? graph.nodes : []}
              edges={graph.edges}
              highlighted={graph.highlighted}
              pathNodeIds={graph.layers.paths ? graph.pathNodeIds : []}
              pathEdgeKeys={graph.layers.paths ? graph.pathEdgeKeys : []}
              selectedNodeId={graph.selectedNodeId}
              onSelectNode={(nodeId) => {
                graph.selectNode(nodeId);
                if (nodeId) setTab('entity');
              }}
              loading={graph.loading}
              error={graph.error}
              onRetry={() => void graph.loadFocus('attack_surface')}
            />
          </div>

          <div className="scalebar">
            <span>
              {graph.nodes.length} nodes · {graph.edges.length} edges · {ms(graph.latencyMs)}
            </span>
            {graph.highlightReason ? <span>highlight: {graph.highlightReason}</span> : null}
            {graph.truncated ? (
              <span>
                +{graph.hiddenNodes} more hidden
                <Button
                  small
                  variant="quiet"
                  icon="expand"
                  onClick={() => void graph.expand(pathNodeIds)}
                  style={{ marginLeft: 8 }}
                >
                  expand paths
                </Button>
              </span>
            ) : null}
          </div>

          <Legend />

          {simulation ? (
            <div className="riskbar">
              <div className="riskbar-head">
                <span className="label">Risk before → after</span>
                <span className="mono-sm">
                  {simulation.fixes_applied.length} fix(es) simulated on a graph copy ·{' '}
                  {pct(simulation.risk_removed_pct)} removed
                </span>
              </div>
              <div className="riskbar-rows">
                <span className="riskbar-key">before</span>
                <span className="riskbar-track">
                  <span
                    className="riskbar-fill"
                    style={{ width: `${(beforeWeight / widest) * 100}%` }}
                  />
                </span>
                <span className="riskbar-value">{ratio(beforeWeight)}</span>
                <span className="riskbar-key">after</span>
                <span className="riskbar-track">
                  <span
                    className="riskbar-fill"
                    data-side="after"
                    style={{ width: `${(afterWeight / widest) * 100}%` }}
                  />
                </span>
                <span className="riskbar-value">{ratio(afterWeight)}</span>
              </div>
              <p className="mono-sm" style={{ marginTop: 'var(--s-2)', marginBottom: 0 }}>
                {simulation.before.paths} paths → {simulation.after.paths} ·{' '}
                {simulation.crown_jewels_cut.length > 0
                  ? `crown jewels cut off: ${simulation.crown_jewels_cut.join(', ')}`
                  : 'no crown jewel fully cut off by this set'}
              </p>
            </div>
          ) : null}

          {showSimulation && !simulation ? (
            <div className="riskbar">
              <p className="mono-sm" style={{ margin: 0 }}>
                No simulation was run in this investigation.
              </p>
            </div>
          ) : null}
        </section>

        <aside className="pane pane-right">
          <Dossier
            tab={tab}
            onTabChange={(next: DossierTab) => setTab(next)}
            verdicts={store.verdicts}
            selectedVerdictId={store.selectedVerdictId}
            activeCitation={store.activeCitationStepId}
            onSelectVerdict={store.selectVerdict}
            onCitation={(stepId) => store.setActiveCitation(stepId)}
            onFeedbackSaved={onFeedbackSaved}
            path={selectedPath ?? store.paths[0] ?? null}
            steps={store.rows}
            hypotheses={store.hypotheses}
            challenges={store.challenges}
            onSelectStep={selectStepAndHighlight}
            actions={store.actions}
            onActionUpdated={onActionUpdated}
            entityId={graph.selectedNodeId}
          />
        </aside>

        <section className="case-ledger">
          <SectionHead
            number="03"
            title="Ledger"
            right={
              <>
                <input
                  ref={filterRef}
                  type="text"
                  className="input-mono"
                  placeholder="filter tools, agents, summaries"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  style={{ width: 240, height: 22, padding: '0 6px' }}
                />
                <span className="mono-sm">
                  {filteredRows.length}/{store.rows.length}
                </span>
              </>
            }
          />
          {store.errors.length > 0 ? (
            <div style={{ padding: 'var(--s-2) var(--s-3) 0' }}>
              <ErrorBlock
                title={`${store.errors.length} failed call${store.errors.length === 1 ? '' : 's'}`}
                message={store.errors[store.errors.length - 1]?.message ?? ''}
                stepId={store.errors[store.errors.length - 1]?.stepId}
              />
            </div>
          ) : null}
          <Ledger
            rows={filteredRows}
            selectedId={store.selectedStepId}
            expandedId={expandedStep}
            onSelect={store.selectStep}
            onToggle={(stepId) => setExpandedStep(expandedStep === stepId ? null : stepId)}
          />
        </section>
      </div>

      {scribeDone && !store.revealDismissed ? (
        <VerdictReveal
          fixes={store.detail.chokepoints}
          simulation={simulation}
          verdictCount={store.verdicts.length}
          topPathScore={store.paths[0]?.score_pct ?? null}
          onShowSimulation={() => {
            setShowSimulation(true);
            document.querySelector('.riskbar')?.scrollIntoView({ block: 'center' });
          }}
          onDismiss={store.dismissReveal}
        />
      ) : null}

      {store.finished && store.finished.status === 'failed' ? (
        <div className="page" style={{ paddingTop: 0 }}>
          <ErrorBlock
            title="Run failed"
            message={store.finished.error || 'The run ended early. The ledger shows how far it got.'}
            onRetry={() => void load(id)}
          />
        </div>
      ) : null}
    </>
  );
}
