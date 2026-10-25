/**
 * 03 Ledger: every tool call, success or failure, with the exact Graph statement and the
 * raw result behind an expandable row.
 */

import { Fragment, useEffect, useRef } from 'react';

import { EmptyState } from '../../components/EmptyState';
import { Stamp } from '../../components/Stamp';
import { compactArgs, ms, stepLabel, truncate } from '../../lib/format';
import type { LedgerRow } from '../../store/useInvestigation';
import { GraphBlock } from './GraphBlock';

interface LedgerProps {
  rows: LedgerRow[];
  selectedId: string | null;
  expandedId: string | null;
  onSelect: (id: string) => void;
  onToggle: (id: string) => void;
}

export function Ledger({ rows, selectedId, expandedId, onSelect, onToggle }: LedgerProps) {
  const bodyRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!selectedId) return;
    const host = bodyRef.current;
    const row = host?.querySelector(`[data-step-id="${selectedId}"]`);
    row?.scrollIntoView({ block: 'nearest' });
  }, [selectedId]);

  if (rows.length === 0) {
    return (
      <div style={{ padding: 'var(--s-3)' }}>
        <EmptyState
          statement="No tool call has been made yet."
          detail="Every call the agents make appears here with its Graph statement, row count and latency."
        />
      </div>
    );
  }

  return (
    <div className="table-scroll" ref={bodyRef} id="ledger-scroll">
      <table className="ledger-table">
        <thead>
          <tr>
            <th scope="col" style={{ width: 44 }}>
              #
            </th>
            <th scope="col" style={{ width: 92 }}>
              Agent
            </th>
            <th scope="col" style={{ width: 170 }}>
              Tool
            </th>
            <th scope="col" style={{ width: 200 }}>
              Args
            </th>
            <th scope="col" className="num">
              Rows
            </th>
            <th scope="col" className="num">
              ms
            </th>
            <th scope="col" className="num">
              Engine
            </th>
            <th scope="col">Summary</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const expanded = expandedId === row.id;
            return (
              <Fragment key={row.id}>
                <tr
                  className="ledger-row"
                  data-step-id={row.id}
                  data-selected={selectedId === row.id ? 'true' : undefined}
                  data-ok={row.ok ? 'true' : 'false'}
                  tabIndex={0}
                  onClick={() => {
                    onSelect(row.id);
                    onToggle(row.id);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelect(row.id);
                      onToggle(row.id);
                    }
                  }}
                >
                  <td>{stepLabel(row.id)}</td>
                  <td className="ledger-agent">{row.agent}</td>
                  <td className="ledger-tool">
                    {row.tool}
                    {row.pending ? ' …' : ''}
                    {!row.ok ? (
                      <>
                        {' '}
                        <Stamp tone="upheld">error</Stamp>
                      </>
                    ) : null}
                  </td>
                  <td className="ledger-args" title={JSON.stringify(row.args)}>
                    {compactArgs(row.args)}
                  </td>
                  <td className="num">{row.pending ? '—' : row.rows}</td>
                  <td className="num">{row.pending ? '—' : ms(row.latency_ms)}</td>
                  <td>{row.pending ? '—' : row.engine}</td>
                  <td className="ledger-summary" title={row.summary}>
                    {row.pending ? 'running' : truncate(row.summary, 180)}
                  </td>
                </tr>
                {expanded ? (
                  <tr className="ledger-detail">
                    <td colSpan={8}>
                      <div style={{ display: 'flex', gap: 'var(--s-3)', flexWrap: 'wrap' }}>
                        <span className="mono-sm">step {row.id}</span>
                        <span className="mono-sm">touched {row.touched_ids.length} node(s)</span>
                        <span className="mono-sm">engine {row.engine}</span>
                      </div>
                      {row.touched_ids.length > 0 ? (
                        <div className="scope-chips" style={{ margin: 'var(--s-2) 0' }}>
                          {row.touched_ids.slice(0, 24).map((id) => (
                            <span className="chip" key={id}>
                              {id}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </td>
                    {row.cypher.length === 0 ? (
                      <p className="mono-sm">This tool ran no Graph statement of its own.</p>
                    ) : (
                      row.cypher.map((statement, index) => (
                        <GraphBlock key={index} statement={statement} index={index} />
                      ))
                    )}
                    <span className="label">Raw result</span>
                    <pre className="raw-json">
                      {row.result ? JSON.stringify(row.result, null, 2) : 'Not stored for this step.'}
                    </pre>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}