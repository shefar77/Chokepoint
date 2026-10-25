/** "The naive view": the scanner queue sorted by CVSS, which is the problem. */

import type { FindingRow } from '../../api/types';
import { EmptyState } from '../../components/EmptyState';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Loading } from '../../components/Loading';
import { Panel } from '../../components/Panel';
import { Stamp } from '../../components/Stamp';
import { Table, type Column } from '../../components/Table';
import { ms, score } from '../../lib/format';

interface NaiveViewProps {
  findings: FindingRow[];
  latencyMs: number;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

const columns: Column<FindingRow>[] = [
  { key: 'id', head: 'Finding', mono: true, render: (row) => row.finding_id, width: '72px' },
  {
    key: 'cve',
    head: 'CVE',
    mono: true,
    render: (row) => (
      <span title={row.summary}>
        {row.cve}
        {row.kev ? (
          <>
            {' '}
            <Stamp tone="fix_now">kev</Stamp>
          </>
        ) : null}
      </span>
    ),
  },
  { key: 'service', head: 'Service', mono: true, render: (row) => row.service_id },
  { key: 'cvss', head: 'CVSS', numeric: true, render: (row) => score(row.cvss) },
  { key: 'epss', head: 'EPSS', numeric: true, render: (row) => row.epss.toFixed(3) },
  {
    key: 'reach',
    head: 'Code reached',
    render: (row) => (row.reachable_code ? 'yes' : 'no'),
  },
];

export function NaiveView({ findings, latencyMs, loading, error, onRetry }: NaiveViewProps) {
  return (
    <Panel
      number="01"
      title="The naive view"
      right={<span className="mono-sm">{ms(latencyMs)}</span>}
      flush
    >
      <div style={{ padding: 'var(--s-3) var(--s-3) 0' }}>
        <p className="mono-sm" style={{ margin: 0 }}>
          Top findings by CVSS, the order a scanner hands you.
        </p>
      </div>
      {error ? (
        <div style={{ padding: 'var(--s-3)' }}>
          <ErrorBlock title="Findings unavailable" message={error} onRetry={onRetry} />
        </div>
      ) : loading ? (
        <div style={{ padding: 'var(--s-3)' }}>
          <Loading what="reading findings" />
        </div>
      ) : (
        <div className="table-scroll" style={{ marginTop: 'var(--s-2)' }}>
          <Table
            columns={columns}
            rows={findings}
            getKey={(row) => row.finding_id}
            empty={
              <div style={{ padding: 'var(--s-3)' }}>
                <EmptyState statement="No open findings in the graph." detail="Reset the seed to regenerate the estate." />
              </div>
            }
          />
        </div>
      )}
    </Panel>
  );
}
