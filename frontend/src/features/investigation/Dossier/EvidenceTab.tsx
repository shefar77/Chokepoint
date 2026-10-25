/** Evidence: the score breakdown for the selected path and the live-exploit checks. */

import type { AttackPathModel, StepRecord } from '../../../api/types';
import { EmptyState } from '../../../components/EmptyState';
import { Icon } from '../../../components/icons';
import { Stamp } from '../../../components/Stamp';
import { ratio, records, score, titleCase } from '../../../lib/format';

interface EvidenceTabProps {
  path: AttackPathModel | null;
  steps: StepRecord[];
}

interface ExploitCheckData {
  finding_id: string;
  cve: string;
  live_exploit: boolean;
  checks: Record<string, boolean>;
  reasons: string[];
  blocking_controls: string[];
  ingress_authn: string;
}

function exploitChecks(steps: StepRecord[], findingIds: string[]): ExploitCheckData[] {
  const wanted = new Set(findingIds);
  const found: ExploitCheckData[] = [];
  for (const step of steps) {
    if (step.tool !== 'check_exploitability' || !step.result) continue;
    const data = (step.result as { data?: unknown }).data;
    if (!data || typeof data !== 'object') continue;
    const candidate = data as Partial<ExploitCheckData>;
    if (candidate.finding_id && wanted.has(candidate.finding_id)) {
      found.push({
        finding_id: candidate.finding_id,
        cve: candidate.cve ?? '',
        live_exploit: Boolean(candidate.live_exploit),
        checks: candidate.checks ?? {},
        reasons: candidate.reasons ?? [],
        blocking_controls: candidate.blocking_controls ?? [],
        ingress_authn: candidate.ingress_authn ?? '',
      });
    }
  }
  return found;
}

export function EvidenceTab({ path, steps }: EvidenceTabProps) {
  if (!path) {
    return (
      <div className="pane-scroll">
        <EmptyState
          statement="No path selected."
          detail="Pick a path in the ribbon above the map to see how its score was built."
        />
      </div>
    );
  }
  const components = path.components;
  const checks = exploitChecks(
    steps,
    path.live_exploits.map((exploit) => exploit.finding_id),
  );

  return (
    <div className="pane-scroll">
      <span className="label">Score breakdown</span>
      <p className="mono-sm">
        {path.entry} to {path.target} · {path.hops} hops · entry authn {path.entry_authn || '—'}
      </p>
      <div className="breakdown">
        <span className="breakdown-key">exploitability (0.45 epss + 0.25 cvss/10 + 0.30 kev)</span>
        <span className="breakdown-value">{ratio(components.exploitability)}</span>
        <span className="breakdown-key">exposure (ingress authn)</span>
        <span className="breakdown-value">{ratio(components.exposure)}</span>
        <span className="breakdown-key">
          impact ({path.target_classification || 'internal'}, {records(path.target_records)} records)
        </span>
        <span className="breakdown-value">{ratio(components.impact)}</span>
        <span className="breakdown-key">length penalty (0.92 ^ (hops - 3))</span>
        <span className="breakdown-value">{ratio(components.length_penalty)}</span>
        <span className="breakdown-key">control discount (0.5 per control on path)</span>
        <span className="breakdown-value">{ratio(components.control_discount)}</span>
        <span className="breakdown-key breakdown-total">score times 100</span>
        <span className="breakdown-value breakdown-total">{score(path.score_pct)}</span>
      </div>

      {path.mitigating_controls.length > 0 ? (
        <>
          <span className="label">Controls on this path</span>
          <ul className="checklist" style={{ marginBottom: 'var(--s-3)' }}>
            {path.mitigating_controls.map((control) => (
              <li className="check" key={control}>
                <Icon name="shield" size={13} />
                <span className="check-reason">{control}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <span className="label">Live exploits on this path</span>
      {path.live_exploits.length === 0 ? (
        <p className="mono-sm">None recorded for this path.</p>
      ) : (
        <ul className="checklist" style={{ marginBottom: 'var(--s-3)' }}>
          {path.live_exploits.map((exploit) => (
            <li className="check" key={exploit.finding_id}>
              <Icon name="target" size={13} />
              <span>
                <span className="mono">{exploit.finding_id}</span> {exploit.cve} on{' '}
                {exploit.service_id}
                <div className="check-reason">
                  cvss {score(exploit.cvss)} · epss {ratio(exploit.epss, 3)}
                  {exploit.kev ? ' · kev' : ''} · {exploit.package} · exploitability{' '}
                  {ratio(exploit.exploitability)}
                </div>
              </span>
            </li>
          ))}
        </ul>
      )}

      <span className="label">Exploitability checks</span>
      {checks.length === 0 ? (
        <p className="mono-sm">
          No check_exploitability step covers these findings yet. The Scout runs one before claiming
          a finding matters.
        </p>
      ) : (
        checks.map((check) => (
          <div key={check.finding_id} style={{ marginBottom: 'var(--s-3)' }}>
            <div
              style={{ display: 'flex', gap: 'var(--s-2)', alignItems: 'center', marginBottom: 4 }}
            >
              <span className="mono">{check.finding_id}</span>
              <Stamp tone={check.live_exploit ? 'fix_now' : 'suppress'}>
                {check.live_exploit ? 'live exploit' : 'not live'}
              </Stamp>
              {check.ingress_authn ? (
                <span className="mono-sm">ingress authn {check.ingress_authn}</span>
              ) : null}
            </div>
            <ul className="checklist">
              {Object.entries(check.checks).map(([name, value]) => (
                <li className="check" key={name}>
                  <Icon name={value ? 'check' : 'x'} size={13} />
                  <span>{titleCase(name)}</span>
                </li>
              ))}
            </ul>
            <ul className="checklist" style={{ marginTop: 4 }}>
              {check.reasons.map((reason) => (
                <li className="check" key={reason}>
                  <Icon name="chevron-right" size={13} />
                  <span className="check-reason">{reason}</span>
                </li>
              ))}
            </ul>
            {check.blocking_controls.length > 0 ? (
              <p className="mono-sm">blocked by {check.blocking_controls.join('; ')}</p>
            ) : null}
          </div>
        ))
      )}
    </div>
  );
}
