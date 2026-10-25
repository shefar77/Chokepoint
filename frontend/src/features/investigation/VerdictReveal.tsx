/** The reveal: the headline number, stated once, with a route to the detail. */

import type { ChokepointFix, SimulationResult } from '../../api/types';
import { Button } from '../../components/Button';
import { pct, score } from '../../lib/format';

interface VerdictRevealProps {
  fixes: ChokepointFix[];
  simulation: SimulationResult | null;
  verdictCount: number;
  topPathScore: number | null;
  onShowSimulation: () => void;
  onDismiss: () => void;
}

export function VerdictReveal({
  fixes,
  simulation,
  verdictCount,
  topPathScore,
  onShowSimulation,
  onDismiss,
}: VerdictRevealProps) {
  if (fixes.length === 0 && !simulation) return null;
  const shown = fixes.slice(0, Math.min(3, fixes.length));
  const last = shown[shown.length - 1];
  const headline = last
    ? `${shown.length} ${shown.length === 1 ? 'fix removes' : 'fixes remove'} ${pct(
        last.cumulative_risk_removed_pct,
      )} of exploitable path risk.`
    : 'The simulation is ready.';

  return (
    <section className="reveal" aria-live="polite">
      <p className="reveal-statement" style={{ margin: 0 }}>
        {headline}
      </p>
      <span className="reveal-figure">
        <span className="numeral-sm">{verdictCount}</span>
        <span className="numeral-caption">verdicts</span>
      </span>
      {topPathScore === null ? null : (
        <span className="reveal-figure">
          <span className="numeral-sm">{score(topPathScore)}</span>
          <span className="numeral-caption">worst path</span>
        </span>
      )}
      <div className="btn-row" style={{ marginLeft: 'auto' }}>
        <Button icon="scales" small onClick={onShowSimulation}>
          Show simulation
        </Button>
        <Button icon="x" small variant="quiet" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
    </section>
  );
}
