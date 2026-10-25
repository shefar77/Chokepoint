/** Memory → Scout → Skeptic → Rebuttal → Scribe on a hairline track. */

import type { Phase } from '../../api/types';
import { PHASES } from '../../store/useInvestigation';

interface PhaseTrackProps {
  phase: Phase | null;
  done: Phase[];
  running: boolean;
}

export function PhaseTrack({ phase, done, running }: PhaseTrackProps) {
  return (
    <div className="phase-track" aria-label="Investigation phases">
      {PHASES.map((name, index) => {
        const state = phase === name && running ? 'active' : done.includes(name) ? 'done' : 'idle';
        return (
          <div key={name} style={{ display: 'flex', alignItems: 'center' }}>
            <div className="phase-step" data-state={state}>
              <span className="phase-name">{name}</span>
            </div>
            {index < PHASES.length - 1 ? <span className="phase-link" /> : null}
          </div>
        );
      })}
    </div>
  );
}
