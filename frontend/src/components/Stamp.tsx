/** Bordered uppercase mono rectangles: verdicts, grounding, outcomes. */

import type { ReactNode } from 'react';

import { Icon } from './icons';

export type StampTone =
  | 'fix_now'
  | 'schedule'
  | 'suppress'
  | 'accept'
  | 'grounded'
  | 'unverified'
  | 'upheld'
  | 'rejected'
  | 'neutral'
  | 'structure';

interface StampProps {
  tone: StampTone;
  children: ReactNode;
  title?: string;
}

export function Stamp({ tone, children, title }: StampProps) {
  return (
    <span className={`stamp stamp-${tone}`} title={title}>
      {tone === 'grounded' ? <Icon name="check" size={11} /> : null}
      {tone === 'unverified' ? <Icon name="warning" size={11} /> : null}
      {children}
    </span>
  );
}

function verdictTone(kind: string): StampTone {
  switch (kind) {
    case 'FIX_NOW':
      return 'fix_now';
    case 'SCHEDULE':
      return 'schedule';
    case 'SUPPRESS':
      return 'suppress';
    case 'ACCEPT':
      return 'accept';
    default:
      return 'neutral';
  }
}

export function VerdictStamp({ kind }: { kind: string }) {
  return <Stamp tone={verdictTone(kind)}>{kind.replace('_', ' ')}</Stamp>;
}

export function GroundingStamp({ grounded }: { grounded: boolean }) {
  return grounded ? (
    <Stamp tone="grounded" title="Every claim cites a step, names only touched nodes, and quotes only numbers that appear in those steps.">
      grounded
    </Stamp>
  ) : (
    <Stamp tone="unverified" title="At least one claim failed the grounding check.">
      unverified
    </Stamp>
  );
}
