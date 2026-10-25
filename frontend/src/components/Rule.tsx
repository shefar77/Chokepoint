/** Hairline dividers and numbered section heads. */

import type { ReactNode } from 'react';

export function Rule({ strong = false }: { strong?: boolean }) {
  return <div className={strong ? 'hairline-strong' : 'hairline'} />;
}

interface SectionHeadProps {
  number: string;
  title: string;
  right?: ReactNode;
}

export function SectionHead({ number, title, right }: SectionHeadProps) {
  return (
    <div className="pane-head">
      <span className="section-number">{number}</span>
      <span className="label">{title}</span>
      {right ? <span className="panel-head-right">{right}</span> : null}
    </div>
  );
}
