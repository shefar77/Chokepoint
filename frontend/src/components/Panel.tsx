/** A bordered container with a numbered head. The only box in the system. */

import type { CSSProperties, ReactNode } from 'react';

interface PanelProps {
  number?: string;
  title: string;
  right?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  style?: CSSProperties;
}

export function Panel({ number, title, right, children, flush = false, className, style }: PanelProps) {
  return (
    <section className={className ? `panel ${className}` : 'panel'} style={style}>
      <header className="panel-head">
        {number ? <span className="section-number">{number}</span> : null}
        <h2 className="label">{title}</h2>
        {right ? <div className="panel-head-right">{right}</div> : null}
      </header>
      <div className={flush ? 'panel-body-flush' : 'panel-body'}>{children}</div>
    </section>
  );
}
