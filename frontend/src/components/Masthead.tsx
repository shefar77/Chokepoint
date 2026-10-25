/** Wordmark, caption, navigation and the status strip. */

import { NavLink } from 'react-router-dom';

import type { HealthResponse } from '../api/types';
import { StatusStrip } from './StatusStrip';

const LINKS = [
  { to: '/', label: 'Board' },
  { to: '/memory', label: 'Memory' },
  { to: '/evals', label: 'Evals' },
  { to: '/explorer', label: 'Explorer' },
];

export function Masthead({ health }: { health: HealthResponse | null }) {
  return (
    <header className="masthead">
      <div className="masthead-brand">
        <NavLink to="/" className="wordmark">
          Chokepoint
        </NavLink>
        <span className="wordmark-caption">attack-path triage · Graphify</span>
      </div>
      <StatusStrip health={health} />
      <nav className="nav" aria-label="Sections">
        {LINKS.map((link) => (
          <NavLink key={link.to} to={link.to} end={link.to === '/'}>
            {link.label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}
