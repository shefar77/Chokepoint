/**
 * Hand-authored icon set: 16px grid, 1.5px stroke, square caps, mitre joins.
 * No icon library. Geometry is drawn on whole and half pixels so the strokes
 * stay crisp at 16px.
 */

import type { ReactElement } from 'react';

export type IconName =
  | 'search'
  | 'play'
  | 'check'
  | 'x'
  | 'arrow-right'
  | 'arrow-down'
  | 'link'
  | 'clock'
  | 'memory'
  | 'branch'
  | 'flag'
  | 'copy'
  | 'expand'
  | 'filter'
  | 'reset'
  | 'warning'
  | 'target'
  | 'shield'
  | 'store'
  | 'globe'
  | 'terminal'
  | 'ledger'
  | 'scales'
  | 'folder'
  | 'trash'
  | 'chevron-right';

const GLYPHS: Record<IconName, ReactElement> = {
  search: (
    <>
      <circle cx="6.75" cy="6.75" r="4.25" />
      <path d="M10 10l3.5 3.5" />
    </>
  ),
  play: <path d="M4.5 2.5l8 5.5-8 5.5z" />,
  check: <path d="M2.5 8.5l3.5 3.5 7.5-8" />,
  x: (
    <>
      <path d="M3.5 3.5l9 9" />
      <path d="M12.5 3.5l-9 9" />
    </>
  ),
  'arrow-right': (
    <>
      <path d="M2.5 8h11" />
      <path d="M9.5 4l4 4-4 4" />
    </>
  ),
  'arrow-down': (
    <>
      <path d="M8 2.5v11" />
      <path d="M4 9.5l4 4 4-4" />
    </>
  ),
  link: (
    <>
      <path d="M6.5 9.5l3-3" />
      <path d="M9 4l1.5-1.5a2.8 2.8 0 014 4L13 8" />
      <path d="M7 12l-1.5 1.5a2.8 2.8 0 01-4-4L3 8" />
    </>
  ),
  clock: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <path d="M8 4.5V8l2.5 1.5" />
    </>
  ),
  memory: (
    <>
      <path d="M2.5 5l5.5-2.5L13.5 5 8 7.5z" />
      <path d="M2.5 8.5L8 11l5.5-2.5" />
      <path d="M2.5 11.5L8 14l5.5-2.5" />
    </>
  ),
  branch: (
    <>
      <circle cx="4.5" cy="3.5" r="1.75" />
      <circle cx="4.5" cy="12.5" r="1.75" />
      <circle cx="12" cy="7" r="1.75" />
      <path d="M4.5 5.25v5.5" />
      <path d="M6.25 4.25h3.5A2 2 0 0111.5 5.5" />
    </>
  ),
  flag: (
    <>
      <path d="M4 14V2.5" />
      <path d="M4 3h8l-1.75 3L12 9H4z" />
    </>
  ),
  copy: (
    <>
      <rect x="5.5" y="5.5" width="8" height="8" />
      <path d="M10.5 5.5V2.5h-8v8h3" />
    </>
  ),
  expand: (
    <>
      <path d="M9.5 2.5h4v4" />
      <path d="M6.5 13.5h-4v-4" />
      <path d="M13.5 2.5L9 7" />
      <path d="M2.5 13.5L7 9" />
    </>
  ),
  filter: (
    <>
      <path d="M2.5 3.5h11L9.25 8.5v4.5l-2.5-1.5V8.5z" />
    </>
  ),
  reset: (
    <>
      <path d="M13.5 8a5.5 5.5 0 11-1.9-4.15" />
      <path d="M13.5 2v3.5H10" />
    </>
  ),
  warning: (
    <>
      <path d="M8 2.5l6 11H2z" />
      <path d="M8 6.5v3.25" />
      <path d="M8 11.5v.75" />
    </>
  ),
  target: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <circle cx="8" cy="8" r="2" />
    </>
  ),
  shield: (
    <>
      <path d="M8 2.5l5 2v4c0 3-2.2 4.7-5 5.5-2.8-.8-5-2.5-5-5.5v-4z" />
      <path d="M5.75 8.25L7.5 10l3-3.25" />
    </>
  ),
  store: (
    <>
      <rect x="2.5" y="3.5" width="11" height="9" />
      <path d="M2.5 6.5h11" />
      <path d="M2.5 9.5h11" />
    </>
  ),
  globe: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <path d="M2.5 8h11" />
      <path d="M8 2.5c2 2 2 9 0 11-2-2-2-9 0-11z" />
    </>
  ),
  terminal: (
    <>
      <rect x="2" y="3" width="12" height="10" />
      <path d="M4.5 6.5L6.5 8l-2 1.5" />
      <path d="M8 10h3.5" />
    </>
  ),
  ledger: (
    <>
      <path d="M3 2.5h10v11H3z" />
      <path d="M5.5 5.5h5" />
      <path d="M5.5 8h5" />
      <path d="M5.5 10.5h3" />
    </>
  ),
  folder: (
    <path d="M1.5 3.5h4l1.5 2h6v7h-11.5z" />
  ),
  trash: (
    <>
      <path d="M3 4.5h10M6.5 4.5v-2h3v2M4.5 4.5l.5 9h6l.5-9" />
    </>
  ),
  scales: (
    <>
      <path d="M8 2.5v11" />
      <path d="M3 5.5h10" />
      <path d="M3 5.5L1.5 9.5h3z" />
      <path d="M13 5.5l1.5 4h-3z" />
      <path d="M5.5 13.5h5" />
    </>
  ),
  'chevron-right': <path d="M6 3.5L10.5 8 6 12.5" />,
};

export interface IconProps {
  name: IconName;
  size?: number;
  title?: string;
  className?: string;
}

export function Icon({ name, size = 16, title, className }: IconProps): ReactElement {
  return (
    <svg
      className={className ? `icon ${className}` : 'icon'}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      role={title ? 'img' : 'presentation'}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      {GLYPHS[name]}
    </svg>
  );
}
