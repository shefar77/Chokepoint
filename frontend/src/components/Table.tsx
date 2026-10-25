/** Hairline rows, mono ids, right-aligned numerics, sticky header, no zebra. */

import type { ReactNode } from 'react';

export interface Column<T> {
  key: string;
  head: string;
  render: (row: T) => ReactNode;
  numeric?: boolean;
  mono?: boolean;
  width?: string;
  title?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  getKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  empty?: ReactNode;
  caption?: string;
}

export function Table<T>({
  columns,
  rows,
  getKey,
  onRowClick,
  selectedKey,
  empty,
  caption,
}: TableProps<T>) {
  if (rows.length === 0 && empty) return <>{empty}</>;
  return (
    <table className={onRowClick ? 'table table-clickable' : 'table'}>
      {caption ? <caption className="mono-sm" style={{ textAlign: 'left', paddingBottom: 6 }}>{caption}</caption> : null}
      <thead>
        <tr>
          {columns.map((column) => (
            <th
              key={column.key}
              scope="col"
              style={column.width ? { width: column.width } : undefined}
              className={column.numeric ? 'num' : undefined}
              title={column.title}
            >
              {column.head}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => {
          const key = getKey(row);
          return (
            <tr
              key={key}
              data-selected={selectedKey === key ? 'true' : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={
                onRowClick
                  ? (event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        onRowClick(row);
                      }
                    }
                  : undefined
              }
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={[column.numeric ? 'num' : '', column.mono ? 'id' : '']
                    .filter(Boolean)
                    .join(' ')}
                >
                  {column.render(row)}
                </td>
              ))}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
