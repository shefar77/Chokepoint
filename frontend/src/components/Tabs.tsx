/** A row of mono tabs. The selected one is inked. */

export interface TabSpec {
  id: string;
  label: string;
  count?: number;
}

interface TabsProps {
  tabs: TabSpec[];
  active: string;
  onChange: (id: string) => void;
  ariaLabel: string;
}

export function Tabs({ tabs, active, onChange, ariaLabel }: TabsProps) {
  return (
    <div className="tabs" role="tablist" aria-label={ariaLabel}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          className="tab"
          aria-selected={active === tab.id}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.count === undefined ? null : <span className="tab-count">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}
