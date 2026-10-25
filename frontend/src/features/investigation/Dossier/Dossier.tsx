/** The right pane: five tabs over the same investigation record. */

import { useState } from 'react';

import type {
  ActionModel,
  AttackPathModel,
  ChallengeModel,
  HypothesisModel,
  StepRecord,
  VerdictModel,
} from '../../../api/types';
import { Tabs, type TabSpec } from '../../../components/Tabs';
import { ActionsTab } from './ActionsTab';
import { BlackboardTab } from './BlackboardTab';
import { EntityTab } from './EntityTab';
import { EvidenceTab } from './EvidenceTab';
import { VerdictsTab } from './VerdictsTab';

export type DossierTab = 'verdicts' | 'evidence' | 'blackboard' | 'actions' | 'entity';

interface DossierProps {
  tab: DossierTab;
  onTabChange: (tab: DossierTab) => void;
  verdicts: VerdictModel[];
  selectedVerdictId: string | null;
  activeCitation: string | null;
  onSelectVerdict: (id: string) => void;
  onCitation: (stepId: string | null) => void;
  onFeedbackSaved: (verdictId: string, message: string) => void;
  path: AttackPathModel | null;
  steps: StepRecord[];
  hypotheses: HypothesisModel[];
  challenges: ChallengeModel[];
  onSelectStep: (stepId: string) => void;
  actions: ActionModel[];
  onActionUpdated: (action: ActionModel, message: string) => void;
  entityId: string | null;
}

export function Dossier(props: DossierProps) {
  const {
    tab,
    onTabChange,
    verdicts,
    selectedVerdictId,
    activeCitation,
    onSelectVerdict,
    onCitation,
    onFeedbackSaved,
    path,
    steps,
    hypotheses,
    challenges,
    onSelectStep,
    actions,
    onActionUpdated,
    entityId,
  } = props;

  const tabs: TabSpec[] = [
    { id: 'verdicts', label: 'Verdicts', count: verdicts.length },
    { id: 'evidence', label: 'Evidence' },
    { id: 'blackboard', label: 'Blackboard', count: hypotheses.length },
    { id: 'actions', label: 'Actions', count: actions.length },
    { id: 'entity', label: 'Entity' },
  ];

  return (
    <>
      <Tabs
        tabs={tabs}
        active={tab}
        ariaLabel="Dossier"
        onChange={(id) => onTabChange(id as DossierTab)}
      />
      {tab === 'verdicts' ? (
        <VerdictsTab
          verdicts={verdicts}
          selectedId={selectedVerdictId}
          activeCitation={activeCitation}
          onSelect={onSelectVerdict}
          onCitation={onCitation}
          onFeedbackSaved={onFeedbackSaved}
        />
      ) : null}
      {tab === 'evidence' ? <EvidenceTab path={path} steps={steps} /> : null}
      {tab === 'blackboard' ? (
        <BlackboardTab
          hypotheses={hypotheses}
          challenges={challenges}
          onSelectStep={onSelectStep}
        />
      ) : null}
      {tab === 'actions' ? <ActionsTab actions={actions} onUpdated={onActionUpdated} /> : null}
      {tab === 'entity' ? <EntityTab nodeId={entityId} /> : null}
    </>
  );
}

/** `useState` wrapper so the page does not have to own the tab identity. */
export function useDossierTab(initial: DossierTab = 'verdicts') {
  return useState<DossierTab>(initial);
}
