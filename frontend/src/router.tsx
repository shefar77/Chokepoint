/** Routes. Five screens, no nesting. */

import { Route, Routes } from 'react-router-dom';

import { CaseBoard } from './features/board/CaseBoard';
import { EvalsPage } from './features/evals/EvalsPage';
import { ExplorerPage } from './features/explorer/ExplorerPage';
import { InvestigationPage } from './features/investigation/InvestigationPage';
import { MemoryPage } from './features/memory/MemoryPage';
import { IntroPage } from './features/Intro';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<CaseBoard />} />
      <Route path="/intro" element={<IntroPage />} />
      <Route path="/i/:id" element={<InvestigationPage />} />
      <Route path="/memory" element={<MemoryPage />} />
      <Route path="/evals" element={<EvalsPage />} />
      <Route path="/explorer" element={<ExplorerPage />} />
      <Route path="*" element={<CaseBoard />} />
    </Routes>
  );
}
