/** 01 Brief: the memory brief, the diff, and the MCP toolbelt. */

import type { McpToolInfo, MemoryBrief, MemoryHit } from '../../api/types';
import type { AgentLine } from '../../store/useInvestigation';
import { EmptyState } from '../../components/EmptyState';
import { Loading } from '../../components/Loading';
import { Rule } from '../../components/Rule';
import { Stamp } from '../../components/Stamp';
import { count, ratio, titleCase } from '../../lib/format';

interface BriefPaneProps {
  brief: MemoryBrief | null;
  liveLessons: MemoryHit[];
  tools: McpToolInfo[];
  toolUsage: Record<string, number>;
  lines: AgentLine[];
  loading: boolean;
  mcpError: string;
}

const GROUP_ORDER = ['read', 'analysis', 'memory', 'blackboard', 'action'];

function LessonCard({ lesson }: { lesson: MemoryHit }) {
  return (
    <div className="lesson">
      <p className="lesson-text">{lesson.text}</p>
      <div className="lesson-meta">
        <span>{lesson.lesson_id}</span>
        <span>
          {lesson.scope_kind}={lesson.scope_value}
        </span>
        <span>{lesson.effect}</span>
        <span>strength {ratio(lesson.strength, 2)}</span>
        <Stamp tone="structure">{lesson.why_retrieved}</Stamp>
        {lesson.similarity === null ? null : <span>cos {ratio(lesson.similarity, 3)}</span>}
      </div>
    </div>
  );
}

export function BriefPane({
  brief,
  liveLessons,
  tools,
  toolUsage,
  lines,
  loading,
  mcpError,
}: BriefPaneProps) {
  const lessons = brief?.lessons?.length ? brief.lessons : (liveLessons ?? []);
  const diff = brief?.diff;
  const safeTools = tools ?? [];
  const grouped = GROUP_ORDER.map((group) => ({
    group,
    tools: safeTools.filter((tool) => tool.group === group),
  })).filter((entry) => entry.tools.length > 0);
  const usedCount = safeTools.filter((tool) => (toolUsage[tool.name] ?? 0) > 0).length;

  return (
    <div className="pane-scroll">
      <section className="brief-section">
        <span className="label">Memory brief</span>
        {loading && !brief ? (
          <Loading what="recalling" />
        ) : lessons.length === 0 ? (
          <EmptyState
            statement="No lesson applies here yet."
            detail="Override a verdict and the next related investigation will cite what you taught it."
          />
        ) : (
          <>
            {lessons.map((lesson) => (
              <LessonCard key={lesson.lesson_id} lesson={lesson} />
            ))}
            <p className="mono-sm" style={{ marginTop: 'var(--s-2)' }}>
              retrieved by {brief?.retrieval ?? 'graph'}
              {brief && !brief.vector_search ? ' · vector memory off' : ''}
            </p>
          </>
        )}
      </section>

      <Rule />

      <section className="brief-section">
        <span className="label">Diff since last run</span>
        {diff && diff.baseline_investigation_id ? (
          <div className="diff-grid">
            <span>baseline</span>
            <span>{diff.baseline_investigation_id}</span>
            <span>new paths</span>
            <span>{diff.new_paths}</span>
            <span>resolved paths</span>
            <span>{diff.resolved_paths}</span>
            <span>changed paths</span>
            <span>{diff.changed_paths}</span>
            <span>new findings</span>
            <span>{diff.new_findings.length}</span>
            <span>resolved findings</span>
            <span>{diff.resolved_findings.length}</span>
            <span>unchanged findings</span>
            <span>{count(diff.unchanged_findings)}</span>
            <span>weight now</span>
            <span>{ratio(diff.current_total_weight)}</span>
            <span>weight before</span>
            <span>{ratio(diff.previous_total_weight)}</span>
          </div>
        ) : (
          <p className="mono-sm">
            No completed investigation to diff against. Everything open counts as new.
          </p>
        )}
      </section>

      <Rule />

      <section className="brief-section">
        <span className="label">
          Toolbelt · {usedCount}/{safeTools.length} used
        </span>
        {mcpError ? (
          <p className="mono-sm">MCP server unreachable: {mcpError}</p>
        ) : safeTools.length === 0 ? (
          <Loading what="discovering tools" />
        ) : (
          <div className="toolbelt">
            {grouped.map((entry) => (
              <div className="toolbelt-group" key={entry.group}>
                <span className="label">{titleCase(entry.group)}</span>
                {entry.tools.map((tool) => {
                  const used = toolUsage[tool.name] ?? 0;
                  return (
                    <span
                      className="tool"
                      key={tool.name}
                      data-used={used > 0 ? 'true' : 'false'}
                      title={`${tool.description}\n\nroles: ${tool.roles.join(', ')}${
                        tool.write ? ' · write tool' : ''
                      }`}
                    >
                      <span className="tool-mark" />
                      {tool.name}
                      {used > 0 ? <span className="tool-count">{used}</span> : null}
                    </span>
                  );
                })}
              </div>
            ))}
            <p className="mono-sm">Tools discovered over MCP at run time, not hard-wired.</p>
          </div>
        )}
      </section>

      <Rule />

      <section className="brief-section">
        <span className="label">What the agents said</span>
        {lines.length === 0 ? (
          <p className="mono-sm">Nothing narrated yet.</p>
        ) : (
          <div className="narration">
            {lines.map((line) => (
              <p className="narration-line" key={line.seq}>
                <span className="narration-agent">{line.agent}</span>
                {line.text}
              </p>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
