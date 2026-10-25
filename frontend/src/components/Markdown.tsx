/**
 * A deliberately small Markdown renderer: headings, lists, fenced and inline
 * code, bold, rules and paragraphs. Enough for a ticket body, no dependency.
 */

import type { ReactNode } from 'react';

function inline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let cursor = 0;
  let index = 0;
  for (const match of text.matchAll(pattern)) {
    const at = match.index ?? 0;
    if (at > cursor) nodes.push(text.slice(cursor, at));
    const token = match[0];
    if (token.startsWith('**')) {
      nodes.push(<strong key={`${keyPrefix}-b${index}`}>{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(<code key={`${keyPrefix}-c${index}`}>{token.slice(1, -1)}</code>);
    }
    cursor = at + token.length;
    index += 1;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

export function Markdown({ source }: { source: string }) {
  if (!source.trim()) {
    return <p className="mono-sm">No body was written for this action.</p>;
  }
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let listItems: string[] = [];
  let fence: string[] | null = null;
  let paragraph: string[] = [];

  const flushList = () => {
    if (listItems.length === 0) return;
    blocks.push(
      <ul key={`ul-${blocks.length}`}>
        {listItems.map((item, index) => (
          <li key={index}>{inline(item, `li-${blocks.length}-${index}`)}</li>
        ))}
      </ul>,
    );
    listItems = [];
  };
  const flushParagraph = () => {
    if (paragraph.length === 0) return;
    const text = paragraph.join(' ');
    blocks.push(<p key={`p-${blocks.length}`}>{inline(text, `p-${blocks.length}`)}</p>);
    paragraph = [];
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith('```')) {
      if (fence) {
        blocks.push(<pre key={`pre-${blocks.length}`}>{fence.join('\n')}</pre>);
        fence = null;
      } else {
        flushParagraph();
        flushList();
        fence = [];
      }
      continue;
    }
    if (fence) {
      fence.push(raw);
      continue;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }
    if (line.startsWith('### ')) {
      flushParagraph();
      flushList();
      blocks.push(<h3 key={`h3-${blocks.length}`}>{inline(line.slice(4), `h3-${blocks.length}`)}</h3>);
      continue;
    }
    if (line.startsWith('## ')) {
      flushParagraph();
      flushList();
      blocks.push(<h2 key={`h2-${blocks.length}`}>{inline(line.slice(3), `h2-${blocks.length}`)}</h2>);
      continue;
    }
    if (line.startsWith('# ')) {
      flushParagraph();
      flushList();
      blocks.push(<h3 key={`h1-${blocks.length}`}>{inline(line.slice(2), `h1-${blocks.length}`)}</h3>);
      continue;
    }
    if (line.trim() === '---') {
      flushParagraph();
      flushList();
      blocks.push(<div className="hairline" key={`hr-${blocks.length}`} />);
      continue;
    }
    if (/^[-*] /.test(line.trim())) {
      flushParagraph();
      listItems.push(line.trim().slice(2));
      continue;
    }
    paragraph.push(line.trim());
  }
  flushParagraph();
  flushList();
  if (fence) blocks.push(<pre key={`pre-${blocks.length}`}>{fence.join('\n')}</pre>);

  return <div className="md">{blocks}</div>;
}
