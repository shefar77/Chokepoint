/**
 * Minimal Cypher tinting: keywords, functions, parameters, strings and
 * comments. Four tones in the ink palette, not a rainbow.
 */

const KEYWORDS = [
  'MATCH', 'OPTIONAL', 'WHERE', 'RETURN', 'WITH', 'UNWIND', 'ORDER', 'BY', 'LIMIT', 'SKIP',
  'CREATE', 'MERGE', 'SET', 'DELETE', 'DETACH', 'CALL', 'YIELD', 'AS', 'AND', 'OR', 'NOT',
  'IN', 'DISTINCT', 'ASC', 'DESC', 'ON', 'INDEX', 'FOR', 'OPTIONS', 'VECTOR', 'CASE', 'WHEN',
  'THEN', 'ELSE', 'END', 'TRUE', 'FALSE', 'NULL', 'IS', 'COUNT', 'EXISTS',
];

const FUNCTIONS = [
  'collect', 'coalesce', 'labels', 'type', 'nodes', 'relationships', 'length', 'all', 'any',
  'none', 'size', 'toLower', 'toUpper', 'vecf32', 'properties', 'count', 'startNode', 'endNode',
  'keys', 'range', 'head', 'last',
];

export interface Token {
  text: string;
  kind: 'kw' | 'fn' | 'param' | 'str' | 'comment' | 'plain';
}

// Written as one literal rather than assembled from strings: the alternation
// needs backslashes, and building it by concatenation invites exactly the
// double-escaping bug that makes the whole module throw on load.
// Groups, in order: line comment, single-quoted string, $parameter, word.
const PATTERN = /(\/\/[^\n]*)|('(?:[^'\\]|\\.)*')|(\$[A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_.]*)/g;

export function tintCypher(source: string): Token[] {
  const tokens: Token[] = [];
  let cursor = 0;
  for (const match of source.matchAll(PATTERN)) {
    const index = match.index ?? 0;
    if (index > cursor) tokens.push({ text: source.slice(cursor, index), kind: 'plain' });
    const [raw, comment, str, param, word] = match;
    if (comment) tokens.push({ text: raw, kind: 'comment' });
    else if (str) tokens.push({ text: raw, kind: 'str' });
    else if (param) tokens.push({ text: raw, kind: 'param' });
    else if (word && KEYWORDS.includes(word.toUpperCase()) && word === word.toUpperCase()) {
      tokens.push({ text: raw, kind: 'kw' });
    } else if (word && FUNCTIONS.includes(word)) {
      tokens.push({ text: raw, kind: 'fn' });
    } else {
      tokens.push({ text: raw, kind: 'plain' });
    }
    cursor = index + raw.length;
  }
  if (cursor < source.length) tokens.push({ text: source.slice(cursor), kind: 'plain' });
  return tokens;
}

export const TOKEN_CLASS: Record<Token['kind'], string> = {
  kw: 'cy-kw',
  fn: 'cy-fn',
  param: 'cy-param',
  str: 'cy-str',
  comment: 'cy-comment',
  plain: '',
};
