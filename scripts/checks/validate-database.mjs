#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function sqlFiles(root, relative) {
  let entries;
  try { entries = readdirSync(join(root, relative), { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  return entries.flatMap(entry => {
    const path = `${relative}/${entry.name}`;
    return entry.isDirectory() ? sqlFiles(root, path) : entry.name.endsWith('.sql') ? [path] : [];
  }).sort();
}

export function validTimestamp(timestamp) {
  const parts = [timestamp.slice(0, 4), timestamp.slice(4, 6), timestamp.slice(6, 8),
    timestamp.slice(8, 10), timestamp.slice(10, 12), timestamp.slice(12, 14)].map(Number);
  const date = new Date(Date.UTC(parts[0], parts[1] - 1, ...parts.slice(2)));
  return date.getUTCFullYear() === parts[0] && date.getUTCMonth() + 1 === parts[1]
    && date.getUTCDate() === parts[2] && date.getUTCHours() === parts[3]
    && date.getUTCMinutes() === parts[4] && date.getUTCSeconds() === parts[5];
}

// Tokenize SQL so comments, quoted identifiers and literal text are not treated as commands.
function sqlTokens(sql) {
  const tokens = [];
  for (let i = 0; i < sql.length;) {
    if (/\s/.test(sql[i])) { i++; continue; }
    if (sql.startsWith('--', i)) { const end = sql.indexOf('\n', i); i = end < 0 ? sql.length : end; continue; }
    if (sql.startsWith('/*', i)) {
      let depth = 1; i += 2;
      while (i < sql.length && depth) {
        if (sql.startsWith('/*', i)) { depth++; i += 2; }
        else if (sql.startsWith('*/', i)) { depth--; i += 2; }
        else i++;
      }
      continue;
    }
    const start = i;
    const tag = sql.slice(i).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i)?.[0];
    if (tag) {
      const end = sql.indexOf(tag, i + tag.length);
      tokens.push({ kind: 'body', text: sql.slice(i + tag.length, end < 0 ? sql.length : end) });
      i = end < 0 ? sql.length : end + tag.length; continue;
    }
    if (sql[i] === "'" || sql[i] === '"') {
      const quote = sql[i++]; let text = '';
      const escaped = quote === "'" && /(?:^|[^a-z0-9_])e$/i.test(sql.slice(0, start));
      while (i < sql.length) {
        if (sql[i] === quote) {
          if (sql[i + 1] === quote) { text += quote; i += 2; continue; }
          i++; break;
        }
        if (escaped && sql[i] === '\\') { text += sql[i + 1] ?? ''; i += 2; }
        else text += sql[i++];
      }
      tokens.push({ kind: quote === "'" ? 'literal' : 'identifier', text }); continue;
    }
    const word = sql.slice(i).match(/^[a-z_][a-z0-9_$]*/i)?.[0];
    if (word) { tokens.push({ kind: 'word', text: word.toUpperCase() }); i += word.length; }
    else { tokens.push({ kind: 'symbol', text: sql[i++] }); }
  }
  return tokens;
}

export function migrationDataCommands(sql) {
  const violations = new Set();
  const inspect = (tokens, block = false) => {
    const words = tokens.filter(t => t.kind !== 'symbol').map(t => t.kind === 'word' ? t.text : '<QUOTED>');
    const first = words[0];
    // Defining runtime functions/procedures/triggers/rules is schema work, not executing their DML.
    if (!block && first === 'CREATE') {
      const offset = words[1] === 'OR' && words[2] === 'REPLACE' ? 3 : 1;
      if (['FUNCTION', 'PROCEDURE', 'TRIGGER', 'RULE'].includes(words[offset]) || words[offset] === 'CONSTRAINT' && words[offset + 1] === 'TRIGGER') return;
      if ((words.includes('TABLE') || words.includes('MATERIALIZED')) && words.includes('AS') && words.includes('SELECT') && !words.join(' ').includes('WITH NO DATA')) violations.add('CREATE AS SELECT');
      return;
    }
    if (!block && first === 'DO') {
      for (const token of tokens.filter(t => ['body', 'literal'].includes(t.kind))) inspect(sqlTokens(token.text), true);
      return;
    }
    if (!block && !['INSERT', 'UPDATE', 'DELETE', 'MERGE', 'TRUNCATE', 'COPY', 'WITH', 'SELECT', 'CALL', 'REFRESH'].includes(first)) return;
    for (let i = 0; i < words.length; i++) {
      const word = words[i]; const next = words[i + 1];
      if (word === 'INSERT' && next === 'INTO' || word === 'DELETE' && next === 'FROM' || word === 'MERGE' && next === 'INTO') violations.add(word);
      if (word === 'UPDATE' && words[i - 1] !== 'FOR' && !['SET', 'WHERE', 'RETURNING', 'SKIP', 'NOWAIT', 'OF'].includes(next) && next) violations.add(word);
      if (word === 'TRUNCATE' || word === 'CALL' || word === 'REFRESH' && next === 'MATERIALIZED') violations.add(word);
      if (word === 'COPY') {
        let depth = 0;
        for (const token of tokens.slice(tokens.findIndex(t => t.kind === 'word' && t.text === 'COPY') + 1)) {
          if (token.kind === 'symbol' && token.text === '(') depth++;
          if (token.kind === 'symbol' && token.text === ')') depth--;
          if (!depth && token.kind === 'word' && ['FROM', 'TO'].includes(token.text)) {
            if (token.text === 'FROM') violations.add('COPY FROM');
            break;
          }
        }
      }
      if (word === 'SELECT' && words.slice(i + 1).includes('INTO')) violations.add('SELECT INTO');
      if (['SETVAL', 'NEXTVAL'].includes(word)) violations.add(word);
      // Dynamic/procedural calls in executed DO blocks cannot be proven to be schema-only.
      if (block && ['EXECUTE', 'PERFORM'].includes(word)) violations.add(`DO ${word}`);
    }
  };
  let statement = [];
  for (const token of sqlTokens(sql)) {
    if (token.kind === 'symbol' && token.text === ';') {
      const words = statement.filter(t => t.kind === 'word').map(t => t.text);
      // SQL-standard routine bodies can use BEGIN ATOMIC without dollar quoting.
      const routine = /^CREATE (?:OR REPLACE )?(?:FUNCTION|PROCEDURE)\b/.test(words.join(' '));
      const atomic = words.some((word, i) => word === 'BEGIN' && words[i + 1] === 'ATOMIC');
      const depth = words.reduce((n, word) => n + (['BEGIN', 'CASE'].includes(word) ? 1 : word === 'END' ? -1 : 0), 0);
      if (routine && atomic && depth > 0) { statement.push(token); continue; }
      inspect(statement); statement = [];
    }
    else statement.push(token);
  }
  inspect(statement);
  return [...violations];
}

export function validateDatabase({ root = process.cwd(), base = 'origin/dev', exactBase = false } = {}) {
  const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 }).trim();
  // Missing references fail closed; never silently skip history protection.
  const reference = git(['rev-parse', '--verify', `${base}^{commit}`]);
  const ancestor = exactBase ? reference : git(['merge-base', reference, 'HEAD']);
  const baseline = new Set(git(['ls-tree', '-r', '--name-only', ancestor, '--', 'supabase/migrations', 'supabase/seed']).split('\n'));
  const errors = [];
  // Disable rename detection: a rename is a deletion + addition and cannot bypass protection.
  const changes = git(['diff', '--name-status', '--no-renames', ancestor, '--', 'supabase/migrations']).split('\n');
  for (const change of changes) {
    if (!change) continue;
    const [status, path] = change.split('\t');
    if (baseline.has(path) && status !== 'A') errors.push(`${path}: existing migration ${status === 'D' ? 'deleted or renamed' : 'modified'}. Add a new migration instead.`);
  }
  const files = [...sqlFiles(root, 'supabase/migrations'), ...sqlFiles(root, 'supabase/seed/dev'), ...sqlFiles(root, 'supabase/seed/production')];
  const timestamps = new Map();
  const legacy = [];
  const baseMigrationTimes = [...baseline].filter(p => p.startsWith('supabase/migrations/')).map(p => basename(p).match(/^(\d{14})_/)?.[1]).filter(Boolean).sort();
  const latest = baseMigrationTimes.at(-1);
  for (const path of files) {
    const migration = path.startsWith('supabase/migrations/');
    if (migration && !baseline.has(path)) {
      const commands = migrationDataCommands(readFileSync(join(root, path), 'utf8'));
      if (commands.length) errors.push(`${path}: data manipulation (${commands.join(', ')}) belongs in seed files, not migrations. Keep migrations schema-only.`);
    }
    const pattern = migration ? /^(\d{14})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/ : /^(\d{14})_seed_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/;
    const match = basename(path).match(pattern);
    if (!match || !validTimestamp(match[1])) {
      if (baseline.has(path)) { legacy.push(path); continue; }
      errors.push(`${path}: expected a valid YYYYMMDDHHMMSS_${migration ? '' : 'seed_'}description.sql filename (lowercase snake_case).`);
      continue;
    }
    const scope = migration ? 'migrations' : dirname(path);
    const key = `${scope}/${match[1]}`;
    if (timestamps.has(key)) errors.push(`${path}: timestamp duplicates ${timestamps.get(key)} in the same sequence.`);
    timestamps.set(key, path);
    if (migration && !baseline.has(path) && latest && match[1] <= latest) errors.push(`${path}: new migration must sort after baseline migration timestamp ${latest}.`);
  }
  return { errors, legacy, ancestor, checked: files.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const baseIndex = args.indexOf('--base');
    if (baseIndex !== -1 && !args[baseIndex + 1]) throw new Error('--base requires a Git reference');
    const result = validateDatabase({ base: baseIndex === -1 ? process.env.DB_BASE_REF || 'origin/dev' : args[baseIndex + 1], exactBase: args.includes('--exact-base') });
    for (const error of result.errors) console.error(`ERROR: ${error}`);
    if (result.legacy.length) console.log(`Grandfathered ${result.legacy.length} existing SQL filenames; new filenames must follow the timestamp convention.`);
    console.log(`Checked ${result.checked} SQL filenames and migration history against ${result.ancestor}.`);
    process.exitCode = result.errors.length ? 1 : 0;
  } catch (error) { console.error(`Database validation failed: ${error.message}`); process.exitCode = 1; }
}
