// L2 grep output filter + policy-file guards. Imports the real lib (Node 24 strips the
// types), unlike the older tests that re-implement the logic.
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { filterGrepOutput, layer2Mode, permissionSystemActive, PERMISSION_SYSTEM_SERVICES, policyFileError, readPolicyForUpdate } from '../../lib/guard-lib.ts';

let pass = 0, fail = 0;
function check(name, cond) { if (cond) pass++; else { fail++; console.log('FAIL:', name); } }

const denied = new Set(['.env', 'conf/server.pem', 'odd-name-3-x.txt']);
const isDenied = (p) => denied.has(p);

const out = [
  'src/app.ts:12: const key = process.env.KEY',
  '.env:1: KEY=sk-live-123',
  '.env-2- # comment',
  'conf/server.pem:1: -----BEGIN PRIVATE KEY-----',
  '--',
  'src/app.ts-13- return key',
  'odd-name-3-x.txt:4: secret',
  '[Showing first 100 matches]',
].join('\n');
const r = filterGrepOutput(out, isDenied);

check('keeps allowed match line', r.text.includes('src/app.ts:12:'));
check('keeps allowed context line', r.text.includes('src/app.ts-13-'));
check('drops denied match line', !r.text.includes('sk-live-123'));
check('drops denied context line', !r.text.includes('.env-2-'));
check('drops nested denied file', !r.text.includes('BEGIN PRIVATE KEY'));
check('drops path containing -N- pattern', !r.text.includes('odd-name-3-x.txt'));
check('keeps separators and notices', r.text.includes('--') && r.text.includes('[Showing first 100 matches]'));
check('counts removed lines', r.removedLines === 4);
check('lists removed files once', r.removedFiles.length === 3);
check('no-op when nothing denied', filterGrepOutput(out, () => false).text === out);

const dir = join(tmpdir(), `pi-secure-it-test-${process.pid}`);
mkdirSync(dir, { recursive: true });
const good = join(dir, 'good.json'), bad = join(dir, 'bad.json');
writeFileSync(good, '{"filesystem":{"allowWrite":["."]}}');
writeFileSync(bad, '{"filesystem":{"allowWrite":[".", "~/.cache",]}}');
check('policyFileError: valid file', policyFileError(good) === null);
check('policyFileError: absent file', policyFileError(join(dir, 'none.json')) === null);
check('policyFileError: trailing comma reported', typeof policyFileError(bad) === 'string');
check('readPolicyForUpdate: absent file is empty', Object.keys(readPolicyForUpdate(join(dir, 'none.json'))).length === 0);
let threw = false;
try { readPolicyForUpdate(bad); } catch { threw = true; }
check('readPolicyForUpdate: refuses to overwrite unparseable file', threw);
rmSync(dir, { recursive: true, force: true });

// Layer 2 role detection (ADR-011)
const ctxFor = (id) => ({ sessionManager: { getSessionId: () => id } });
const store = { [PERMISSION_SYSTEM_SERVICES]: new Map([['s1', {}]]) };
check('detects pi-permission-system for this session', permissionSystemActive(ctxFor('s1'), store));
check('other session is not detected', !permissionSystemActive(ctxFor('s2'), store));
check('no service map: not detected', !permissionSystemActive(ctxFor('s1'), {}));
check('unset role + pi-permission-system: floor', layer2Mode({}, ctxFor('s1'), store) === 'floor');
check('unset role, no pi-permission-system: guard', layer2Mode({}, ctxFor('s1'), {}) === 'guard');
check('explicit guard wins over detection', layer2Mode({ layer2: 'guard' }, ctxFor('s1'), store) === 'guard');
check('explicit floor without pi-permission-system', layer2Mode({ layer2: 'floor' }, ctxFor('x'), {}) === 'floor');

console.log(`PASS=${pass}, FAIL=${fail}`);
process.exit(fail ? 1 : 0);
