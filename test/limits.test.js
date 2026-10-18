// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const ql = require('..');
const F = require('../lib/format');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const iso = (s) => new Date(s * 1000).toISOString();

const COUNTER = [
  "'use strict';",
  "const fs = require('fs');",
  'const dir = process.env.QLOG_COUNT_DIR;',
  'const fds = new Set();',
  'let bytes = 0;',
  'const open = fs.openSync;',
  'fs.openSync = function (p, ...rest) { const fd = open.call(fs, p, ...rest); if (String(p).startsWith(dir)) fds.add(fd); return fd; };',
  'const read = fs.readSync;',
  'fs.readSync = function (fd, ...rest) { const n = read.call(fs, fd, ...rest); if (fds.has(fd)) bytes += n; return n; };',
  'const readFile = fs.readFileSync;',
  "fs.readFileSync = function (p, ...rest) { const out = readFile.call(fs, p, ...rest); if ((typeof p === 'string' && p.startsWith(dir)) || (typeof p === 'number' && fds.has(p))) bytes += out.length; return out; };",
  "process.on('exit', () => process.stderr.write('\\nBYTES_READ ' + bytes + '\\n'));",
].join('\n');

function nest(depth) {
  let v = 'x';
  for (let i = 0; i < depth; i += 1) v = [v];
  return v;
}

test('plain data is capped at 4096 list items and a nesting depth of six, as in the sibling packages', () => {
  assert.doesNotThrow(() => F.plainCopy(new Array(4096).fill(1)));
  assert.throws(() => F.plainCopy(new Array(4097).fill(1)), /too long/);
  assert.doesNotThrow(() => F.plainCopy(nest(6)));
  assert.throws(() => F.plainCopy(nest(7)), /nested too deeply/);
});

test('appending to a long log reads only its last line, not the whole log', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qlog-append-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const counter = path.join(dir, 'count.js');
  fs.writeFileSync(counter, COUNTER);
  const key = ql.generateKey();
  const read = [];
  for (const n of [500, 5000]) {
    const log = [ql.create({ key })];
    for (let i = 1; i < n; i += 1) log.push(ql.append(log, { kind: 'event', digest: (i % 16).toString(16).repeat(64) }));
    const file = path.join(dir, 'log-' + n + '.jsonl');
    fs.writeFileSync(file, ql.toJsonl(log));
    const append = () => spawnSync(process.execPath, ['--require', counter, path.join(ROOT, 'bin', 'qlog.js'), 'append', file, '--kind', 'event', '--digest', 'a'.repeat(64)], { encoding: 'utf8', env: Object.assign({}, process.env, { QLOG_COUNT_DIR: dir }) });
    assert.strictEqual(append().status, 0);
    const second = append();
    assert.strictEqual(second.status, 0, second.stderr);
    const bytes = Number((second.stderr.match(/BYTES_READ (\d+)/) || [])[1]);
    assert.ok(bytes < fs.statSync(file).size / 20, 'the append read ' + bytes + ' bytes of a ' + fs.statSync(file).size + ' byte log');
    read.push(bytes);
  }
  assert.ok(read[1] <= read[0] * 2 + 4096, 'the bytes read grew with the log, ' + read.join(' then '));
});

test('a seal more than a day before its anchor, or an anchor after the time of verification, does not prove the log', async (t) => {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = (r) => !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && r.checks.every((c) => c.ok || c.name === 'proof');
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
  const now = Math.floor(Date.now() / 1000);
  const chain = makeChain(ROOT, { time: now - 4 * 86400 });
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const key = ql.generateKey();
  const sealed = async (at, anchoredAt) => {
    const log = [ql.create({ key, time: iso(at - 2) })];
    log.push(ql.append(log, { kind: 'event', digest: 'a'.repeat(64), time: iso(at - 1) }));
    chain.nextBlockTime = anchoredAt;
    const [cp] = await ql.anchor([ql.checkpoint(log, { key, sealedAt: iso(at) })], Object.assign({ seed: SEED, index: 0 }, ep));
    return { log, opts: Object.assign({ writerKeyId: ql.keyId(key), checkpoints: [cp] }, ep) };
  };
  const old = await sealed(now - 3 * 86400 - 60, now - 60);
  const fresh = await sealed(now - 180, now - 60);
  chain.newBlock();
  const late = await ql.verify(old.log, old.opts);
  assert.strictEqual(late.valid, false);
  assert.ok(late.checks.some((c) => !c.ok && /24 hours/.test(c.detail)));
  assert.strictEqual((await ql.verify(old.log, Object.assign({ maxAnchorDelay: 4 * 86400 }, old.opts))).status, 'valid');
  assert.strictEqual((await ql.verify(fresh.log, fresh.opts)).status, 'valid');
  assert.strictEqual((await ql.verify(fresh.log, Object.assign({ at: iso(now - 1800) }, fresh.opts))).valid, false);
});
