// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const util = require('util');
const q = require('..');

test('a generated key never shows its bytes when printed or serialised', () => {
  const key = q.generateKey();
  const hex = Buffer.from(key).toString('hex');
  const listed = Array.from(key).join(',');
  const shown = [util.inspect(key), util.inspect({ key }), JSON.stringify({ key }), String(key), `${key}`, util.format('%o', key), util.format('%j', { key }), key.toLocaleString()];
  for (const s of shown) {
    assert.ok(!s.includes(hex), s);
    assert.ok(!s.replace(/\s/g, '').includes(listed.slice(0, 24)), s);
  }
  assert.ok(key instanceof Uint8Array);
  assert.strictEqual(key.length, 32);
  assert.strictEqual(Object.prototype.toString.call(key.slice(0, 4)), '[object Uint8Array]');
  assert.strictEqual(q.keyId(key), q.keyId(Uint8Array.from(key)));
});

test('text with an unassigned code point or a noncharacter is refused', () => {
  const F = require('../lib/format');
  for (const t of ['a\u0378b', 'a\ufffeb', 'a\u{10ffff}b']) assert.ok(F.textProblem(t, 64, 'text'), JSON.stringify(t));
  assert.strictEqual(F.textProblem('plain text', 64, 'text'), null);
});

test('a signing key of zero bytes or in shared memory is refused', async () => {
  const sign = (key) => q.create({ key, time: new Date(Date.now() - 1000).toISOString() });
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  shared.set(q.generateKey());
  await assert.rejects(Promise.resolve().then(() => sign(new Uint8Array(32))));
  await assert.rejects(Promise.resolve().then(() => sign(shared)));
  await Promise.resolve().then(() => sign(q.generateKey()));
});

test('a misspelled or unknown option of a signing call is refused and nothing is signed', async () => {
  await assert.rejects(Promise.resolve().then(() => q.create({ key: q.generateKey(), time: new Date(Date.now() - 1000).toISOString(), nte: 'x' })), /is not (an option of|used by)/);
  await assert.rejects(Promise.resolve().then(() => q.anchor([], { seed: new Uint8Array(32).fill(5), index: 0, untl: '2030-01-01T00:00:00.000Z' })));
});

test('a call whose options are optional works without them', () => {
  const log = [q.create({ key: q.generateKey(), time: new Date(Date.now() - 5000).toISOString() })];
  const beat = q.heartbeat(log);
  assert.strictEqual(beat.kind, 'heartbeat');
  assert.throws(() => q.heartbeat(log, [1, 2]), /plain object/);
});
