// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const ql = require('..');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const iso = (s) => new Date(s * 1000).toISOString();

function pinned(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

function world(startedAgo) {
  const now = Math.floor(Date.now() / 1000);
  const chain = makeChain(ROOT, { time: now - startedAgo - 3600 });
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const anchorAt = async (env, t) => {
    chain.nextBlockTime = t;
    return (await ql.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  };
  return { now, chain, ep, anchorAt };
}

const failed = (r, name) => r.checks.find((c) => c.name === name && !c.ok);

test('heartbeats written after a silence verify invalid', async (t) => {
  pinned(t);
  const { now, chain, ep, anchorAt } = world(7 * 86400);
  const w = ql.generateKey();
  const t0 = now - 7 * 86400;
  const log = [ql.create({ key: w, time: iso(t0) })];
  log.push(ql.append(log, { kind: 'event', payload: Buffer.from('e1'), time: iso(t0 + 60) }));
  const cp1 = await anchorAt(ql.checkpoint(log, { key: w, sealedAt: iso(t0 + 120) }), t0 + 180);
  for (let h = 1; h <= 7 * 24 - 1; h += 1) log.push(ql.heartbeat(log, { time: iso(t0 + 120 + h * 3600) }));
  log.push(ql.append(log, { kind: 'action', payload: Buffer.from('wire 1m'), time: iso(now - 600) }));
  const cp2 = await anchorAt(ql.checkpoint(log, { key: w, sealedAt: iso(now - 300) }), now - 240);
  chain.setTime(now);
  const r = await ql.verify(log, Object.assign({ writerKeyId: ql.keyId(w), checkpoints: [cp1, cp2], maxGapSeconds: 2 * 3600 }, ep));
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'heartbeat').detail, /no anchored checkpoint proves it/);
});

test('a writer that anchors within the heartbeat gap verifies valid', async (t) => {
  pinned(t);
  const { now, chain, ep, anchorAt } = world(6 * 3600);
  const w = ql.generateKey();
  const t0 = now - 6 * 3600;
  const log = [ql.create({ key: w, time: iso(t0) })];
  const cps = [];
  for (let h = 1; h <= 6; h += 1) {
    log.push(ql.heartbeat(log, { time: iso(t0 + h * 3600 - 1800) }));
    log.push(ql.heartbeat(log, { time: iso(t0 + h * 3600 - 60) }));
    cps.push(await anchorAt(ql.checkpoint(log, { key: w, sealedAt: iso(t0 + h * 3600 - 30) }), t0 + h * 3600 - 20));
  }
  chain.setTime(now);
  const r = await ql.verify(log, Object.assign({ writerKeyId: ql.keyId(w), checkpoints: cps, maxGapSeconds: 2 * 3600 }, ep));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
});

test('an entry dated before the checkpoint it follows verifies invalid', async () => {
  const now = Math.floor(Date.now() / 1000);
  const w = ql.generateKey();
  const log = [ql.create({ key: w, time: iso(now - 600) })];
  log.push(ql.append(log, { kind: 'event', payload: Buffer.from('a'), time: iso(now - 500) }));
  const cp = ql.checkpoint(log, { key: w, sealedAt: iso(now - 300) });
  log.push(ql.append(log, { kind: 'event', payload: Buffer.from('b'), time: iso(now - 400) }));
  const cp2 = ql.checkpoint(log, { key: w, sealedAt: iso(now - 200) });
  const r = await ql.verify(log, { writerKeyId: ql.keyId(w), checkpoints: [cp, cp2], requireAnchor: false, at: iso(now) });
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'sealing order').detail, /dated into the past/);
});

test('verification never falls back to the local clock when the chain time fails', async () => {
  const now = Math.floor(Date.now() / 1000);
  const w = ql.generateKey();
  const log = [ql.create({ key: w, time: iso(now - 600) })];
  log.push(ql.heartbeat(log, { time: iso(now - 300) }));
  const cp = ql.checkpoint(log, { key: w, sealedAt: iso(now - 200) });
  const down = { base: 'https://down.example', async nodeInfo() { throw new Error('refused by test'); }, async transaction() { return null; } };
  const down2 = Object.assign({}, down, { base: 'https://down2.example' });
  const r = await ql.verify(log, { writerKeyId: ql.keyId(w), checkpoints: [cp], requireAnchor: false, maxGapSeconds: 3600, trustCustomEndpoints: true, clients: [down, down2] });
  assert.strictEqual(r.status, 'indeterminate');
  const c = failed(r, 'chain time');
  assert.ok(c && c.transport);
  assert.match(c.detail, /local clock was not used/);
});

test('a fabricated receipt from endpoints that are not pinned operators never verifies valid', async () => {
  const { now, chain, ep, anchorAt } = world(3600);
  const w = ql.generateKey();
  const log = [ql.create({ key: w, time: iso(now - 300) })];
  log.push(ql.heartbeat(log, { time: iso(now - 200) }));
  const cp = await anchorAt(ql.checkpoint(log, { key: w, sealedAt: iso(now - 100) }), now - 90);
  chain.setTime(now);
  const r = await ql.verify(log, Object.assign({ writerKeyId: ql.keyId(w), checkpoints: [cp] }, ep));
  assert.notStrictEqual(r.status, 'valid');
  assert.ok(r.checks.some((c) => c.unproven && !c.ok));
  const single = await ql.verify(log, { writerKeyId: ql.keyId(w), checkpoints: [cp], trustCustomEndpoints: true, clients: [ep.clients[0]], trustSingleEndpoint: true });
  assert.notStrictEqual(single.status, 'valid');
});

test('endpoints chosen by the caller need trustCustomEndpoints, loopback needs allowLoopback and the anchor sender is checked', async (t) => {
  const { now, chain, ep, anchorAt } = world(3600);
  const w = ql.generateKey();
  const t0 = now - 3600;
  const log = [ql.create({ key: w, time: iso(t0) })];
  log.push(ql.append(log, { kind: 'event', payload: Buffer.from('e1'), time: iso(t0 + 60) }));
  const cp = await anchorAt(ql.checkpoint(log, { key: w, sealedAt: iso(t0 + 120) }), t0 + 180);
  chain.setTime(now);
  const base = { writerKeyId: ql.keyId(w), checkpoints: [cp] };
  const untrusted = await ql.verify(log, Object.assign({ clients: ep.clients, at: new Date().toISOString() }, base));
  assert.notStrictEqual(untrusted.status, 'valid');
  const loop = await ql.verify(log, Object.assign({ trustCustomEndpoints: true, rpc: 'http://127.0.0.1:9', at: new Date().toISOString() }, base));
  assert.notStrictEqual(loop.status, 'valid');
  const plainResult = await ql.verify(log, Object.assign({}, base, ep));
  assert.notStrictEqual(plainResult.status, 'valid');
  assert.ok(plainResult.checks.some((c) => !c.ok && c.unproven));
  pinned(t);
  const wrong = await ql.verify(log, Object.assign({ expectedSender: chain.core.address(new Uint8Array(32).fill(9), 0) }, base, ep));
  assert.notStrictEqual(wrong.status, 'valid');
  const right = await ql.verify(log, Object.assign({ expectedSender: chain.core.address(SEED, 0) }, base, ep));
  assert.strictEqual(right.status, 'valid', JSON.stringify(right.checks.filter((c) => !c.ok)));
});
