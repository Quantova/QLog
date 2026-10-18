'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { iterations, mulberry32 } = require('./fuzz');
const { pinFakes, fakeNetwork, iso } = require('./honest');
const ql = require('..');

const CLOCK_SKEW_S = 300;

function rng(seed) {
  const rnd = mulberry32(seed);
  const int = (n) => Math.floor(rnd() * n);
  const between = (lo, hi) => lo + int(hi - lo + 1);
  const pick = (a) => a[int(a.length)];
  return { rnd, int, between, pick };
}

function randomPolicy(r) {
  const gap = r.pick([r.between(60, 600), r.between(600, 3600), r.between(3600, 7200)]);
  const policy = { maxGapSeconds: gap };
  if (r.int(2)) policy.requireAnchor = r.pick([true, false]);
  if (r.int(2)) policy.requireIntentFirst = r.pick([true, false]);
  if (r.int(2)) policy.maxAnchorDelay = r.pick([60, 3600, 86400]);
  return policy;
}

function scenario(r, policy) {
  const gap = policy.maxGapSeconds;
  const spacing = r.between(Math.ceil(gap / 2), gap);
  const silence = r.int(3) ? r.between(gap + CLOCK_SKEW_S + 1, 2 * gap + 2 * CLOCK_SKEW_S) : r.between(2 * gap + 2 * CLOCK_SKEW_S, 20 * gap);
  const beats = 1 + Math.ceil((silence - 2) / spacing);
  const t0 = Math.floor(Date.now() / 1000) - 4 * 86400 + r.int(86400);
  return { gap, spacing, silence, beats, t0 };
}

const heartbeatFailed = (res) => res.checks.some((c) => c.name === 'heartbeat' && !c.ok && /no anchored checkpoint proves it/.test(c.detail));
const failing = (res) => JSON.stringify(res.checks.filter((c) => !c.ok)).slice(0, 600);

async function backfilled(s, policy) {
  const net = fakeNetwork(s.t0);
  const key = ql.generateKey();
  const log = [ql.create({ key, time: iso(s.t0) })];
  const cps = [await net.stamp(ql.checkpoint(log, { key, sealedAt: iso(s.t0 + 1) }), s.t0 + 2)];
  for (let i = 1; i <= s.beats; i += 1) log.push(ql.heartbeat(log, { time: iso(s.t0 + i * s.spacing) }));
  const last = s.t0 + s.beats * s.spacing;
  const sealedAt = last + 2;
  cps.push(await net.stamp(ql.checkpoint(log, { key, sealedAt: iso(last + 1) }), sealedAt));
  const firstBeat = s.t0 + s.spacing;
  assert.ok(sealedAt - firstBeat > s.gap + CLOCK_SKEW_S, 'the scenario does not hold a silence beyond the permitted gap');
  return ql.verify(log, Object.assign({ writerKeyId: ql.keyId(key), checkpoints: cps, at: iso(sealedAt + 1) }, policy, net.ep));
}

async function honestWriter(s, policy) {
  const net = fakeNetwork(s.t0);
  const key = ql.generateKey();
  const log = [ql.create({ key, time: iso(s.t0) })];
  const cps = [await net.stamp(ql.checkpoint(log, { key, sealedAt: iso(s.t0 + 1) }), s.t0 + 2)];
  for (let i = 1; i <= s.beats; i += 1) {
    const t = s.t0 + i * s.spacing;
    log.push(ql.heartbeat(log, { time: iso(t) }));
    cps.push(await net.stamp(ql.checkpoint(log, { key, sealedAt: iso(t + 1) }), t + 2));
  }
  const last = s.t0 + s.beats * s.spacing;
  return ql.verify(log, Object.assign({ writerKeyId: ql.keyId(key), checkpoints: cps, at: iso(last + 3) }, policy, net.ep));
}

test('heartbeats back filled after a silence beyond the permitted gap and sealed once never meet the heartbeat policy', async (t) => {
  pinFakes(t);
  const r = rng(0xbeef);
  const n = iterations(100);
  for (let i = 0; i < n; i += 1) {
    const policy = randomPolicy(r);
    const s = scenario(r, policy);
    const res = await backfilled(s, policy);
    const where = 'iteration ' + i + ' ' + JSON.stringify(Object.assign({}, policy, s));
    assert.notStrictEqual(res.status, 'valid', where + ' verified valid');
    assert.ok(heartbeatFailed(res), where + ' did not fail the heartbeat check ' + failing(res));
  }
});

test('a writer that anchors a checkpoint after every heartbeat meets the same policies', async (t) => {
  pinFakes(t);
  const r = rng(0xbeef);
  const n = iterations(100);
  for (let i = 0; i < n; i += 1) {
    const policy = randomPolicy(r);
    const s = scenario(r, policy);
    const res = await honestWriter(s, policy);
    assert.strictEqual(res.status, 'valid', 'iteration ' + i + ' ' + JSON.stringify(Object.assign({}, policy, s)) + ' ' + failing(res));
    assert.ok(res.checks.some((c) => c.name === 'heartbeat' && c.ok));
  }
});
