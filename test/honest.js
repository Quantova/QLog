'use strict';

const path = require('path');
const ql = require('..');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const iso = (s) => new Date(s * 1000).toISOString();

function provenByFakes(r) {
  return !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && Array.isArray(r.checks) && r.checks.every((c) => c.ok || c.name === 'proof');
}

function pinFakes(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = provenByFakes;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

function fakeNetwork(start) {
  const chain = makeChain(ROOT, { time: start - 3600 });
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const stamp = async (env, t) => {
    chain.nextBlockTime = t;
    return (await ql.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  };
  return { chain, ep, stamp };
}

async function honest() {
  const now = Math.floor(Date.now() / 1000);
  const t0 = now - 3000;
  const net = fakeNetwork(t0);
  const key = ql.generateKey();
  const writerKeyId = ql.keyId(key);
  const bytes = { 1: Buffer.from('invoice 1001 received'), 2: Buffer.from('pay invoice 1001'), 3: Buffer.from('paid invoice 1001') };
  const log = [ql.create({ key, time: iso(t0), note: 'treasury desk' })];
  log.push(ql.append(log, { kind: 'event', payload: bytes[1], time: iso(t0 + 10) }));
  log.push(ql.append(log, { kind: 'intent', payload: bytes[2], time: iso(t0 + 20) }));
  const intentSeal = ql.checkpoint(log, { key, sealedAt: iso(t0 + 21) });
  const anchoredIntentSeal = await net.stamp(intentSeal, t0 + 25);
  log.push(ql.append(log, { kind: 'action', ref: 2, after: anchoredIntentSeal, payload: bytes[3], time: iso(t0 + 30) }));
  log.push(ql.heartbeat(log, { time: iso(t0 + 40) }));
  const headSeal = ql.checkpoint(log, { key, sealedAt: iso(t0 + 41) });
  const anchoredHeadSeal = await net.stamp(headSeal, t0 + 45);
  const at = iso(t0 + 60);
  const payloads = [{ seq: 1, bytes: bytes[1] }, { seq: 3, bytes: bytes[3] }];
  const anchoredOptions = (checkpoints) => Object.assign({ writerKeyId, checkpoints: checkpoints || [anchoredIntentSeal, anchoredHeadSeal], requireIntentFirst: true, maxGapSeconds: 600, payloads, at }, net.ep);
  const unanchoredOptions = (checkpoints) => Object.assign({ writerKeyId, checkpoints: checkpoints || [headSeal], requireAnchor: false, maxGapSeconds: 600, payloads, at }, net.ep);
  return {
    ql, net, key, writerKeyId, log, at, t0,
    seals: { intent: intentSeal, head: headSeal },
    anchored: { intent: anchoredIntentSeal, head: anchoredHeadSeal },
    anchoredOptions, unanchoredOptions,
  };
}

module.exports = { honest, pinFakes, provenByFakes, fakeNetwork, iso, ROOT };
