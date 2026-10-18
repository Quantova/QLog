// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const F = require('../lib/format');
const { honest, pinFakes, iso } = require('./honest');

function handWritten(log, ref, after, time, text) {
  const last = F.parseEntry(log[log.length - 1]);
  return F.parseEntry({
    format: F.ENTRY_FORMAT,
    logId: last.logId,
    seq: last.seq + 1,
    prev: F.entryHash(last),
    time,
    kind: 'action',
    ref,
    after,
    digest: crypto.createHash('sha3-256').update(text).digest('hex'),
    note: '',
  });
}

test('append refuses a second action for an intent that an action already carried out', async (t) => {
  pinFakes(t);
  const h = await honest();
  assert.throws(() => h.ql.append(h.log, { kind: 'action', ref: 2, after: h.anchored.intent, payload: Buffer.from('paid invoice 1001 again'), time: iso(h.t0 + 46) }), (e) => e.code === 'QLOG_INVALID_INPUT' && /one intent allows one action/.test(e.message));
});

test('under requireIntentFirst a second action naming the same intent is invalid', async (t) => {
  pinFakes(t);
  const h = await honest();
  const base = await h.ql.verify(h.log, h.anchoredOptions());
  assert.strictEqual(base.status, 'valid', JSON.stringify(base.checks.filter((c) => !c.ok)));
  const first = h.log.map((e) => F.parseEntry(e)).find((e) => e.kind === 'action');
  const twice = h.log.concat([handWritten(h.log, 2, first.after, iso(h.t0 + 46), 'paid invoice 1001 again')]);
  const cp = h.ql.checkpoint(twice, { key: h.key, sealedAt: iso(h.t0 + 47) });
  const sealed = await h.net.stamp(cp, h.t0 + 50);
  const r = await h.ql.verify(twice, h.anchoredOptions([h.anchored.intent, h.anchored.head, sealed]));
  assert.strictEqual(r.status, 'invalid');
  assert.match(r.checks.find((c) => c.name === 'intent first' && !c.ok).detail, /already carried out/);
  assert.strictEqual(r.actionsIntentFirst, 1);
  const intent = h.ql.append(h.log, { kind: 'intent', payload: Buffer.from('pay invoice 1002'), time: iso(h.t0 + 46) });
  const fresh = h.log.concat([intent]);
  const intentSeal = await h.net.stamp(h.ql.checkpoint(fresh, { key: h.key, sealedAt: iso(h.t0 + 47) }), h.t0 + 48);
  fresh.push(h.ql.append(fresh, { kind: 'action', ref: 5, after: intentSeal, payload: Buffer.from('paid invoice 1002'), time: iso(h.t0 + 52) }));
  const headSeal = await h.net.stamp(h.ql.checkpoint(fresh, { key: h.key, sealedAt: iso(h.t0 + 53) }), h.t0 + 55);
  const ok = await h.ql.verify(fresh, h.anchoredOptions([h.anchored.intent, h.anchored.head, intentSeal, headSeal]));
  assert.strictEqual(ok.status, 'valid', JSON.stringify(ok.checks.filter((c) => !c.ok)));
  assert.strictEqual(ok.actionsIntentFirst, 2);
});
