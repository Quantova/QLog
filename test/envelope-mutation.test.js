'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { campaign, mutator, canon, iterations, timed, CALL_LIMIT_MS } = require('./fuzz');
const { honest, pinFakes } = require('./honest');

const CODE = 'QLOG_';

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

const isValid = (r) => r.status === 'valid' || r.valid === true;
const failing = (r) => JSON.stringify(r.checks.filter((c) => !c.ok));
const poolOf = (w) => stringsOf([w.log, w.seals, w.anchored], []);

async function honestBaseline(w, log, opts) {
  const r = await w.ql.verify(log, opts);
  assert.strictEqual(r.status, 'valid', failing(r));
  return r;
}

['genesis', 'event', 'intent', 'action', 'heartbeat'].forEach((kind, seq) => {
  test('a changed ' + kind + ' entry never lets the log verify valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    pinFakes(t);
    const w = await setup();
    assert.strictEqual(w.log[seq].kind, kind);
    const opts = w.anchoredOptions();
    await honestBaseline(w, w.log, opts);
    const stats = await campaign({
      name: kind + ' entry',
      seed: 0x109e + seq,
      base: w.log[seq],
      pool: poolOf(w),
      code: CODE,
      check: (m) => {
        const log = w.log.slice();
        log[seq] = m;
        return w.ql.verify(log, opts);
      },
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('a changed log never verifies valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
  pinFakes(t);
  const w = await setup();
  const opts = w.anchoredOptions();
  await honestBaseline(w, w.log, opts);
  const stats = await campaign({
    name: 'log',
    seed: 0x10a0,
    base: w.log,
    pool: poolOf(w),
    code: CODE,
    check: (m) => w.ql.verify(m, opts),
    valid: isValid,
  });
  t.diagnostic(JSON.stringify(stats));
});

test('a changed line of the JSON lines form never verifies valid', async (t) => {
  pinFakes(t);
  const w = await setup();
  const opts = w.anchoredOptions();
  const text = w.ql.toJsonl(w.log);
  await honestBaseline(w, text, opts);
  const lines = text.slice(0, -1).split('\n');
  const m = mutator(0x10a1);
  const n = iterations(1000);
  const ops = [
    (ls) => { const i = m.int(ls.length); ls[i] = m.textMutate(ls[i]); return ls.join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length); ls.splice(i, 1); return ls.join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length); ls.splice(i, 0, ls[i]); return ls.join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length - 1); [ls[i], ls[i + 1]] = [ls[i + 1], ls[i]]; return ls.join('\n') + '\n'; },
    (ls) => ls.join('\r\n') + '\r\n',
    (ls) => ls.join('\n'),
    (ls) => ls.join('\n') + '\n\n',
    (ls) => '\ufeff' + ls.join('\n') + '\n',
    (ls) => { const i = m.int(ls.length); ls[i] = ls[i] + ' '; return ls.join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length); ls[i] = m.lookalike(ls[i]); return ls.join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length); const j = m.int(ls[i].length); return ls.slice(0, i).concat([ls[i].slice(0, j) + String.fromCharCode(ls[i].charCodeAt(j) ^ (1 << m.int(7))) + ls[i].slice(j + 1)], ls.slice(i + 1)).join('\n') + '\n'; },
    (ls) => { const i = m.int(ls.length); ls[i] = JSON.stringify(JSON.parse(ls[i]), null, 1).replace(/\n/g, ''); return ls.join('\n') + '\n'; },
  ];
  let mutated = 0;
  for (let i = 0; i < n; i += 1) {
    const changed = m.pick(ops)(lines.slice());
    if (changed === text) continue;
    mutated += 1;
    const r = await timed(() => w.ql.verify(changed, opts));
    assert.ok(r.ms < CALL_LIMIT_MS, 'iteration ' + i + ' took ' + Math.round(r.ms) + ' ms');
    if (r.error) {
      assert.ok(typeof r.error.code === 'string' && r.error.code.startsWith(CODE), 'iteration ' + i + ' threw ' + r.error.message);
      continue;
    }
    assert.ok(!isValid(r.result), 'iteration ' + i + ' accepted a changed log text ' + JSON.stringify(changed).slice(0, 300));
  }
  assert.ok(mutated >= n * 0.9, 'only ' + mutated + ' changed texts');
  t.diagnostic(JSON.stringify({ iterations: n, mutated }));
});

[['intent', 0], ['head', 1]].forEach(([name, at], n) => {
  test('a changed anchored ' + name + ' checkpoint never lets the log verify valid', async (t) => {
    pinFakes(t);
    const w = await setup();
    const opts = w.anchoredOptions();
    await honestBaseline(w, w.log, opts);
    const others = opts.checkpoints;
    const stats = await campaign({
      name: name + ' checkpoint',
      seed: 0xc4e0 + n,
      base: w.anchored[name],
      pool: poolOf(w),
      code: CODE,
      check: (m) => {
        const cps = others.slice();
        cps[at] = m;
        return w.ql.verify(w.log, Object.assign({}, opts, { checkpoints: cps }));
      },
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed Qstamp receipt never lets the ' + name + ' checkpoint make the log verify valid', async (t) => {
    pinFakes(t);
    const w = await setup();
    const opts = w.anchoredOptions();
    await honestBaseline(w, w.log, opts);
    const others = opts.checkpoints;
    const stats = await campaign({
      name: name + ' receipt',
      seed: 0xa7c0 + n,
      base: w.anchored[name].anchor,
      pool: stringsOf(Object.values(w.anchored).map((e) => e.anchor), []),
      code: CODE,
      check: (r) => {
        const cps = others.slice();
        cps[at] = Object.assign({}, w.anchored[name], { anchor: r });
        return w.ql.verify(w.log, Object.assign({}, opts, { checkpoints: cps }));
      },
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('a changed signed checkpoint never lets an unanchored log verify valid when anchors are not required', async (t) => {
  const w = await setup();
  const opts = w.unanchoredOptions();
  await honestBaseline(w, w.log, opts);
  const base = w.seals.head;
  const baseForm = canon(base);
  const signedPart = (v) => {
    if (!v || typeof v !== 'object' || Array.isArray(v) || !Object.prototype.hasOwnProperty.call(v, 'anchor')) return null;
    const rest = Object.assign({}, v);
    delete rest.anchor;
    return canon(rest);
  };
  const stats = await campaign({
    name: 'unanchored head checkpoint',
    seed: 0xc4e9,
    base,
    pool: poolOf(w),
    code: CODE,
    skip: (v) => canon(v) === baseForm || signedPart(v) === baseForm,
    check: (m) => w.ql.verify(w.log, Object.assign({}, opts, { checkpoints: [m] })),
    valid: isValid,
  });
  t.diagnostic(JSON.stringify(stats));
});
