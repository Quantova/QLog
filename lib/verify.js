// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const L = require('./log');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const CHECKPOINTS_MAX = 1000;
const PAYLOADS_MAX = 1000;
const GAP_MAX_SECONDS = 10 * 365 * 24 * 3600;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract'];

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  if (checks.some((c) => !c.ok && !c.transport && !c.indeterminate)) return 'invalid';
  if (checks.some((c) => !c.ok)) return 'indeterminate';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate });
  return { checks, add };
}

function finish(checks, extra) {
  const status = statusOf(checks);
  return Object.assign({ valid: status === 'valid', status }, extra, { checks: checks.map((c) => Object.assign({}, c)) });
}

function anchorOptions(opts) {
  const out = {};
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function strictlyAfter(a, b) {
  if (a.chain === b.chain) {
    if (a.height !== b.height) return a.height > b.height;
    return a.tx === b.tx && a.index > b.index;
  }
  return a.ms > b.ms;
}

function laterBlock(a, b) {
  if (a.chain === b.chain) return a.height > b.height;
  return a.ms > b.ms;
}

function earlier(a, b) {
  if (!a) return b;
  if (!b) return a;
  return strictlyAfter(a, b) ? b : a;
}

function iso(pos) {
  return new Date(pos.ms).toISOString();
}

function expectedWriter(opts) {
  if (opts.writerKeyId !== undefined && opts.writerPublicKey !== undefined) F.reject('give writerKeyId or writerPublicKey, not both');
  if (opts.writerKeyId !== undefined) {
    if (typeof opts.writerKeyId !== 'string' || !/^[0-9a-f]{64}$/.test(opts.writerKeyId)) F.reject('writerKeyId is 64 lowercase hex characters');
    return opts.writerKeyId;
  }
  if (opts.writerPublicKey !== undefined) {
    let pk = opts.writerPublicKey;
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject('writerPublicKey is canonical base64');
      pk = raw;
    }
    return F.keyIdOf(pk);
  }
  F.reject('the expected writer is required, give writerKeyId or writerPublicKey so an attacker cannot substitute a log of its own');
}

function listOption(opts, name, max) {
  const list = opts[name];
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > max) F.reject(name + ' is a list of at most ' + max + ' items');
  return list;
}

function readOptions(opts) {
  const out = { writer: expectedWriter(opts), requireAnchor: opts.requireAnchor !== false, requireIntentFirst: opts.requireIntentFirst === true };
  if (opts.requireAnchor !== undefined && typeof opts.requireAnchor !== 'boolean') F.reject('requireAnchor is true or false');
  if (opts.requireIntentFirst !== undefined && typeof opts.requireIntentFirst !== 'boolean') F.reject('requireIntentFirst is true or false');
  out.maxGapSeconds = null;
  if (opts.maxGapSeconds !== undefined) {
    const g = opts.maxGapSeconds;
    if (typeof g !== 'number' || !Number.isSafeInteger(g) || g < 1 || g > GAP_MAX_SECONDS) F.reject('maxGapSeconds is a whole number of seconds from 1 to ' + GAP_MAX_SECONDS);
    out.maxGapSeconds = g;
  }
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  out.atMs = opts.at === undefined ? Date.now() : Date.parse(opts.at);
  out.checkpoints = listOption(opts, 'checkpoints', CHECKPOINTS_MAX);
  out.payloads = listOption(opts, 'payloads', PAYLOADS_MAX).map((p, i) => {
    if (p === null || typeof p !== 'object' || Array.isArray(p)) F.reject('payload ' + (i + 1) + ' is an object with seq and bytes');
    const seq = p.seq;
    const bytes = p.bytes;
    if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) F.reject('payload ' + (i + 1) + ' needs the seq of a log entry');
    if (!(bytes instanceof Uint8Array)) F.reject('payload ' + (i + 1) + ' needs bytes as a Uint8Array');
    return { seq, digest: F.sha3(bytes).toString('hex') };
  });
  return out;
}

async function checkAnchor(p, opts) {
  const receipt = p.anchor;
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return { fault: 'mismatch', detail: 'the anchor is not a Qstamp receipt' };
    if (receipt.kind !== String(qstamp.KINDS.record)) return { fault: 'mismatch', detail: 'the anchor was not recorded under the record kind' };
    if (!receipt.record || receipt.record.alg !== 'sha3-256') return { fault: 'mismatch', detail: 'the anchor does not record a SHA3 digest' };
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    if (result.status !== 'valid') {
      const failed = result.checks.filter((c) => !c.ok);
      const hard = failed.find((c) => !c.transport);
      if (result.status === 'invalid' || hard) return { fault: 'mismatch', detail: (hard || failed[0] || { detail: 'the anchor does not verify' }).detail };
      return { fault: 'transport', detail: (failed[0] || { detail: 'the anchor could not be reached' }).detail };
    }
    const position = {
      ms: receipt.anchor.time * 1000,
      height: receipt.anchor.height,
      tx: receipt.anchor.tx,
      index: receipt.proof.index,
      block: receipt.anchor.block,
      chain: receipt.chain.id + '/' + receipt.chain.genesis,
    };
    if (Date.parse(p.statement.sealedAt) > position.ms + CLOCK_SKEW_MS) return { fault: 'late', detail: 'the checkpoint claims a sealing time later than its anchor at ' + iso(position) };
    return { position };
  } catch (e) {
    return { fault: 'mismatch', detail: 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error') };
  }
}

async function anchorsOf(copies, opts) {
  const positions = [];
  const faults = { late: null, mismatch: null, transport: null };
  for (const c of copies) {
    if (c.anchor === undefined) continue;
    const r = await checkAnchor(c, opts);
    if (r.position) positions.push(r.position);
    else if (!faults[r.fault]) faults[r.fault] = r.detail;
  }
  let earliest = null;
  for (const pos of positions) earliest = earlier(earliest, pos);
  return { positions, earliest, faults };
}

function suffixEarliest(points) {
  const out = new Array(points.length + 1).fill(null);
  for (let i = points.length - 1; i >= 0; i -= 1) out[i] = earlier(points[i].position, out[i + 1]);
  return out;
}

function firstAtLeast(points, seq) {
  let lo = 0;
  let hi = points.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (points[mid].seq < seq) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function readLog(log, add) {
  let list = log;
  if (typeof log === 'string') {
    try {
      list = L.fromJsonl(log);
    } catch (e) {
      add('format', false, e.message);
      return null;
    }
  }
  const chain = L.chainOf(list);
  if (chain.problem) {
    add('chain', false, chain.problem.message);
    return null;
  }
  add('chain', true, chain.entries.length + ' entries, each linked to the one before it');
  return chain.entries;
}

async function sealOf(entries, o, opts, add) {
  const n = entries.length;
  const logId = entries[0].logId;
  const groups = new Map();
  let signedThrough = -1;
  for (const [i, env] of o.checkpoints.entries()) {
    const name = 'checkpoint ' + (i + 1);
    let p;
    try {
      p = F.parse(env);
    } catch (e) {
      add(name, true, 'ignored, it is not a well formed checkpoint');
      continue;
    }
    const st = p.statement;
    if (st.logId !== logId) {
      add(name, true, 'ignored, it seals another log');
      continue;
    }
    if (p.signerId !== o.writer || st.writerKeyId !== o.writer || F.keyIdOf(p.publicKey) !== o.writer || !native.verify(p.publicKey, F.payload(st), p.signature)) {
      add(name, true, 'ignored, it is not validly signed by the writer of this log');
      continue;
    }
    if (st.seq >= n) {
      add(name, false, 'the writer sealed ' + (st.seq + 1) + ' entries but only ' + n + ' were given, so the log was cut short');
      continue;
    }
    if (st.head !== F.entryHash(entries[st.seq]) || st.lastTime !== entries[st.seq].time) {
      add(name, false, 'the writer sealed a different entry ' + st.seq + ', so the log was changed after sealing');
      continue;
    }
    if (Date.parse(st.sealedAt) > o.atMs + CLOCK_SKEW_MS) {
      add(name, false, 'the checkpoint claims to be sealed after the time of verification');
      continue;
    }
    if (st.seq > signedThrough) signedThrough = st.seq;
    const id = F.anchorDigest(p).toString('hex');
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(p);
  }
  const points = [];
  const blocks = new Map();
  for (const copies of groups.values()) {
    const seq = copies[0].statement.seq;
    if (!copies.some((c) => c.anchor !== undefined)) continue;
    const { positions, earliest, faults } = await anchorsOf(copies, opts);
    const label = 'checkpoint through ' + seq + ' anchor';
    if (faults.late) add(label, false, faults.late);
    else if (earliest) add(label, true, 'recorded by ' + iso(earliest));
    else if (faults.transport) add(label, false, faults.transport, true);
    else add(label, true, 'ignored, the attached receipt does not belong to this checkpoint, ' + faults.mismatch);
    if (faults.late || !earliest) continue;
    points.push({ seq, position: earliest });
    for (const pos of positions) {
      if (!blocks.has(pos.block)) blocks.set(pos.block, []);
      blocks.get(pos.block).push({ seq, position: pos });
    }
  }
  points.sort((a, b) => a.seq - b.seq);
  return { signedThrough, points, blocks };
}

function timeCheck(entries, o, add) {
  const last = Date.parse(entries[entries.length - 1].time);
  if (last > o.atMs + CLOCK_SKEW_MS) {
    add('time', false, 'the last entry is dated after the time of verification');
    return;
  }
  if (o.maxGapSeconds === null) return;
  const limit = o.maxGapSeconds * 1000;
  for (let i = 1; i < entries.length; i += 1) {
    if (Date.parse(entries[i].time) - Date.parse(entries[i - 1].time) > limit) {
      add('heartbeat', false, 'entries ' + (i - 1) + ' and ' + i + ' are more than ' + o.maxGapSeconds + ' seconds apart, so the writer was silent for longer than the policy allows');
      return;
    }
  }
  if (o.atMs - last > limit) {
    add('heartbeat', false, 'the last entry is more than ' + o.maxGapSeconds + ' seconds before the time of verification, so later entries may be missing or the writer stopped', false, true);
    return;
  }
  add('heartbeat', true, 'no gap between entries exceeds ' + o.maxGapSeconds + ' seconds');
}

function intentCheck(entries, o, seal, add) {
  const suffix = suffixEarliest(seal.points);
  let actions = 0;
  let proven = 0;
  let firstBad = null;
  let firstOpen = null;
  for (const e of entries) {
    if (e.kind !== 'action') continue;
    actions += 1;
    if (e.ref === null || e.after === '') {
      if (firstBad === null) firstBad = 'action ' + e.seq + ' does not name an intent and the block that anchored it';
      continue;
    }
    const intent = (seal.blocks.get(e.after) || []).filter((c) => c.seq >= e.ref && c.seq < e.seq).reduce((best, c) => earlier(best, c.position), null);
    const sealed = suffix[firstAtLeast(seal.points, e.seq)];
    if (!intent) {
      if (firstOpen === null) firstOpen = 'the anchored checkpoint covering intent ' + e.ref + ' in the block named by action ' + e.seq + ' was not supplied or could not be confirmed';
    } else if (!sealed) {
      if (firstOpen === null) firstOpen = 'action ' + e.seq + ' is not yet sealed by an anchored checkpoint';
    } else if (sealed.chain !== intent.chain || !laterBlock(sealed, intent) || Date.parse(e.time) < Math.floor(intent.ms / 1000) * 1000) {
      if (firstBad === null) firstBad = 'action ' + e.seq + ' is not ordered after the anchor of its intent';
    } else {
      proven += 1;
    }
  }
  if (o.requireIntentFirst) {
    if (firstBad) add('intent first', false, firstBad);
    else if (firstOpen) add('intent first', false, firstOpen, false, true);
    else add('intent first', true, actions ? 'every action names the block that anchored its intent and was recorded after it' : 'the log holds no actions');
  }
  return { actions, proven };
}

function payloadCheck(entries, o, add) {
  for (const p of o.payloads) {
    const e = entries[p.seq];
    const name = 'payload ' + p.seq;
    if (!e) add(name, false, 'the log has no entry ' + p.seq);
    else if (e.kind === 'genesis' || e.kind === 'heartbeat') add(name, false, 'entry ' + p.seq + ' is a ' + e.kind + ' and carries no payload');
    else add(name, p.digest === e.digest, p.digest === e.digest ? 'the payload matches the digest in the log' : 'the payload differs from the one the log recorded');
  }
}

async function verify(log, options) {
  if (options === null || typeof options !== 'object') F.reject('options is an object naming the expected writer');
  const opts = options;
  const o = readOptions(opts);
  const { checks, add } = recorder();
  const entries = readLog(log, add);
  if (!entries) return finish(checks, { logId: null, writerKeyId: o.writer });
  const n = entries.length;
  const logId = entries[0].logId;
  const writerOk = entries[0].digest === o.writer;
  add('writer', writerOk, writerOk ? 'the log was started by the expected writer' : 'the log was started by a different writer than expected');
  const base = { logId, writerKeyId: o.writer, entries: n, head: F.entryHash(entries[n - 1]) };
  if (!writerOk) return finish(checks, base);

  const seal = await sealOf(entries, o, opts, add);
  const { signedThrough, points } = seal;
  let sealedThrough = -1;
  let first = null;
  let last = null;
  for (const p of points) {
    if (p.seq > sealedThrough) sealedThrough = p.seq;
    first = earlier(first, p.position);
    if (!last || strictlyAfter(p.position, last)) last = p.position;
  }
  const unsealed = n - 1 - sealedThrough;
  const covered = Math.max(signedThrough, sealedThrough);
  if (unsealed === 0) {
    add('sealed', true, 'every entry is sealed by an anchored checkpoint');
  } else if (o.requireAnchor) {
    add('sealed', false, sealedThrough < 0 ? 'no entry is sealed by an anchored checkpoint, so the log is only the claim of its writer' : 'entries ' + (sealedThrough + 1) + ' to ' + (n - 1) + ' are not yet sealed by an anchored checkpoint', false, true);
  } else if (covered < n - 1) {
    add('sealed', false, covered < 0 ? 'no checkpoint signed by the writer covers the log, so any holder of the file could have written it' : 'entries ' + (covered + 1) + ' to ' + (n - 1) + ' are not covered by a checkpoint signed by the writer', false, true);
  } else {
    add('sealed', true, sealedThrough < 0 ? 'signed by the writer through entry ' + covered + ' but not anchored, so the times are the claim of the writer' : 'anchored through entry ' + sealedThrough + ' and signed by the writer through entry ' + covered);
  }

  timeCheck(entries, o, add);
  const intent = intentCheck(entries, o, seal, add);
  payloadCheck(entries, o, add);

  return finish(checks, Object.assign(base, {
    signedThrough,
    sealedThrough,
    unsealed,
    firstAnchoredAt: first ? iso(first) : null,
    lastAnchoredAt: last ? iso(last) : null,
    actions: intent.actions,
    actionsIntentFirst: intent.proven,
    payloadsChecked: o.payloads.length,
  }));
}

module.exports = { verify, CHECKPOINTS_MAX, PAYLOADS_MAX };
