// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  return Object.assign(Object.create(null), value);
}

const ENTRIES_MAX = 1000000;
const LINE_MAX = 8192;
const APPEND_KINDS = Object.freeze(['event', 'intent', 'action', 'heartbeat']);

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function generateKey() {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qlog-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

function nowIso() {
  return new Date().toISOString();
}

function textOption(value, what) {
  const v = value === undefined ? '' : value;
  const p = F.textProblem(v, F.NOTE_MAX, what);
  if (p) F.reject(p);
  return v;
}

function timeOption(value, what) {
  const v = value === undefined ? nowIso() : value;
  const p = F.timeProblem(v, what);
  if (p) F.reject(p);
  return v;
}

function create(options) {
  if (!options || typeof options !== 'object') F.reject('create needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.logId !== undefined) F.reject('the log identifier is always chosen at random, so two logs can never share one');
  return F.parseEntry({
    format: F.ENTRY_FORMAT,
    logId: randomHex(16),
    seq: 0,
    prev: F.ZERO,
    time: timeOption(options.time, 'time'),
    kind: 'genesis',
    ref: null,
    after: '',
    digest: keyId(options.key),
    note: textOption(options.note, 'note'),
  });
}

function lastOf(log) {
  if (!Array.isArray(log) || log.length === 0) F.reject('the log is a non empty list of entries, starting with its genesis entry');
  const last = F.parseEntry(log[log.length - 1]);
  if (last.seq !== log.length - 1) F.reject('the log list does not run from the genesis entry, the last entry has seq ' + last.seq);
  return last;
}

function digestOption(options, kind) {
  const given = ['payload', 'digest'].filter((k) => options[k] !== undefined);
  if (kind === 'heartbeat') {
    if (given.length) F.reject('a heartbeat carries no payload');
    return F.EMPTY_DIGEST;
  }
  if (given.length !== 1) F.reject('give exactly one of payload or digest');
  if (options.payload !== undefined) {
    if (!(options.payload instanceof Uint8Array)) F.reject('payload is a Uint8Array');
    return F.sha3(options.payload).toString('hex');
  }
  if (typeof options.digest !== 'string' || !/^[0-9a-f]{64}$/.test(options.digest)) F.reject('digest is 64 lowercase hex characters, the SHA3-256 of the payload');
  return options.digest;
}

function afterOption(value, ref, last) {
  if (value === undefined || value === '') return '';
  if (ref === null) F.reject('after needs ref, the intent the action carries out');
  if (typeof value === 'string') {
    if (!F.BLOCK_ID.test(value)) F.reject('after is the block identifier of the anchor of a checkpoint covering the intent');
    return value;
  }
  let cp;
  try {
    cp = F.parse(F.plainCopy(value));
  } catch (e) {
    F.reject('after is an anchored checkpoint or the block identifier of its anchor');
  }
  const block = cp.anchor && typeof cp.anchor === 'object' && cp.anchor.anchor && typeof cp.anchor.anchor === 'object' ? cp.anchor.anchor.block : undefined;
  if (typeof block !== 'string' || !F.BLOCK_ID.test(block)) F.reject('the checkpoint given as after is not anchored');
  if (cp.statement.logId !== last.logId) F.reject('the checkpoint given as after seals another log');
  if (cp.statement.seq < ref || cp.statement.seq > last.seq) F.reject('the checkpoint given as after does not cover the intent ' + ref);
  return block;
}

function append(log, options) {
  if (!options || typeof options !== 'object') F.reject('append needs options');
  options = own(options);
  const last = lastOf(log);
  const kind = options.kind;
  if (!APPEND_KINDS.includes(kind)) F.reject('kind is one of ' + APPEND_KINDS.join(', '));
  const seq = last.seq + 1;
  if (!Number.isSafeInteger(seq) || seq >= ENTRIES_MAX) F.reject('the log has reached its maximum length of ' + ENTRIES_MAX + ' entries, start a new log');
  const time = timeOption(options.time, 'time');
  if (Date.parse(time) < Date.parse(last.time)) F.reject('time cannot be earlier than the previous entry at ' + last.time);
  let ref = null;
  if (options.ref !== undefined && options.ref !== null) {
    if (kind !== 'action') F.reject('only an action may carry a ref');
    if (typeof options.ref !== 'number' || !Number.isSafeInteger(options.ref) || options.ref < 1 || options.ref >= seq) F.reject('ref is the seq of an earlier intent entry');
    const target = F.parseEntry(log[options.ref]);
    if (target.seq !== options.ref || target.kind !== 'intent' || target.logId !== last.logId) F.reject('ref must point to an intent entry of this log');
    ref = options.ref;
  }
  if (options.after !== undefined && kind !== 'action') F.reject('only an action may carry after');
  const after = afterOption(options.after, ref, last);
  return F.parseEntry({
    format: F.ENTRY_FORMAT,
    logId: last.logId,
    seq,
    prev: F.entryHash(last),
    time,
    kind,
    ref,
    after,
    digest: digestOption(options, kind),
    note: textOption(options.note, 'note'),
  });
}

function heartbeat(log, options) {
  const opts = own(options);
  return append(log, { kind: 'heartbeat', time: opts.time, note: opts.note });
}

function chainOf(log) {
  if (!Array.isArray(log) || log.length === 0) return { problem: { at: 0, message: 'the log is empty' }, entries: [] };
  if (log.length > ENTRIES_MAX) return { problem: { at: ENTRIES_MAX, message: 'the log has more than ' + ENTRIES_MAX + ' entries' }, entries: [] };
  const entries = [];
  let prev = null;
  let prevHash = null;
  for (let i = 0; i < log.length; i += 1) {
    let e;
    try {
      e = F.parseEntry(log[i]);
    } catch (err) {
      return { problem: { at: i, message: 'entry ' + i + ' is malformed, ' + err.message }, entries };
    }
    const bad = (message) => ({ problem: { at: i, message }, entries });
    if (e.seq !== i) return bad('entry ' + i + ' carries seq ' + e.seq + ', so an entry was removed, inserted or reordered');
    if (i > 0) {
      if (e.logId !== prev.logId) return bad('entry ' + i + ' belongs to another log');
      if (e.prev !== prevHash) return bad('entry ' + i + ' does not follow entry ' + (i - 1) + ', so an entry was removed, inserted or changed');
      if (Date.parse(e.time) < Date.parse(prev.time)) return bad('entry ' + i + ' is dated before the entry it follows');
      if (e.kind === 'action' && e.ref !== null && entries[e.ref].kind !== 'intent') return bad('action ' + i + ' refers to entry ' + e.ref + ', which is not an intent');
    }
    entries.push(e);
    prev = e;
    prevHash = F.entryHash(e);
  }
  return { problem: null, entries };
}

function chainProblem(log) {
  return chainOf(log).problem;
}

function checkpoint(log, options) {
  if (!options || typeof options !== 'object') F.reject('checkpoint needs options');
  options = own(options);
  requireSeed(options.key);
  const chain = chainOf(log);
  if (chain.problem) F.reject('the log cannot be sealed, ' + chain.problem.message);
  const pk = publicKey(options.key);
  const id = F.keyIdOf(pk);
  if (chain.entries[0].digest !== id) F.reject('this key is not the writer that started the log');
  const last = chain.entries[chain.entries.length - 1];
  const sealedAt = timeOption(options.sealedAt, 'sealedAt');
  const statement = {
    logId: last.logId,
    writerKeyId: id,
    seq: last.seq,
    head: F.entryHash(last),
    lastTime: last.time,
    sealedAt,
    note: textOption(options.note, 'note'),
  };
  const sp = F.checkpointProblem(statement);
  if (sp) F.reject(sp);
  const message = F.payload(statement);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(options.key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type: 'checkpoint',
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement,
    signature: Buffer.from(signature).toString('base64'),
  };
}

function signedCheckpoints(checkpoints) {
  const list = Array.isArray(checkpoints) ? checkpoints : [checkpoints];
  if (list.length === 0) F.reject('at least one checkpoint is needed');
  const copies = list.map((e) => {
    try {
      return F.plainCopy(e);
    } catch (err) {
      return F.reject('a checkpoint is not plain data');
    }
  });
  const parsed = copies.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('a checkpoint is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== p.statement.writerKeyId) F.reject('a checkpoint is not signed by the writer it names');
    if (!native.verify(p.publicKey, F.payload(p.statement), p.signature)) F.reject('a checkpoint carries a signature that does not verify');
    return p;
  });
  return { copies, parsed };
}

function attach(copies, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== copies.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return copies.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(checkpoints, options) {
  const { copies, parsed } = signedCheckpoints(checkpoints);
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  return attach(copies, await qstamp.stamp(Object.assign(own(options), { records, kind: 'record' })));
}

async function complete(checkpoints, pending, options) {
  const { copies, parsed } = signedCheckpoints(checkpoints);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(qstamp.KINDS.record)) {
    F.reject('the pending stamp does not belong to these checkpoints');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these checkpoints, or they are in another order');
  });
  return attach(copies, await qstamp.complete(p, own(options)));
}

function toJsonl(log) {
  if (!Array.isArray(log)) F.reject('the log is a list of entries');
  return log.map((e) => JSON.stringify(F.parseEntry(e), F.ENTRY_FIELDS) + '\n').join('');
}

function fromJsonl(text) {
  if (typeof text !== 'string') F.reject('the log text is a string');
  if (text.charCodeAt(0) === 0xfeff) F.reject('the log text starts with a byte order mark');
  if (text.length === 0) F.reject('the log text is empty');
  if (!text.endsWith('\n')) F.reject('the log text must end with a newline, the last line may be incomplete');
  let count = 0;
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) {
    count += 1;
    if (count > ENTRIES_MAX) F.reject('the log has more than ' + ENTRIES_MAX + ' entries');
  }
  const lines = text.slice(0, -1).split('\n');
  return lines.map((line, i) => {
    if (line.length === 0 || line.length > LINE_MAX) F.reject('line ' + (i + 1) + ' is empty or longer than ' + LINE_MAX + ' characters');
    let obj;
    try {
      obj = JSON.parse(line);
    } catch (e) {
      F.reject('line ' + (i + 1) + ' is not valid JSON');
    }
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj) || JSON.stringify(obj, F.ENTRY_FIELDS) !== line) F.reject('line ' + (i + 1) + ' is not an entry in canonical form, with fields in their fixed order and no spaces, repeated fields or alternative escapes');
    return obj;
  });
}

module.exports = { generateKey, publicKey, keyId, describeKey, create, append, heartbeat, checkpoint, anchor, complete, chainOf, chainProblem, toJsonl, fromJsonl, ENTRIES_MAX, LINE_MAX };
