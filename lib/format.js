// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qlog/1';
const ENTRY_FORMAT = 'qlog-entry/1';
const ALGORITHM = 'ML-DSA-65';
const KINDS = Object.freeze(['genesis', 'event', 'intent', 'action', 'heartbeat']);
const KEY_DOMAIN = Buffer.from('quantova/qlog/key/1', 'ascii');
const ENTRY_DOMAIN = Buffer.from('quantova/qlog/entry/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qlog/anchor/1', 'ascii');
const MAGIC = Buffer.from('QLOG', 'ascii');
const ENTRY_MAGIC = Buffer.from('QLGE', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const NOTE_MAX = 1000;
const ZERO = '0'.repeat(64);
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const BLOCK_ID = /^QBK1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{6,100}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;
const ENTRY_FIELDS = Object.freeze(['format', 'logId', 'seq', 'prev', 'time', 'kind', 'ref', 'after', 'digest', 'note']);
const CHECKPOINT_FIELDS = Object.freeze(['logId', 'writerKeyId', 'seq', 'head', 'lastTime', 'sealedAt', 'note']);

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QLOG_INVALID_ENVELOPE';
  throw e;
}

function badEntry(message) {
  const e = new Error('the entry is not valid, ' + message);
  e.code = 'QLOG_INVALID_ENTRY';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QLOG_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

const EMPTY_DIGEST = sha3(Buffer.alloc(0)).toString('hex');

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function textProblem(value, max, what) {
  if (typeof value !== 'string') return what + ' must be text';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function seqProblem(value, what) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) return what + ' must be a whole number from 0';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function sameKeys(obj, fields) {
  return Object.keys(obj).sort().join(',') === fields.slice().sort().join(',');
}

function entryProblem(e) {
  if (e === null || typeof e !== 'object' || Array.isArray(e)) return 'an entry must be an object';
  if (!sameKeys(e, ENTRY_FIELDS)) return 'an entry holds exactly ' + ENTRY_FIELDS.join(', ');
  if (e.format !== ENTRY_FORMAT) return 'format must be ' + ENTRY_FORMAT;
  const p = pattern(e.logId, HEX16, 'logId', '32 lowercase hex characters')
    || seqProblem(e.seq, 'seq')
    || pattern(e.prev, HEX32, 'prev', '64 lowercase hex characters')
    || timeProblem(e.time, 'time')
    || (KINDS.includes(e.kind) ? null : 'kind must be one of ' + KINDS.join(', '))
    || pattern(e.digest, HEX32, 'digest', '64 lowercase hex characters')
    || textProblem(e.note, NOTE_MAX, 'note');
  if (p) return p;
  if (e.ref !== null) {
    const rp = seqProblem(e.ref, 'ref');
    if (rp) return rp;
  }
  if (e.kind === 'genesis') {
    if (e.seq !== 0) return 'only the first entry may be the genesis entry';
    if (e.prev !== ZERO) return 'the genesis entry must have an all zero prev';
    if (e.ref !== null) return 'the genesis entry has no ref';
  } else {
    if (e.seq === 0) return 'the first entry must be the genesis entry';
    if (e.prev === ZERO) return 'only the genesis entry may have an all zero prev';
  }
  if (typeof e.after !== 'string' || (e.after !== '' && !BLOCK_ID.test(e.after))) return 'after must be empty or a Quantova block identifier';
  if (e.kind === 'action') {
    if (e.ref !== null && e.ref >= e.seq) return 'an action may only refer to an earlier entry';
    if (e.after !== '' && e.ref === null) return 'only an action that names its intent may carry after';
  } else if (e.ref !== null) {
    return 'only an action may carry a ref';
  } else if (e.after !== '') {
    return 'only an action may carry after';
  }
  if (e.kind === 'heartbeat' && e.digest !== EMPTY_DIGEST) return 'a heartbeat entry carries the digest of empty content';
  return null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function entryBytes(e) {
  const ref = e.ref === null ? field(Buffer.from([0])) : Buffer.concat([field(Buffer.from([1])), u64(e.ref)]);
  return Buffer.concat([ENTRY_MAGIC, Buffer.from([VERSION]), ascii(e.kind), hex(e.logId), u64(e.seq), hex(e.prev), ascii(e.time), ref, ascii(e.after), hex(e.digest), utf8(e.note)]);
}

function entryHash(e) {
  return sha3(ENTRY_DOMAIN, Buffer.from([0]), entryBytes(e)).toString('hex');
}

function parseEntry(value) {
  let e;
  try {
    e = plainCopy(value);
  } catch (err) {
    badEntry('it is not plain data');
  }
  const problem = entryProblem(e);
  if (problem) badEntry(problem);
  return e;
}

function checkpointProblem(st) {
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  if (!sameKeys(st, CHECKPOINT_FIELDS)) return 'a checkpoint statement holds exactly ' + CHECKPOINT_FIELDS.join(', ');
  return pattern(st.logId, HEX16, 'logId', '32 lowercase hex characters')
    || pattern(st.writerKeyId, HEX32, 'writerKeyId', '64 lowercase hex characters')
    || seqProblem(st.seq, 'seq')
    || pattern(st.head, HEX32, 'head', '64 lowercase hex characters')
    || timeProblem(st.lastTime, 'lastTime')
    || timeProblem(st.sealedAt, 'sealedAt')
    || (Date.parse(st.sealedAt) < Date.parse(st.lastTime) ? 'sealedAt cannot be earlier than lastTime' : null)
    || textProblem(st.note, NOTE_MAX, 'note');
}

function payload(st) {
  return Buffer.concat([MAGIC, Buffer.from([VERSION]), ascii('checkpoint'), hex(st.logId), hex(st.writerKeyId), u64(st.seq), hex(st.head), ascii(st.lastTime), ascii(st.sealedAt), utf8(st.note)]);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function parse(envelope) {
  let env;
  try {
    env = plainCopy(envelope);
  } catch (e) {
    fail('it is not plain data');
  }
  exactKeys(env, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (env.format !== FORMAT) fail('format must be ' + FORMAT);
  if (env.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (env.type !== 'checkpoint') fail('type must be checkpoint');
  exactKeys(env.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof env.signer.id !== 'string' || !HEX32.test(env.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(env.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  const problem = checkpointProblem(env.statement);
  if (problem) fail(problem);
  const signature = decodeBase64(env.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(env, 'anchor') ? env.anchor : undefined;
  return { type: 'checkpoint', signerId: env.signer.id, publicKey, statement: env.statement, signature, anchor };
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(parsed.statement), parsed.signature);
}

module.exports = {
  FORMAT, ENTRY_FORMAT, ALGORITHM, KINDS, ENTRY_FIELDS, BLOCK_ID, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, NOTE_MAX, ZERO, EMPTY_DIGEST,
  sha3, keyIdOf, textProblem, timeProblem, entryProblem, entryHash, parseEntry, checkpointProblem, payload, parse, anchorDigest, reject, plainCopy,
};
