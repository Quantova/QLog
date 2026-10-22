#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ql = require('..');
const { chainProblem } = require('../lib/log');
const F = require('../lib/format');

const ENVELOPE_MAX = 1024 * 1024;
const CHECKPOINT_MAX = 64 * 1024;
const LOCK_WAIT_MS = 5000;
const PAYLOAD_MAX = 64 * 1024 * 1024;
const PAYLOADS_TOTAL_MAX = 256 * 1024 * 1024;
const LOG_MAX = 256 * 1024 * 1024;
const STATE_FORMAT = 'qlog-append-state/1';
const STATE_MAX = 4096;
const LINE_BYTES_MAX = 4 * 8192 + 1;

const HELP = `qlog, post quantum tamper evident logs with Quantova time proofs

  qlog keygen <keyfile>
  qlog key <keyfile>
  qlog init <log> --key <writer keyfile> [--note TEXT]
  qlog append <log> --kind event|intent|action (--payload-file FILE | --digest HEX)
              [--ref SEQ --after <anchored checkpoint>] [--note TEXT]
  qlog heartbeat <log> [--note TEXT]
  qlog checkpoint <log> --key <writer keyfile> [--note TEXT] --out FILE
  qlog anchor <checkpoint>... --seed-file <file> [--index N] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]
  qlog complete <checkpoint>... --pending FILE [--tx ID] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]...
                [--allow-loopback]
  qlog verify <log> (--writer-key-id HEX | --writer-public-key FILE) [--checkpoint FILE]...
              [--max-gap SECONDS] [--require-intent-first] [--payload SEQ=FILE]...
              [--allow-unanchored] [--at TIME] [--max-anchor-delay SECONDS] [--expect-sender ADDRESS]... [--rpc URL]...
              [--trust-custom-endpoints] [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--json]

A log is a file of JSON lines. Appending needs no key, the writer seals the head with a signed
checkpoint and anchors it, and only sealed entries are proven. An action names its intent with --ref
and the anchored checkpoint covering that intent with --after. If an anchor is interrupted after its
transaction was sent, the pending stamp is kept beside the first checkpoint and complete finishes it.
With --max-gap every entry must be proven by an anchored checkpoint within that gap of its own time, so
heartbeats written after a silence verify INVALID. An anchor counts only when it is proven by a finality
certificate or by official endpoints of two different operators, any other anchor is UNPROVEN and never VALID.
Endpoints given with --rpc are consulted by verify only with --trust-custom-endpoints, loopback endpoints only
with --allow-loopback and private network endpoints only when named with --allow-endpoint. --expect-sender names
the account that must have signed each anchor.

Exit codes are 0 for valid, 1 for invalid or an error, 2 for indeterminate or unproven and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

function endpointOptions(flags) {
  const out = {};
  if (flags.rpc) out.clients = flags.rpc;
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['trust-single-endpoint']) out.trustSingleEndpoint = true;
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  return out;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  init: { flags: ['force'], values: ['key', 'note'] },
  append: { flags: [], values: ['kind', 'payload-file', 'digest', 'ref', 'after', 'note'] },
  heartbeat: { flags: [], values: ['note'] },
  checkpoint: { flags: ['force'], values: ['key', 'note', 'out'] },
  anchor: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee'], multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx'], multi: ['rpc', 'allow-endpoint'] },
  verify: { flags: ['allow-unanchored', 'require-intent-first', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'], values: ['writer-key-id', 'writer-public-key', 'max-gap', 'at', 'max-anchor-delay'], multi: ['checkpoint', 'payload', 'rpc', 'allow-endpoint', 'expect-sender'] },
};

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(code);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      void e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
}

function readJson(file, what, invalidExit, limit) {
  const max = limit || ENVELOPE_MAX;
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(max + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > max) throw bad('the ' + what + ' is larger than ' + max + ' bytes');
  try {
    return strictJson(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb\u00ad\u180e\ufe00-\ufe0f]|\uDB40[\uDC00-\uDC7F]/g, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = ql.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + ql.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => ql.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readPayload(file) {
  const fd = openRegular(file, 'payload file');
  try {
    return readAll(fd, 'payload file', PAYLOAD_MAX);
  } finally {
    fs.closeSync(fd);
  }
}

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function readAll(fd, what, max) {
  const size = fs.fstatSync(fd).size;
  if (size > max) {
    const err = new Error('the ' + what + ' is larger than ' + max + ' bytes');
    err.invalid = true;
    throw err;
  }
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = fs.readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  return buf.subarray(0, off);
}

function decodeLog(buf) {
  try {
    return UTF8.decode(buf);
  } catch (e) {
    const err = new Error('the log is not valid UTF-8 text');
    err.invalid = true;
    throw err;
  }
}

function entriesOf(text) {
  try {
    return ql.fromJsonl(text);
  } catch (e) {
    const err = new Error('the log is damaged, ' + e.message);
    err.invalid = true;
    throw err;
  }
}

function readLogText(file) {
  const fd = openRegular(file, 'log file');
  try {
    return decodeLog(readAll(fd, 'log file', LOG_MAX));
  } finally {
    fs.closeSync(fd);
  }
}

function lockPath(file) {
  let dir = path.dirname(file);
  try {
    dir = fs.realpathSync(dir);
  } catch (e) {
    throw usageError('the folder of the log file ' + safe(file) + ' could not be opened');
  }
  return path.join(dir, '.' + path.basename(file) + '.lock');
}

function holderOf(lock) {
  try {
    const pid = Number(fs.readFileSync(lock, { encoding: 'utf8', flag: fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) }).trim());
    if (!Number.isSafeInteger(pid) || pid <= 0) return null;
    try {
      process.kill(pid, 0);
      return { pid, running: true };
    } catch (e) {
      return { pid, running: e.code !== 'ESRCH' };
    }
  } catch (e) {
    return null;
  }
}

async function acquire(lock) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (let wait = 20; ; wait = Math.min(wait * 2, 400)) {
    try {
      return fs.openSync(lock, 'wx', 0o600);
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
    if (Date.now() >= deadline) {
      const holder = holderOf(lock);
      const err = new Error(holder && !holder.running
        ? 'the log is locked by process ' + holder.pid + ' which is no longer running, remove ' + safe(lock) + ' once no other writer is active'
        : 'the log stayed locked by another writer for ' + LOCK_WAIT_MS / 1000 + ' seconds, nothing was appended');
      throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
}

async function withLock(file, fn) {
  const lock = lockPath(file);
  let fd = await acquire(lock);
  pendingTemp.add(lock);
  try {
    fs.writeSync(fd, String(process.pid) + '\n');
    fs.closeSync(fd);
    fd = undefined;
    return fn();
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(lock, { force: true });
    pendingTemp.delete(lock);
  }
}

function statePath(file) {
  const lock = lockPath(file);
  return lock.slice(0, -'.lock'.length) + '.state';
}

function readState(file) {
  let fd;
  try {
    fd = fs.openSync(statePath(file), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > STATE_MAX) return null;
    const buf = Buffer.alloc(st.size);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const s = strictJson(buf.subarray(0, n).toString('utf8'));
    const digits = /^[0-9]{1,30}$/;
    if (!s || s.format !== STATE_FORMAT) return null;
    for (const k of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'lineStart']) if (typeof s[k] !== 'string' || !digits.test(s[k])) return null;
    if (!Number.isSafeInteger(s.seq) || s.seq < 0 || typeof s.head !== 'string' || !/^[0-9a-f]{64}$/.test(s.head) || typeof s.logId !== 'string') return null;
    return s;
  } catch (e) {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

function writeState(file, fd, entry, lineStart) {
  try {
    const st = fs.fstatSync(fd, { bigint: true });
    const state = {
      format: STATE_FORMAT,
      dev: String(st.dev),
      ino: String(st.ino),
      size: String(st.size),
      mtimeNs: String(st.mtimeNs),
      ctimeNs: String(st.ctimeNs),
      lineStart: String(lineStart),
      seq: entry.seq,
      head: F.entryHash(entry),
      logId: entry.logId,
    };
    atomicWrite(statePath(file), JSON.stringify(state) + '\n', true);
  } catch (e) {
    try {
      fs.rmSync(statePath(file), { force: true });
    } catch (e2) {
      return;
    }
  }
}

function readAt(fd, offset, length) {
  const buf = Buffer.alloc(length);
  let off = 0;
  while (off < length) {
    const n = fs.readSync(fd, buf, off, length - off, offset + off);
    if (n === 0) break;
    off += n;
  }
  return buf.subarray(0, off);
}

function recordedTail(file, fd) {
  const state = readState(file);
  if (!state) return null;
  const st = fs.fstatSync(fd, { bigint: true });
  if (st.size > BigInt(LOG_MAX)) return null;
  if (String(st.dev) !== state.dev || String(st.ino) !== state.ino || String(st.size) !== state.size) return null;
  if (String(st.mtimeNs) !== state.mtimeNs || String(st.ctimeNs) !== state.ctimeNs) return null;
  const size = Number(st.size);
  const lineStart = Number(state.lineStart);
  if (lineStart >= size || size - lineStart > LINE_BYTES_MAX) return null;
  try {
    const tail = readAt(fd, lineStart, size - lineStart);
    if (tail.length !== size - lineStart || tail.indexOf(10) !== tail.length - 1) return null;
    const lines = ql.fromJsonl(decodeLog(tail));
    const last = F.parseEntry(lines[0]);
    if (last.seq !== state.seq || last.logId !== state.logId || F.entryHash(last) !== state.head) return null;
    if (lineStart === 0 && last.seq !== 0) return null;
    const log = [];
    log[last.seq] = lines[0];
    return { log, size };
  } catch (e) {
    return null;
  }
}

function appendEntry(file, build, refs) {
  return withLock(file, () => {
    const flags = fs.constants.O_RDWR | fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
    let fd;
    try {
      fd = fs.openSync(file, flags);
    } catch (e) {
      throw usageError(e.code === 'ELOOP' ? 'the log file must not be a symbolic link' : 'the log file ' + safe(file) + ' could not be opened');
    }
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile()) throw usageError('the log file must be a regular file');
      if (st.nlink !== 1) throw usageError('the log file has other hard links, which would let two writers bypass the lock');
      const recorded = refs && refs.length ? null : recordedTail(file, fd);
      let log;
      let size;
      if (recorded) {
        log = recorded.log;
        size = recorded.size;
      } else {
        const bytes = readAll(fd, 'log file', LOG_MAX);
        log = entriesOf(decodeLog(bytes));
        const problem = chainProblem(log);
        if (problem) {
          const err = new Error('the log is damaged and nothing was appended, ' + problem.message);
          err.invalid = true;
          throw err;
        }
        size = bytes.length;
      }
      const entry = build(log);
      const line = Buffer.from(JSON.stringify(entry, ql.ENTRY_FIELDS) + '\n', 'utf8');
      try {
        let off = 0;
        while (off < line.length) off += fs.writeSync(fd, line, off, line.length - off);
        fs.fsyncSync(fd);
      } catch (e) {
        try {
          fs.ftruncateSync(fd, size);
          fs.fsyncSync(fd);
        } catch (e2) {
          throw new Error('the entry could not be written (' + (e.code || 'error') + ') and the log could not be restored to its previous ' + size + ' bytes, so it now ends with an incomplete line that must be removed by hand');
        }
        throw e;
      }
      writeState(file, fd, entry, size);
      return entry;
    } finally {
      fs.closeSync(fd);
    }
  });
}

function readDigestOption(flags) {
  const given = ['payload-file', 'digest'].filter((k) => flags[k] !== undefined);
  if (given.length !== 1) throw usageError('give exactly one of --payload-file or --digest');
  if (flags.digest !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(flags.digest)) throw usageError('--digest is 64 lowercase hex characters, the SHA3-256 of the payload');
    return { digest: flags.digest };
  }
  return { payload: readPayload(flags['payload-file']) };
}

function seqFlag(value, name) {
  if (!/^\d{1,9}$/.test(value)) throw usageError('--' + name + ' is a whole number');
  return Number(value);
}

async function cmdInit(positional, flags) {
  if (positional.length !== 1) throw usageError('init takes one log file path');
  const entry = withSeed(need(flags, 'key'), '--key', (seed) => ql.create({ key: seed, note: flags.note }));
  atomicWrite(positional[0], ql.toJsonl([entry]), flags.force);
  console.log('log ' + entry.logId + ' started by writer ' + entry.digest + ', written to ' + safe(positional[0]));
  return 0;
}

async function cmdAppend(positional, flags) {
  if (positional.length !== 1) throw usageError('append takes one log file path');
  const kind = need(flags, 'kind');
  if (!['event', 'intent', 'action'].includes(kind)) throw usageError('--kind is event, intent or action');
  if ((flags.ref !== undefined || flags.after !== undefined) && kind !== 'action') throw usageError('only an action takes --ref and --after');
  if (flags.after !== undefined && flags.ref === undefined) throw usageError('--after needs --ref, the intent the action carries out');
  const opts = Object.assign({ kind, note: flags.note }, readDigestOption(flags));
  if (flags.ref !== undefined) opts.ref = seqFlag(flags.ref, 'ref');
  if (flags.after !== undefined) opts.after = readJson(flags.after, 'checkpoint', false, CHECKPOINT_MAX);
  const entry = await appendEntry(positional[0], (log) => ql.append(log, opts), opts.ref === undefined ? [] : [opts.ref]);
  console.log(kind + ' ' + entry.seq + ' appended to log ' + entry.logId);
  return 0;
}

async function cmdHeartbeat(positional, flags) {
  if (positional.length !== 1) throw usageError('heartbeat takes one log file path');
  const entry = await appendEntry(positional[0], (log) => ql.heartbeat(log, { note: flags.note }));
  console.log('heartbeat ' + entry.seq + ' appended to log ' + entry.logId);
  return 0;
}

async function cmdCheckpoint(positional, flags) {
  if (positional.length !== 1) throw usageError('checkpoint takes one log file path');
  const out = need(flags, 'out');
  const outStat = statOf(out);
  const logStat = statOf(positional[0]);
  if (outStat && logStat && outStat.dev === logStat.dev && outStat.ino === logStat.ino) throw usageError('--out must not be the log file');
  const log = entriesOf(readLogText(positional[0]));
  const problem = chainProblem(log);
  if (problem) {
    const err = new Error('the log is damaged and cannot be sealed, ' + problem.message);
    err.invalid = true;
    throw err;
  }
  const env = withSeed(need(flags, 'key'), '--key', (seed) => ql.checkpoint(log, { key: seed, note: flags.note }));
  atomicWrite(out, asciiJson(env) + '\n', flags.force);
  console.log('checkpoint of log ' + env.statement.logId + ' through entry ' + env.statement.seq + ', head ' + env.statement.head + ', written to ' + safe(out));
  return 0;
}

function distinctFiles(files) {
  const seen = new Set();
  for (const f of files) {
    const st = statOf(f);
    if (!st || !st.isFile()) throw usageError('the checkpoint ' + safe(f) + ' is not a regular file');
    const id = st.dev + ':' + st.ino;
    if (seen.has(id)) throw usageError('the checkpoint ' + safe(f) + ' was given twice');
    seen.add(id);
    try {
      fs.accessSync(path.dirname(f), fs.constants.W_OK);
      fs.accessSync(f, fs.constants.W_OK);
    } catch (e) {
      throw usageError('the checkpoint ' + safe(f) + ' or its folder is not writable, so the anchor could not be saved');
    }
  }
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  let lost = false;
  anchored.forEach((env, i) => {
    try {
      atomicWrite(files[i], asciiJson(env) + '\n', true);
      console.log('anchored ' + safe(files[i]) + ' in transaction ' + safe(env.anchor.anchor.tx));
    } catch (e) {
      lost = true;
      console.error('the anchored checkpoint could not be written to ' + safe(files[i]) + ', it follows on standard output');
      process.stdout.write(asciiJson(env) + '\n');
    }
  });
  return lost ? 1 : 0;
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more checkpoints');
  distinctFiles(positional);
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'checkpoint', true, CHECKPOINT_MAX));
  let index = 0;
  if (flags.index !== undefined) index = seqFlag(flags.index, 'index');
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await ql.anchor(envs, { seed, index, network: 'testnet', ...endpointOptions(flags), maxFee: flags['max-fee'], onPending: keep });
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      try {
        keep(e.pending);
        e.message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qlog complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        e.message += ', the pending stamp follows on standard output, keep it to finish the anchor';
        process.stdout.write(asciiJson(e.pending) + '\n');
      }
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  const code = saveAnchored(positional, anchored);
  if (code === 0 && saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return code;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the checkpoints given to anchor, in the same order');
  distinctFiles(positional);
  const pendingFile = need(flags, 'pending');
  const pending = readJson(pendingFile, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'checkpoint', true, CHECKPOINT_MAX)).map((e) => {
    if (e && typeof e === 'object' && !Array.isArray(e)) delete e.anchor;
    return e;
  });
  const anchored = await ql.complete(envs, pending, endpointOptions(flags));
  const code = saveAnchored(positional, anchored);
  if (code === 0) {
    fs.rmSync(pendingFile, { force: true });
    for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  }
  return code;
}

function payloadsOf(list) {
  let total = 0;
  const seen = new Set();
  return list.map((spec) => {
    const m = /^(\d{1,9})=(.+)$/s.exec(spec);
    if (!m) throw usageError('--payload is SEQ=FILE');
    const seq = Number(m[1]);
    if (seen.has(seq)) throw usageError('--payload was given twice for entry ' + seq);
    seen.add(seq);
    const bytes = readPayload(m[2]);
    total += bytes.length;
    if (total > PAYLOADS_TOTAL_MAX) throw usageError('the payload files together are larger than ' + PAYLOADS_TOTAL_MAX + ' bytes');
    return { seq, bytes };
  });
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one log file');
  if (flags['writer-key-id'] !== undefined && flags['writer-public-key'] !== undefined) throw usageError('give --writer-key-id or --writer-public-key, not both');
  if (flags['writer-key-id'] === undefined && flags['writer-public-key'] === undefined) throw usageError('give the expected writer with --writer-key-id or --writer-public-key');
  if (flags['writer-key-id'] !== undefined && !/^[0-9a-f]{64}$/.test(flags['writer-key-id'])) throw usageError('--writer-key-id is 64 lowercase hex characters');
  const opts = { requireAnchor: !flags['allow-unanchored'], requireIntentFirst: !!flags['require-intent-first'] };
  if (flags['writer-key-id'] !== undefined) opts.writerKeyId = flags['writer-key-id'];
  if (flags['writer-public-key'] !== undefined) {
    const desc = readJson(flags['writer-public-key'], 'writer key', false, CHECKPOINT_MAX);
    if (!desc || desc.format !== 'qlog-key/1' || typeof desc.publicKey !== 'string') throw usageError('the writer key file is not a qlog-key/1 description');
    opts.writerPublicKey = desc.publicKey;
  }
  const cps = flags.checkpoint || [];
  if (cps.length > 1000) throw usageError('at most 1000 checkpoints can be given');
  opts.checkpoints = cps.map((f) => readJson(f, 'checkpoint', true, CHECKPOINT_MAX));
  if (flags['max-gap'] !== undefined) opts.maxGapSeconds = seqFlag(flags['max-gap'], 'max-gap');
  if (flags.payload) {
    if (flags.payload.length > 1000) throw usageError('at most 1000 payloads can be given');
    opts.payloads = payloadsOf(flags.payload);
  }
  if (flags.at !== undefined) opts.at = flags.at;
  if (flags['max-anchor-delay'] !== undefined) {
    if (!/^[1-9][0-9]{0,9}$/.test(flags['max-anchor-delay'])) throw usageError('--max-anchor-delay is a whole number of seconds');
    opts.maxAnchorDelay = Number(flags['max-anchor-delay']);
  }
  Object.assign(opts, endpointOptions(flags));
  if (flags['expect-sender']) opts.expectedSender = flags['expect-sender'];
  const text = readLogText(positional[0]);
  const res = await ql.verify(text, opts);
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.logId) console.log('log   ' + res.logId);
    if (res.entries !== undefined) console.log('entries ' + res.entries + ', sealed through ' + res.sealedThrough + ', unsealed ' + res.unsealed);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate || c.unproven ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' || res.status === 'unproven' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, init: cmdInit, append: cmdAppend, heartbeat: cmdHeartbeat, checkpoint: cmdCheckpoint, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify }[command];
  return run(positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe(friendly(e)).slice(0, 600));
    process.exitCode = e && (e.usage || e.code === 'QLOG_INVALID_INPUT') ? 64 : 1;
  },
);
