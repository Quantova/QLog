// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const L = require('./lib/log');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: L.generateKey,
  publicKey: L.publicKey,
  keyId: L.keyId,
  describeKey: L.describeKey,
  create: L.create,
  append: L.append,
  heartbeat: L.heartbeat,
  checkpoint: L.checkpoint,
  anchor: L.anchor,
  complete: L.complete,
  verify,
  toJsonl: L.toJsonl,
  fromJsonl: L.fromJsonl,
  entryHash: (entry) => F.entryHash(F.parseEntry(entry)),
  anchorDigest: (checkpoint) => F.anchorDigest(F.parse(checkpoint)).toString('hex'),
  FORMAT: F.FORMAT,
  ENTRY_FORMAT: F.ENTRY_FORMAT,
  ENTRY_FIELDS: F.ENTRY_FIELDS,
  ALGORITHM: F.ALGORITHM,
  KINDS: F.KINDS,
};
