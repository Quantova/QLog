// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');

const RealDate = Date;
const KEY = 'QUANTOVA_TEST_CLOCK_SHIFT_MS';
if (!/^[0-9]+$/.test(process.env[KEY] || '')) {
  process.env[KEY] = String(Math.max(0, (qstamp.NETWORKS.testnet.genesisTime + 30 * 86400) * 1000 - RealDate.now()));
}
const SHIFT_MS = Number(process.env[KEY]);

if (SHIFT_MS > 0 && !RealDate.shiftedForGenesis) {
  class ShiftedDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(RealDate.now() + SHIFT_MS);
      else super(...args);
    }

    static now() {
      return RealDate.now() + SHIFT_MS;
    }
  }
  ShiftedDate.shiftedForGenesis = true;
  globalThis.Date = ShiftedDate;
}
