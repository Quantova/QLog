'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');
const { hostileCampaign, summary } = require('./hostile');
const { honest, ROOT } = require('./honest');
const { qstampRoot } = require('./chain');

const qstamp = require(qstampRoot(ROOT));
const BIN = path.join(ROOT, 'bin', 'qlog.js');
const CHECKPOINT_MAX = 64 * 1024;
const ENVELOPE_MAX = 1024 * 1024;
const LINE_MAX = 8192;

test('hostile log, checkpoint and pending stamp files make the command line exit non zero quickly and never print VALID', async (t) => {
  const w = await honest();
  const dir = tempDir('qlog-ok');
  try {
    const put = (name, text) => {
      const f = path.join(dir, name);
      fs.writeFileSync(f, text);
      return f;
    };
    const logText = w.ql.toJsonl(w.log);
    const log = put('honest.jsonl', logText);
    const head = put('head.json', JSON.stringify(w.seals.head, null, 2) + '\n');
    const headCopy = put('head-copy.json', JSON.stringify(w.seals.head));
    const pending = put('pending.json', '{}');
    const intent = put('intent.json', JSON.stringify(w.anchored.intent));
    const openIntent = w.ql.toJsonl(w.log.slice(0, 3));
    const appendTo = put('append.jsonl', openIntent);
    const digest = 'ab'.repeat(32);
    const verifyTail = ['--writer-key-id', w.writerKeyId, '--allow-unanchored', '--at', w.at];

    const control = await runCli(BIN, ['verify', log, '--checkpoint', head].concat(verifyTail));
    assert.strictEqual(control.code, 0, control.out + control.err);
    assert.ok(SAYS_VALID.test(control.out), control.out);
    const appendControl = await runCli(BIN, ['append', put('append-control.jsonl', openIntent), '--kind', 'action', '--ref', '2', '--digest', digest, '--after', intent]);
    assert.strictEqual(appendControl.code, 0, appendControl.out + appendControl.err);

    const logs = await hostileCampaign({
      bin: BIN,
      tag: 'qlog-log',
      cap: LINE_MAX,
      validText: logText.slice(0, -1),
      suffix: '\n',
      commands: [
        (file) => ['verify', file, '--checkpoint', head].concat(verifyTail),
        (file) => ['verify', file, '--checkpoint', head].concat(verifyTail, ['--json']),
        (file) => ['heartbeat', file],
        (file) => ['append', file, '--kind', 'event', '--digest', digest],
      ],
    });
    t.diagnostic('log ' + summary(logs.results, logs.unchanged));

    const checkpoints = await cliCampaign({
      bin: BIN,
      tag: 'qlog-cp',
      cap: CHECKPOINT_MAX,
      validText: JSON.stringify(w.seals.head),
      commands: [
        (file) => ['verify', log, '--checkpoint', file].concat(verifyTail),
        (file) => ['verify', log, '--checkpoint', file].concat(verifyTail, ['--json']),
        (file) => ['complete', file, '--pending', pending],
      ],
    });
    t.diagnostic('checkpoint ' + checkpoints.length + ' runs, slowest ' + Math.max(...checkpoints.map((r) => r.ms)) + ' ms');

    const afters = await cliCampaign({
      bin: BIN,
      tag: 'qlog-after',
      cap: CHECKPOINT_MAX,
      validText: JSON.stringify(w.anchored.intent),
      commands: [
        (file) => ['append', appendTo, '--kind', 'action', '--ref', '2', '--digest', digest, '--after', file],
      ],
    });
    t.diagnostic('anchored checkpoint ' + afters.length + ' runs, slowest ' + Math.max(...afters.map((r) => r.ms)) + ' ms');
    assert.strictEqual(fs.readFileSync(appendTo, 'utf8'), openIntent);

    const pendings = await hostileCampaign({
      bin: BIN,
      tag: 'qlog-pending',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify({ format: qstamp.PENDING_FORMAT, kind: String(qstamp.KINDS.record), records: [{ alg: 'sha3-256', digest: w.ql.anchorDigest(w.seals.head) }] }),
      commands: [(file) => ['complete', headCopy, '--pending', file]],
    });
    t.diagnostic('pending stamp ' + summary(pendings.results, pendings.unchanged));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
