'use strict';

const fs = require('fs');
const assert = require('node:assert');
const { hostileFiles, runCli, tempDir, SAYS_VALID } = require('./fuzz');

function regular(file) {
  try {
    return fs.lstatSync(file).isFile();
  } catch (e) {
    return false;
  }
}

function holds(file, text) {
  if (!regular(file) || fs.statSync(file).size !== Buffer.byteLength(text)) return false;
  return fs.readFileSync(file, 'utf8') === text;
}

async function hostileCampaign(o) {
  const dir = tempDir(o.tag || 'qcli');
  const results = [];
  const unchanged = [];
  try {
    const all = hostileFiles(dir, o.validText, o.cap);
    const suffix = o.suffix || '';
    if (suffix) for (const f of all) if (regular(f.file)) fs.appendFileSync(f.file, suffix);
    const honestText = o.validText + suffix;
    const files = all.filter((f) => {
      if (!holds(f.file, honestText)) return true;
      unchanged.push(f.name);
      return false;
    });
    for (const variant of o.commands) {
      const runs = await Promise.all(files.map(async (f) => ({ f, r: await runCli(o.bin, variant(f.file), o.limitMs) })));
      for (const { f, r } of runs) {
        const where = f.name + ' with ' + variant('FILE').join(' ');
        assert.strictEqual(r.signal, null, where + ' did not finish within the limit, it was stopped after ' + r.ms + ' ms');
        assert.notStrictEqual(r.code, 0, where + ' exited 0\n' + r.out.slice(0, 400));
        assert.ok(!SAYS_VALID.test(r.out) && !SAYS_VALID.test(r.err), where + ' printed VALID\n' + r.out.slice(0, 400));
        results.push({ name: f.name, code: r.code, ms: r.ms });
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { results, unchanged };
}

function summary(results, unchanged) {
  const slowest = results.length ? Math.max(...results.map((r) => r.ms)) : 0;
  return results.length + ' runs, slowest ' + slowest + ' ms' + (unchanged.length ? ', identical to the honest file and left out ' + unchanged.join(' ') : '');
}

module.exports = { hostileCampaign, summary };
