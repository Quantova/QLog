# QLog

QLog is a post quantum tamper evident log. It keeps an ordered record of events, intentions and actions in which every entry is bound to the one before it by a SHA3 hash, and the writer periodically seals the head of the record with a checkpoint signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204. Each checkpoint can carry a Qstamp time proof recorded on the Quantova network. Once a checkpoint is anchored, no entry it covers can be inserted, reordered or changed without detection, and no entry it covers can be removed without detection by a verifier that holds that checkpoint, and an action can be shown to have been recorded only after its intent was anchored in public.

## What QLog is

An AI agent, a payment system or an operations team produces a stream of decisions and actions. When a dispute, an incident or an audit arises, the record of that stream is the evidence. An ordinary log file can be edited by whoever controls the system that wrote it, so it proves nothing to an outside party.

QLog turns such a stream into evidence. Every entry carries the hash of the entry before it, so the whole record forms a single chain. At intervals the writer signs a checkpoint that commits to the latest entry and anchors it on the Quantova network. A verifier holding the log, the checkpoints and the public key of the writer can then confirm that the record is unaltered and complete up to the latest anchored checkpoint the verifier holds, when each part of it existed, and that every action was written only after its intent had been anchored, without trusting the writer, the operator of the system or Quantova Inc.

QLog is standalone. It runs on the systems of the organisation, holds its keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## Why organisations need it

Regulators now expect firms to show what their automated systems did and why. The European Union AI Act requires automatic logging for high risk AI systems over their lifetime. The guidelines of the Monetary Authority of Singapore on AI risk management, operational resilience rules in banking and the record keeping rules of securities regulators all assume that the records can be trusted.

Logs held in ordinary files or databases can be rewritten by an administrator, an attacker or the system itself, and conventional signed logs depend on classical signatures that a quantum computer will be able to forge within the retention period of many records. QLog gives an append only record whose integrity and timing remain provable for that full period.

The intent rule addresses a specific problem with AI agents. An agent that anchors what it is about to do before it acts cannot later claim that a harmful action was intended differently. Each action entry names the block that anchored its intent, and a block identifier cannot be known before the block exists, so the record of the action provably came after the public record of the intent.

## Who uses it

1. Operators of AI agents that must show what each agent intended and did, and in which order.
2. Banks and payment firms that keep evidential records of payment decisions, overrides and approvals.
3. Security and operations teams that need an audit trail which an intruder with administrative access cannot rewrite.
4. Software and model providers that record releases, approvals and configuration changes.
5. Auditors, regulators and courts that need to confirm a record is complete and unaltered.

## How an organisation integrates QLog

1. Give every log a writer key. The writer key is an ML-DSA-65 key created with the keygen command or the generateKey function and held by the service that seals the log, in the secrets manager or hardware protected store of the organisation.

2. Start the log. The init command or the create function writes the genesis entry, which carries a random 128 bit log identifier and the identifier of the writer key. Every later entry belongs to that log.

3. Append entries. The application appends an event, an intent or an action for each step it wants on the record. An entry carries the SHA3 fingerprint of its content, never the content itself. An action names the earlier intent it carries out and the anchored checkpoint that covers that intent. Appending needs no key, so it adds no signing cost to the hot path.

4. Write heartbeats. A scheduled job appends a heartbeat at a fixed interval. A verifier can then require that no gap between entries exceeds that interval, which shows that the writer was running and that no period of the record is missing.

5. Seal and anchor on a schedule. The sealing service signs a checkpoint over the latest entry and anchors it through a funded Quantova account. An agent that must prove intent before action seals and anchors after each intent and before carrying it out.

6. Keep the content. The organisation keeps the content of each entry, such as the request, the decision or the payment instruction, in its own systems. It can disclose a single entry and its content without revealing any other part of the record.

7. Verify when evidence is needed. The organisation hands the log, its checkpoints and any disclosed content to the party that asks. That party verifies them against the writer key it expects, with the verify command, the library or the independent procedure below. Verification always requires the expected writer, so a log started by any other key is rejected.

## Integration patterns

1. Agent frameworks. A tool wrapper appends an intent before any tool that moves money or makes a commitment, seals and anchors it, runs the tool, and then appends the action naming the anchored intent.
2. Approval workflows. Each approval, override and rejection is appended as an event, so the order of decisions can be shown.
3. Security audit trails. Administrative actions on a system are appended as they happen and sealed every few minutes, so an intruder cannot remove the trace of an intrusion that was already sealed.
4. Release records. Every build, review and deployment is appended, and the release record is sealed before the release ships.
5. Supervisory sampling. An auditor receives the log and its checkpoints, verifies the whole chain and requests the content of selected entries to compare with their fingerprints.

## What is published and what stays private

The log, the checkpoints and the content of every entry stay with the organisation and the parties it chooses to share them with. Entries hold only a SHA3 fingerprint of their content and a note chosen by the application.

When a checkpoint is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed checkpoint and cannot be reversed into the log identifier, the entries, their content or any other field.

## Cryptographic construction

1. Keys. A writer key is a 32 byte seed from which an ML-DSA-65 key pair is derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qlog/key/1, the byte 0x00 and the 1952 byte public key.

2. Entries. Each entry has a log identifier of 16 bytes, a sequence number starting at 0, the hash of the previous entry, a time in UTC with millisecond precision, a kind, an optional reference, an optional anchor block, a 32 byte digest and a note. The kind is genesis, event, intent, action or heartbeat. Only the first entry is the genesis entry, its previous hash is 32 zero bytes and its digest is the identifier of the writer key. The digest of a heartbeat is the SHA3 hash of empty content. Only an action may carry a reference, and it must name an earlier intent of the same log. Only an action with a reference may carry an anchor block, which is the Quantova block identifier of the anchor of a checkpoint covering that intent. The log identifier is always chosen at random. Times never decrease along the log.

3. Entry encoding. An entry is encoded as the ASCII bytes QLGE and the version byte 1, followed by the kind, the log identifier, the sequence number, the previous hash, the time, the reference, the anchor block, the digest and the note. Every field is an unsigned 16 bit big endian length followed by its bytes. The sequence number is an unsigned 64 bit big endian integer. The reference is a field holding the byte 0 when absent, or a field holding the byte 1 followed by the referenced sequence number. The anchor block is encoded as its ASCII text, empty when absent. Every entry therefore has exactly one encoding.

4. Entry hash. The hash of an entry is the SHA3 hash with a 256 bit output of the ASCII label quantova/qlog/entry/1, the byte 0x00 and the encoded entry. Each entry carries the hash of the entry before it, so changing, removing, inserting or reordering any entry changes the hash of every later entry.

5. Checkpoints. A checkpoint states the log identifier, the writer key identifier, the sequence number and hash of the last entry it covers, the time of that entry, the time of sealing and a note. It is encoded as the ASCII bytes QLOG, the version byte 1 and the type checkpoint, followed by these fields in this order with the same field encoding, and signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qlog/1. This context separates QLog signatures from QSign and QMandate signatures, from Quantova network transactions and from every other use of the algorithm.

6. Anchor. To anchor a checkpoint, QLog stamps the SHA3 hash of the label quantova/qlog/anchor/1, the byte 0x00, the encoded checkpoint and its signature as a Qstamp record.

7. File format. A log file holds one entry per line as JSON in canonical form, with no spaces, no repeated fields and no alternative escapes, each line ending with a newline, with the fields in the order format, logId, seq, prev, time, kind, ref, after, digest, note. A line in any other form is rejected, so every log has exactly one file representation and two readers can never interpret it differently.

## Rules applied by verification

1. Every entry is well formed, its sequence number equals its position, it belongs to the same log and carries the hash of the entry before it, its time is no earlier than that of the entry before it, and every action reference names an earlier intent.
2. The genesis entry names the expected writer.
3. A checkpoint is considered only when it concerns this log and is validly signed by the expected writer. Any other checkpoint is ignored, so no third party can disturb the result.
4. A checkpoint that covers more entries than the log holds shows that the log was cut short, and a checkpoint whose head differs from the entry at its position shows that the log was changed after sealing. Either makes the result invalid.
5. The anchor of each checkpoint is verified under the record kind with a SHA3 digest. Every anchored copy is checked and the earliest proven time is used. A checkpoint anchored more than 24 hours after its sealing time, a window the verifier may change, or anchored after a time of verification that is given, does not prove its time and is reported as not proven. An attached receipt that does not belong to its checkpoint is ignored, and one whose anchor cannot be reached leaves the result indeterminate. An anchor counts only when Qstamp reports it proven, which needs at least two pinned independent operators of the network or a light client proof. An anchor confirmed only by custom endpoints, or by a single endpoint under trustSingleEndpoint, is reported as unproven and treated as not anchored, so the result is never valid. A time of sealing later than a proven anchor, allowing five minutes for clock difference, makes the result invalid.
6. Every entry up to the highest anchored checkpoint is sealed. Entries after it are reported as unsealed.
7. No entry and no checkpoint may be dated after the time of verification, which is the time of the chain unless the verifier states another, allowing five minutes for clock difference. When the time of the chain cannot be established the result is indeterminate and the local clock is never used in its place.
8. Every entry that follows a checkpoint is dated no earlier than the sealing time of that checkpoint.
9. When a heartbeat policy is given, no two consecutive entries may be further apart than the permitted gap, every entry must be proven by the earliest anchored checkpoint covering it no later than the permitted gap after its own time, and the last entry may be no older than that gap at the time of verification. A writer that falls silent and later writes heartbeats dated across the silence is therefore shown to be invalid, because those heartbeats are anchored long after their stated times. The writer must anchor a checkpoint at least once in every period of the permitted gap.
10. When intent first is required, every action must name an intent and the block that anchored a checkpoint covering that intent but not the action. That anchor must be verified, the action must be sealed by an anchored checkpoint in a later block of the same network, and the action must claim a time no earlier than the anchor of its intent. An action that is not yet sealed, or whose intent checkpoint was not supplied, leaves the result indeterminate.
11. When content is supplied for an entry, its SHA3 fingerprint must equal the digest in the entry.

A result is valid only when the expected writer is given and every entry is sealed by an anchored checkpoint. When entries are unsealed, an anchor cannot be reached or the last heartbeat is older than the policy allows, the result is indeterminate rather than valid, so a gap in the evidence can never be mistaken for proof. A verifier may accept checkpoints without anchors explicitly, in which case every entry must still be covered by a checkpoint signed by the writer.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors and cross checked against an independent implementation. It has not been validated under FIPS 140-3. An anchor time is accepted only when Qstamp proves the anchor, either by a finality certificate checked against a pinned validator roster or by official endpoints of the network run by two different operators. An anchor confirmed by endpoints of one operator, or by endpoints chosen by the verifier, is reported as unproven and is never valid, whatever options are set. While the network has one official endpoint and no pinned roster every anchor is unproven, which is the honest result. Verification names the endpoints it consulted and says whether they are the official endpoints of the network.

Entries are bound to the writer only through checkpoints. An entry after the last checkpoint is the claim of whoever holds the file, and the writer can still alter its own unsealed entries before it seals them. The times of entries are claims of the writer, bounded above by the anchor of the checkpoint that covers them. Under a heartbeat policy each entry is proven to exist within the permitted gap of its stated time, but no anchor proves that an entry was not written earlier than its stated time, so a writer could still date an entry up to that gap later than it was written. A heartbeat policy and frequent sealing narrow both windows.

Truncation is detected only relative to the checkpoints the verifier holds. A writer that withholds its latest checkpoint and cuts the log back to an earlier one presents a log that verifies as complete up to that earlier point, and Qstamp commitments are salted, so they cannot be found on the ledger without the checkpoint. A verifier that needs completeness should therefore receive each checkpoint as it is anchored, for example through a feed to the auditor or regulator, and keep its own copy. A writer that keeps two diverging logs under the same log identifier is detected when a verifier receives checkpoints from both, because one of them will not match the log. Matching the writer key to an accountable person or system is a matter for the organisation, for example through a published key description. Notes accept only visible characters in Unicode normal form C, and a log holds at most one million entries, after which a new log is started.

## Installation

```
npm install @quantovainc/qlog
```

QLog requires Node 20 or later.

## Command line use

```
qlog keygen writer.key
qlog key writer.key > writer.pub.json

qlog init agent.log --key writer.key --note "Payments agent"

qlog append agent.log --kind intent --payload-file request.json
qlog checkpoint agent.log --key writer.key --out cp-1.json
qlog anchor cp-1.json --seed-file account.key

qlog append agent.log --kind action --ref 1 --after cp-1.json --payload-file result.json
qlog heartbeat agent.log
qlog checkpoint agent.log --key writer.key --out cp-2.json
qlog anchor cp-2.json --seed-file account.key

qlog verify agent.log --writer-public-key writer.pub.json --checkpoint cp-1.json --checkpoint cp-2.json --require-intent-first --max-gap 600 --payload 1=request.json
```

Appends to one log are serialised by a lock file beside it, a log with other hard links is refused, and each append restores the file if the write fails. After every append the tool records the size, the change times, the file identity and the hash of the last entry in a state file beside the log. The next append reads only that last entry when the log is still exactly as recorded, and checks the whole chain before it writes whenever the state file is missing or the log was changed by anything else, so the cost of an append does not grow with the length of the log and no append extends a log whose end it has not checked. The verify command always checks the whole chain. If an anchor is interrupted after its transaction was sent, the pending stamp is saved beside the first checkpoint and the complete command finishes it without paying again. Checkpoints without anchors are accepted only with the allow unanchored flag. The command exits with status 0 when the result is valid, 1 when it is invalid or cannot be read, 2 when it cannot be decided, and 64 for usage errors. Key files must be readable only by their owner, and key and log files are never followed through symbolic links.

## Programmatic use

```js
const qlog = require('@quantovainc/qlog');

const log = [qlog.create({ key: writerKey, note: 'Payments agent' })];
log.push(qlog.append(log, { kind: 'intent', payload: requestBytes }));

const sealed = qlog.checkpoint(log, { key: writerKey });
const [anchored] = await qlog.anchor(sealed, { seed: accountSeed, index: 0, network: 'testnet' });

log.push(qlog.append(log, { kind: 'action', ref: 1, after: anchored, payload: resultBytes }));

const result = await qlog.verify(qlog.toJsonl(log), {
  writerKeyId,
  checkpoints: [anchored, laterCheckpoint],
  requireIntentFirst: true,
  maxGapSeconds: 600,
});
```

## Independent verification procedure

1. Read the log file line by line, confirm each line is canonical JSON and rebuild each entry.
2. Encode each entry as described above, compute its hash and confirm that each entry carries the hash of the one before it, that sequence numbers run from 0 without gaps and that times never decrease.
3. Confirm the digest of the genesis entry equals the identifier of the expected writer key.
4. Decode each checkpoint public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes. Compute the key identifier and compare it with the signer and the writer named in the checkpoint.
5. Encode each checkpoint and verify its signature with ML-DSA-65 under the context string quantova/qlog/1, following FIPS 204.
6. Confirm the head of each checkpoint equals the hash of the entry at its sequence number and its last time equals the time of that entry.
7. Compute the anchor value of each checkpoint and verify its receipt by the procedure published with Qstamp, then apply the rules of verification listed above.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org. By default verification consults the official endpoints of the network. Endpoints chosen by the verifier are given with the rpc or clients option, or with --rpc once for each on the command line, and verification consults them only with trustCustomEndpoints, or --trust-custom-endpoints. An endpoint on a loopback address is refused unless allowLoopback, or --allow-loopback, is set, and an endpoint on a private network address unless it is named in endpointAllowList, or with --allow-endpoint. The option expectedSender, or --expect-sender, names the Quantova accounts entitled to anchor records, and an anchor signed by any other account is invalid. Anchoring accepts chain data only when at least two endpoints run by different operators agree, and the option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint for anchoring and for the time of the chain.

## Licence

QLog is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
