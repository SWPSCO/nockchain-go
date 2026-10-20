import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await import('../dist/wasm/wasm_exec.js');
const { loadNockchain } = await import('../dist/wasm/nockchain.mjs');
const bytes = await readFile(new URL('../dist/wasm/nockchain.wasm', import.meta.url));
const api = await loadNockchain(bytes);
const fixture = JSON.parse(await readFile(new URL('../testdata/reference.json', import.meta.url), 'utf8'));
const consensus = JSON.parse(await readFile(new URL('../testdata/consensus.json', import.meta.url), 'utf8'));
const feeFor = id => String(consensus.transactions.find(v => v.id === id).minimumFee);
const key = fixture.keys.find(k => k.path.length === 0);
const child = fixture.keys.find(k => k.seed === key.seed && k.path.length === 1 && k.path[0] === 5);
assert.deepEqual(api.call('receive', { zpub: key.zpub, index: 5 }), { index: 5, address: child.address, lockRoot: child.lock });
assert.equal(api.call('derivePublic', { zpub: key.zpub, path: 'm/5' }).zpub, child.zpub);
assert.equal(api.call('parseNocks', { amount: '1.25' }), '81920');
assert.equal(api.call('formatNocks', { nicks: '81920' }), '1.25');
assert.equal(api.call('parseNocks', { amount: api.call('formatNocks', { nicks: '18446744073709551615' }) }), '18446744073709551615');
assert.throws(() => api.call('formatNocks', { nicks: 9007199254740992 }), /invalid request/);
assert.throws(() => api.call('formatNocks', { nicks: '01' }), /canonical decimal/);
assert.throws(() => api.call('receive', { zpub: key.zprv, index: 0 }));
assert.throws(() => api.call('inspect', { jam: '00' }));
assert.throws(() => api.call('unknown'));
for (const v of fixture.transactions) {
  const review = api.call('inspect', { jam: v.jam });
  assert.equal(review.id, v.id);
  assert.equal(review.feeNicks, String(v.fee));
  assert.equal(review.minimumFeeNicks, feeFor(v.id));
  assert.equal(api.call('verifySignatures', { jam: v.jam }), true);
}
// Digest values cross the bridge as Base58 strings, never rounded JSON numbers.
for (const v of fixture.multisig) {
  const review = api.call('inspect', { jam: v.jam });
  const lock = { threshold: review.spends[0].lock.threshold, keys: review.spends[0].lock.keys, timelock: review.spends[0].lock.timelock };
  const note = { first: review.spends[0].first, last: review.spends[0].last, originPage: String(v.note.originPage), nicks: String(v.note.nicks), noteDataJam: fixture.nouns.find(n => n.noun === 0).jam };
  assert.equal(api.call('lock', { inputLocks: [lock] }).first, note.first);
  assert.equal(api.call('minimumFee', { inputLocks: [lock], outputLocks: [lock] }), feeFor(v.id));
  const plan = api.call('prepareTransaction', { plans: [{ note, lock, fee: String(v.fee), outputs: [{ lock, nicks: String(v.gift) }] }] });
  assert.throws(() => api.call('verifySignatures', { jam: plan.jam }), /signature/);
  const signerA = fixture.keys.find(k => k.seed === v.seeds[0] && k.path.length === 0);
  const a = api.call('signTransaction', { jam: plan.jam, key: signerA.zprv });
  assert.equal(a.jam, v.partialJam);
  // The Rust fixture supplies the second signature independently.
  const merged = api.call('mergeSignatures', { jam: a.jam, otherJam: v.jam });
  assert.equal(merged.jam, v.jam);
  assert.equal(api.call('verifySignatures', { jam: merged.jam }), true);
  assert.equal(api.call('validateInputs', { jam: merged.jam, notes: [note], height: '105' }), true);
  if (v.timed) assert.throws(() => api.call('validateInputs', { jam: merged.jam, notes: [note], height: '104' }), /lock or maturity/);
}
const wallet = JSON.parse(await readFile(new URL('../testdata/wallet/reference.json', import.meta.url), 'utf8'));
function digest(limbs) {
  let value = limbs.reduceRight((n, limb) => n * 18446744069414584321n + BigInt(limb), 0n), text = '';
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  do { text = alphabet[Number(value % 58n)] + text; value /= 58n; } while (value);
  return text;
}
const output = o => ({ lockRoot: digest(o.root), noteDataJam: o.data, nicks: o.amount });
for (const row of [...wallet.plans, ...wallet.migrations]) {
  const notes = row.candidates.map(jam => ({ jam })), fees = { height: row.height };
  const planning = {
    outputs: row.outputs.map(output), refund: output(row.refund), signerPKH: digest(row.signer),
    version: row.version, ...(row.order ? { order: row.order } : {}),
    ...(row.exactFee !== undefined && row.exactFee !== null ? { feeNicks: row.exactFee } : {}),
    ...(row.sweep ? { sweep: output(row.sweep) } : {}),
  };
  if (row.selection) planning.selection = api.call('inspect', { jam: row.jam, fees }).spends.map(({ first, last }) => ({ first, last }));
  const result = api.call('plan', { notes, height: row.height, planning });
  assert.equal(result.transaction.jam, row.jam, row.case);
  assert.equal(result.finalFee, row.fee); assert.equal(result.minimumFee, row.minimumFee);
  assert.equal(result.seedWords, row.seedWords); assert.equal(result.witnessWords, row.witnessWords);
  if (row.signedJam) {
    const signer = fixture.keys.find(k => k.seed === row.seed && k.path.length === 0);
    const signed = api.call('signTransaction', { jam: row.jam, key: signer.zprv, notes, fees });
    assert.equal(signed.jam, row.signedJam, row.case);
    assert.equal(signed.summary.spends[0].proofJam, null);
    assert.equal(api.call('verifySignatures', { jam: signed.jam, notes, fees }), true);
    assert.equal(api.call('validateInputs', { jam: signed.jam, notes: result.selected.map(({ jam }) => ({ jam })), fees, height: row.height }), true);
    assert.throws(() => api.call('inspect', { jam: signed.jam, fees }), /migration/);
  }
}
for (const row of wallet.locks) {
  const review = api.call('lock', { inputLocks: [{ jam: row.form }] });
  assert.equal(review.root, digest(row.root)); assert.equal(review.lockJam, row.form);
}
await assert.rejects(() => loadNockchain(bytes), /already loaded/);
console.log('WebAssembly: derivation, exact amounts, Rust transactions, multisig, timelocks, signing, merging, planner goldens, V0 migrations and errors pass.');
process.exit(0);
