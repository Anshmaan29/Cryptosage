import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytes, derive, encode, getOqs, random } from '../.build/browser-site/crypto.mjs';
import { Peer, roomId } from '../.build/browser-site/protocol.mjs';

const oqs = await getOqs();

async function pair(algorithm) {
  const secret = random(32), room = await roomId(secret);
  const inviteKey = await derive(secret, 'invite authentication');
  const configs = ['alice', 'bob'].map(role => ({
    oqs, identity: oqs.identity(), role, room, algorithm, inviteKey,
    roomState: { offers: new Set(), seen: new Map() },
  }));
  return configs;
}

async function handshake(a, b) {
  const offer = await a.offer();
  const response = (await b.receive(offer)).reply;
  const finish = (await a.receive(response)).reply;
  const ack = await b.receive(finish);
  assert.ok(ack.ready);
  assert.ok((await a.receive(ack.reply)).ready);
  assert.equal(a.session.sid, b.session.sid);
  return offer;
}

for (const algorithm of ['ML-KEM-768', 'HQC-3']) {
  test(algorithm + ' real browser cryptography, replay, receipts and fresh retry', async () => {
    const [left, right] = await pair(algorithm);
    let a = new Peer(left), b = new Peer(right);
    const original = await handshake(a, b);
    const first = { id: encode(random(16)), text: 'Encrypted browser test 🔐' };
    const { packet, hash } = await a.seal(first);
    const tampered = { ...packet, ciphertext: (packet.ciphertext[0] === 'A' ? 'B' : 'A') + packet.ciphertext.slice(1) };
    await assert.rejects(() => b.receive(tampered));
    const outcome = await b.receive(packet);
    assert.deepEqual(outcome.message, first);
    assert.equal((await a.receive(outcome.reply)).receipt.hash, hash);
    await assert.rejects(() => b.receive(packet), /Replayed/);
    await assert.rejects(() => a.receive({ ...outcome.reply, hash: encode(random(32)) }), /Invalid delivery receipt/);
    const second = { id: encode(random(16)), text: 'Return message' };
    assert.deepEqual((await a.receive((await b.seal(second)).packet)).message, second);
    a.reset();
    b.reset();
    a = new Peer(left);
    b = new Peer(right);
    await assert.rejects(() => b.receive(original), /replayed handshake/);
    await handshake(a, b);
    const fresh = await a.seal(first);
    assert.notEqual(fresh.packet.sid, packet.sid);
    assert.notEqual(fresh.packet.ciphertext, packet.ciphertext);
    const duplicate = await b.receive(fresh.packet);
    assert.equal(duplicate.message, null);
    assert.equal((await a.receive(duplicate.reply)).receipt.hash, fresh.hash);
  });
}

test('wrong invite key, modified negotiation and invalid signatures fail', async () => {
  const [left, right] = await pair('ML-KEM-768');
  const a = new Peer(left), b = new Peer(right);
  const offer = await a.offer();
  await assert.rejects(() => new Peer({ ...right, inviteKey: random(32) }).receive(offer), /Invitation authentication/);
  await assert.rejects(() => b.receive({ ...offer, algorithm: 'HQC-3' }), /different KEM/);
  const signature = oqs.sign(left.identity.secret, bytes('signed'));
  assert.equal(oqs.verify(left.identity.public, bytes('changed'), signature), false);
});

const { defaultPolicy } = await import('../.build/browser-site/policy.mjs');

async function policyPair(initiator, responder) {
  const [left, right] = await pair('ML-KEM-768');
  return [new Peer({ ...left, policy: initiator }), new Peer({ ...right, policy: responder })];
}

test('browser policies select ML-KEM unless both peers opt in to HQC', async () => {
  const preferred = { ...defaultPolicy, experimental: true, preferred: 'HQC-3' };
  const [alice, bob] = await policyPair(preferred, defaultPolicy);
  await handshake(alice, bob);
  assert.equal(alice.session.algorithm, 'ML-KEM-768');
  assert.equal(bob.session.algorithm, 'ML-KEM-768');
});

test('different signed policies negotiate HQC and confirm authenticated delivery', async () => {
  const preferred = { ...defaultPolicy, experimental: true, preferred: 'HQC-3' };
  const [alice, bob] = await policyPair(preferred, { ...defaultPolicy, experimental: true });
  const offer = await alice.offer();
  const response = (await bob.receive(offer)).reply;
  const forgedSelection = await bob.signed({
    ...Object.fromEntries(Object.entries(response).filter(([field]) => !['proof', 'signature'].includes(field))),
    algorithm: 'ML-KEM-768',
  });
  await assert.rejects(() => alice.receive(forgedSelection), /authenticated policy decision/);
  const finish = (await alice.receive(response)).reply;
  const ack = await bob.receive(finish);
  const ready = await alice.receive(ack.reply);
  assert.equal(alice.session.algorithm, 'HQC-3');
  assert.deepEqual(ready.decision, ack.decision);
  const message = { id: encode(random(16)), text: 'Negotiated test message' };
  const { packet, hash } = await alice.seal(message);
  const received = await bob.receive(packet);
  assert.deepEqual(received.message, message);
  assert.equal((await alice.receive(received.reply)).receipt.hash, hash);
});

test('incompatible policies return an authenticated refusal and erase unused keys', async () => {
  const [alice, bob] = await policyPair(defaultPolicy, { ...defaultPolicy, minimumLevel: 5 });
  const offer = await alice.offer();
  const unused = alice.pending.keys['ML-KEM-768'];
  await assert.rejects(() => bob.receive({ ...offer, policy: { ...offer.policy, minimumLevel: 5 } }), /Invitation authentication/);
  const rejected = await bob.receive(offer);
  const decline = rejected.reply;
  assert.equal(decline.type, 'decline');
  await assert.rejects(() => alice.receive({ ...decline, policy: defaultPolicy }), /Invitation authentication/);
  const outcome = await alice.receive(decline);
  assert.equal(outcome.refused, true);
  assert.deepEqual(outcome.decision, rejected.decision);
  assert.ok(unused.every(byte => byte === 0));
  assert.equal(alice.session, null);
  assert.equal(bob.session, null);
  await assert.rejects(() => bob.receive(offer), /replayed handshake/);
});
