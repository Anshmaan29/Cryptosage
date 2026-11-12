import { authenticate, bytes, canonical, crypt, decode, derive, encode, hash, KEMS, random } from './crypto.mjs';

import { eligibleAlgorithms, selectKeyExchange, validatePolicy } from './policy.mjs';

const LEGACY_VERSION = 'crytosage/browser/1';
const POLICY_VERSION = 'crytosage/browser/2';
const MAX_COUNTER = 100;
const MAX_TEXT = 16_384;
const MAX_SEEN = 512;
const utf8 = new TextDecoder('utf-8', { fatal: true });
const hex = data => Array.from(data, byte => byte.toString(16).padStart(2, '0')).join('');
export const randomId = () => hex(random(16));
export const roomId = async secret => hex(await hash(bytes('crytosage/room/' + encode(secret)))).slice(0, 32);

function fields(packet, keys) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet) || Object.keys(packet).length !== keys.length ||
      !keys.every(key => Object.hasOwn(packet, key))) throw new Error('Malformed protocol envelope');
}

export class Peer {
  constructor({ oqs, identity, inviteKey, role, room, algorithm, policy, roomState }) {
    if (policy === undefined && !Object.hasOwn(KEMS, algorithm)) throw new Error('Unknown KEM');
    this.oqs = oqs;
    this.identity = identity;
    this.inviteKey = inviteKey;
    this.role = role;
    this.remote = role === 'alice' ? 'bob' : 'alice';
    this.room = room;
    this.algorithm = algorithm;
    this.policy = policy === undefined ? undefined : validatePolicy(policy);
    this.version = this.policy ? POLICY_VERSION : LEGACY_VERSION;
    this.roomState = roomState;
  }

  header(type, sid) {
    return { type, v: this.version, room: this.room, sid, from: this.role, to: this.remote };
  }

  async signed(body) {
    const signature = this.oqs.sign(this.identity.secret, bytes(canonical(body)));
    const signed = { ...body, signature };
    return { ...signed, proof: await authenticate(this.inviteKey, signed) };
  }

  async verify(packet, specific) {
    fields(packet, ['type', 'v', 'room', 'sid', 'from', 'to', 'identity', 'signature', 'proof', ...specific]);
    const { proof, ...signed } = packet;
    const { signature, ...body } = signed;
    if (!this.policy && body.algorithm !== this.algorithm) throw new Error('Peer policy selected a different KEM');
    if (!await authenticate(this.inviteKey, signed, proof)) throw new Error('Invitation authentication failed');
    if (this.roomState.pin && this.roomState.pin !== body.identity) throw new Error('Peer identity changed. Create a new private chat.');
    if (!this.oqs.verify(body.identity, bytes(canonical(body)), signature)) throw new Error('ML-DSA-65 signature rejected');
    return body;
  }

  reset() {
    for (const key of Object.values(this.pending?.keys ?? {})) key.fill(0);
    this.pending?.root?.fill(0);
    this.pending = null;
    this.session?.sending.fill(0);
    this.session?.receiving.fill(0);
    this.session?.issueReceipt.fill(0);
    this.session?.verifyReceipt.fill(0);
    this.session = null;
  }

  async offer() {
    if (this.role !== 'alice' || this.pending) throw new Error('Handshake already in progress');
    this.reset();
    const body = { ...this.header('offer', randomId()), identity: this.identity.public, time: Date.now() };
    const keys = {};
    this.pending = { offer: body, keys };
    if (this.policy) {
      body.policy = this.policy;
      body.publicKeys = {};
      for (const name of eligibleAlgorithms(this.policy)) {
        const kem = this.oqs.keypair(name);
        body.publicKeys[name] = kem.public;
        keys[name] = kem.secret;
      }
    } else {
      const kem = this.oqs.keypair(this.algorithm);
      body.algorithm = this.algorithm;
      body.publicKey = kem.public;
      keys[this.algorithm] = kem.secret;
    }
    return this.signed(body);
  }

  async deriveRoot(secret, offer, response) {
    try {
      return await derive(secret, this.policy ? 'policy root' : 'root', await hash(bytes(canonical({ offer, response }))));
    } finally {
      secret.fill(0);
    }
  }

  async receive(packet) {
    if (packet?.v !== this.version || packet.room !== this.room || packet.from !== this.remote ||
        packet.to !== this.role || typeof packet.sid !== 'string' || !/^[a-f0-9]{32}$/.test(packet.sid)) {
      throw new Error('Packet is outside the authenticated room or identity');
    }
    if (packet.type === 'offer' && this.role === 'bob' && !this.pending) {
      const offer = await this.verify(packet, this.policy
        ? ['policy', 'publicKeys', 'time']
        : ['algorithm', 'publicKey', 'time']);
      const recent = Number.isSafeInteger(offer.time) && Math.abs(Date.now() - offer.time) < 60_000;
      if (!recent || this.roomState.offers.has(offer.sid)) throw new Error('Expired or replayed handshake');
      if (this.roomState.offers.size >= 128) throw new Error('Room handshake limit reached');
      const response = { ...this.header('response', offer.sid), identity: this.identity.public,
        offerHash: encode(await hash(bytes(canonical(offer)))) };
      let decision;
      let algorithm = this.algorithm;
      let publicKey = offer.publicKey;
      if (this.policy) {
        decision = selectKeyExchange(offer.policy, this.policy);
        const names = eligibleAlgorithms(offer.policy);
        fields(offer.publicKeys, names);
        for (const name of names) decode(offer.publicKeys[name], KEMS[name].public);
        response.policy = this.policy;
        algorithm = decision.selected;
        if (!algorithm) {
          this.roomState.offers.add(offer.sid);
          this.reset();
          return { decision, refused: true, reply: await this.signed({ ...response, type: 'decline' }) };
        }
        publicKey = offer.publicKeys[algorithm];
      }
      const { ciphertext, secret } = this.oqs.encapsulate(algorithm, publicKey);
      Object.assign(response, { algorithm, ciphertext });
      const root = await this.deriveRoot(secret, offer, response);
      this.roomState.offers.add(offer.sid);
      this.reset();
      this.pending = { offer, root, identity: offer.identity, algorithm, decision };
      const confirmation = (await this.confirm('responder', offer.sid, root)).confirmation;
      return { reply: await this.signed({ ...response, confirmation }) };
    }
    const pending = this.pending;
    if ((packet.type === 'response' || (this.policy && packet.type === 'decline')) &&
        this.role === 'alice' && pending?.keys && pending.offer.sid === packet.sid) {
      const declined = packet.type === 'decline';
      const specific = declined ? ['offerHash', 'policy'] : ['algorithm', 'offerHash', 'ciphertext', 'confirmation'];
      if (this.policy && !declined) specific.push('policy');
      const { confirmation, ...response } = await this.verify(packet, specific);
      if (response.offerHash !== encode(await hash(bytes(canonical(pending.offer))))) throw new Error('Offer transcript mismatch');
      let decision;
      if (this.policy) {
        decision = selectKeyExchange(pending.offer.policy, response.policy);
        if (declined && decision.selected === null) {
          this.reset();
          return { decision, refused: true };
        }
        if (declined || response.algorithm !== decision.selected || !decision.selected) {
          throw new Error('Response does not match the authenticated policy decision');
        }
      }
      const algorithm = response.algorithm;
      const secret = this.oqs.decapsulate(algorithm, pending.keys[algorithm], response.ciphertext);
      const root = await this.deriveRoot(secret, pending.offer, response);
      const responder = { ...this.header('responder', packet.sid), from: this.remote, to: this.role };
      let confirmed = false;
      try {
        confirmed = await this.authenticateConfirmation(root, responder, confirmation);
        if (!confirmed) throw new Error('Responder key confirmation failed');
      } finally {
        if (!confirmed) root.fill(0);
      }
      for (const key of Object.values(pending.keys)) key.fill(0);
      this.pending = { offer: pending.offer, root, identity: response.identity, algorithm, decision };
      return { reply: await this.confirm('finish', packet.sid, root) };
    }
    const expected = this.role === 'alice' ? 'ack' : 'finish';
    if (packet.type === expected && pending?.root && pending.offer.sid === packet.sid) {
      fields(packet, ['type', 'v', 'room', 'sid', 'from', 'to', 'confirmation']);
      const { confirmation, ...header } = packet;
      if (!await this.authenticateConfirmation(pending.root, header, confirmation)) throw new Error('Peer key confirmation failed');
      const reply = this.role === 'bob' ? await this.confirm('ack', packet.sid, pending.root) : null;
      this.session = {
        sid: packet.sid,
        algorithm: pending.algorithm,
        sending: await derive(pending.root, this.role + '/chain'),
        receiving: await derive(pending.root, this.remote + '/chain'),
        issueReceipt: await derive(pending.root, this.role + '/receipts'),
        verifyReceipt: await derive(pending.root, this.remote + '/receipts'),
        sendCount: 0, receiveCount: 0, expires: Date.now() + 60 * 60 * 1000,
      };
      this.roomState.pin = pending.identity;
      pending.root.fill(0);
      this.pending = null;
      return { ready: true, reply, decision: pending.decision };
    }
    if (packet.type === 'message') return this.open(packet);
    if (packet.type === 'receipt') return this.checkReceipt(packet);
    throw new Error('Unexpected or replayed protocol flight');
  }

  async authenticateConfirmation(root, header, proof) {
    const key = await derive(root, 'key confirmation');
    try { return await authenticate(key, header, proof); }
    finally { key.fill(0); }
  }

  async confirm(type, sid, root) {
    const header = this.header(type, sid);
    return { ...header, confirmation: await this.authenticateConfirmation(root, header) };
  }

  active(sid) {
    const session = this.session;
    if (!session || (sid && sid !== session.sid) || Date.now() > session.expires) throw new Error('Establish a fresh authenticated session');
    return session;
  }

  async seal(message) {
    const session = this.active();
    const text = bytes(message.text);
    if (!text.length || text.length > MAX_TEXT) throw new Error('Messages must use 1–16,384 UTF-8 bytes');
    if (session.sendCount >= MAX_COUNTER) throw new Error('Renew the session before sending more messages');
    const counter = session.sendCount;
    const header = { ...this.header('message', session.sid), counter, size: text.length };
    const content = new Uint8Array(16 + text.length);
    content.set(decode(message.id, 16));
    content.set(text, 16);
    const key = await derive(session.sending, 'message');
    const ciphertext = encode(await crypt('encrypt', key, counter, header, content));
    const previous = session.sending;
    session.sending = await derive(previous, 'next');
    previous.fill(0);
    key.fill(0);
    content.fill(0);
    session.sendCount++;
    const packet = { ...header, ciphertext };
    return { packet, hash: encode(await hash(bytes(canonical(packet)))) };
  }

  async open(packet) {
    fields(packet, ['type', 'v', 'room', 'sid', 'from', 'to', 'counter', 'size', 'ciphertext']);
    const session = this.active(packet.sid);
    const { ciphertext, ...header } = packet;
    if (header.counter !== session.receiveCount || session.receiveCount >= MAX_COUNTER ||
        !Number.isSafeInteger(header.size) || header.size < 1 || header.size > MAX_TEXT) {
      throw new Error('Replayed, reordered or invalid message');
    }
    const key = await derive(session.receiving, 'message');
    let content;
    try {
      content = await crypt('decrypt', key, header.counter, header, decode(ciphertext, header.size + 32));
    } finally { key.fill(0); }
    const id = encode(content.slice(0, 16));
    const text = utf8.decode(content.slice(16));
    const digest = encode(await hash(content.slice(16)));
    content.fill(0);
    const prior = this.roomState.seen.get(id);
    if (prior && prior !== digest) throw new Error('Duplicate message ID with conflicting content');
    const previous = session.receiving;
    session.receiving = await derive(previous, 'next');
    previous.fill(0);
    session.receiveCount++;
    if (!prior) {
      this.roomState.seen.set(id, digest);
      if (this.roomState.seen.size > MAX_SEEN) this.roomState.seen.delete(this.roomState.seen.keys().next().value);
    }
    const receipt = { ...this.header('receipt', session.sid), counter: header.counter,
      hash: encode(await hash(bytes(canonical(packet)))) };
    return { message: prior ? null : { id, text },
      reply: { ...receipt, proof: await authenticate(session.issueReceipt, receipt) } };
  }

  async checkReceipt(packet) {
    fields(packet, ['type', 'v', 'room', 'sid', 'from', 'to', 'counter', 'hash', 'proof']);
    const session = this.active(packet.sid);
    const { proof, ...receipt } = packet;
    if (!await authenticate(session.verifyReceipt, receipt, proof)) throw new Error('Invalid delivery receipt');
    return { receipt };
  }
}
