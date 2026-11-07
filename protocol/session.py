"""A four-flight, transcript-bound research handshake and ordered hash ratchet."""
from __future__ import annotations
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from crypto.primitives import (available_algorithms, kem_keypair, encapsulate, decapsulate,
                               verify, hkdf, encrypt, decrypt)
from protocol.identity import Identity, b64, unb64, canonical
from policy.engine import select

VERSION = 'crytosage/1'
MAX_MESSAGE = 16_384
REKEY_AFTER = 100


def digest(value: dict) -> bytes:
    return hashlib.sha256(canonical(value)).digest()


def mac(key: bytes, label: bytes, transcript: bytes) -> str:
    return b64(hmac.digest(key, label + transcript, 'sha256'))


def check_mac(key: bytes, label: bytes, transcript: bytes, supplied: str) -> None:
    if not isinstance(supplied, str) or not hmac.compare_digest(mac(key, label, transcript), supplied):
        raise ValueError('Shared-key confirmation failed')


@dataclass
class Session:
    session_id: str
    local: str
    peer: str
    algorithm: str
    reason: str
    transcript: bytes
    _send_chain: bytes = field(repr=False)
    _receive_chain: bytes = field(repr=False)
    handshake_ms: float = 0
    send_count: int = 0
    receive_count: int = 0
    encryption_us: float = 0
    decryption_us: float = 0

    @classmethod
    def create(cls, sid, local, peer, selection, transcript, shared, initiator, elapsed=0):
        root = hkdf(shared, b'crytosage/1/root', salt=transcript)
        a = hkdf(root, b'crytosage/1/initiator-chain')
        b = hkdf(root, b'crytosage/1/responder-chain')
        return cls(sid, local, peer, selection['algorithm'], selection['reason'], transcript,
                   a if initiator else b, b if initiator else a, elapsed)

    def seal(self, text: str) -> dict:
        if not isinstance(text, str) or not text or len(text.encode()) > MAX_MESSAGE:
            raise ValueError('Message must contain 1–16384 UTF-8 bytes')
        if self.send_count >= REKEY_AFTER:
            raise ValueError('Re-key required before sending more messages')
        start = time.perf_counter_ns()
        header = {'type': 'message', 'v': VERSION, 'sid': self.session_id,
                  'from': self.local, 'to': self.peer, 'counter': self.send_count}
        key = hkdf(self._send_chain, b'crytosage/1/message-key')
        nonce = self.send_count.to_bytes(12, 'big')
        ciphertext = encrypt(key, nonce, text.encode(), canonical(header))
        self._send_chain = hkdf(self._send_chain, b'crytosage/1/next-chain')
        self.send_count += 1
        self.encryption_us = (time.perf_counter_ns() - start) / 1000
        return {**header, 'ciphertext': b64(ciphertext)}

    def open(self, packet: dict) -> str:
        start = time.perf_counter_ns()
        expected_keys = {'type', 'v', 'sid', 'from', 'to', 'counter', 'ciphertext'}
        if set(packet) != expected_keys or packet['v'] != VERSION or packet['type'] != 'message':
            raise ValueError('Malformed encrypted message')
        if packet['sid'] != self.session_id or packet['from'] != self.peer or packet['to'] != self.local:
            raise ValueError('Message belongs to a different session or identity')
        counter = packet['counter']
        if type(counter) is not int or counter < 0 or counter >= REKEY_AFTER:
            raise ValueError('Invalid message counter')
        if counter < self.receive_count:
            raise ValueError('Replay rejected: message counter already consumed')
        if counter != self.receive_count:
            raise ValueError('Out-of-order message rejected; reconnect to recover a lost message')
        ciphertext = unb64(packet['ciphertext'])
        if len(ciphertext) < 17 or len(ciphertext) > MAX_MESSAGE + 16:
            raise ValueError('Invalid ciphertext length')
        header = {k: v for k, v in packet.items() if k != 'ciphertext'}
        key = hkdf(self._receive_chain, b'crytosage/1/message-key')
        try:
            plaintext = decrypt(key, counter.to_bytes(12, 'big'), ciphertext, canonical(header)).decode('utf-8')
        except Exception as exc:
            raise ValueError('Ciphertext integrity verification failed') from exc
        self._receive_chain = hkdf(self._receive_chain, b'crytosage/1/next-chain')
        self.receive_count += 1
        self.decryption_us = (time.perf_counter_ns() - start) / 1000
        return plaintext

    def public(self) -> dict:
        return {'session_id': self.session_id, 'peer': self.peer, 'algorithm': self.algorithm, 'security_level': 3,
                'reason': self.reason, 'handshake_ms': self.handshake_ms,
                'send_count': self.send_count, 'receive_count': self.receive_count,
                'encryption_us': self.encryption_us, 'decryption_us': self.decryption_us}


class Peer:
    def __init__(self, identity: Identity, policy: dict, measurements: dict | None = None):
        self.identity, self.policy = identity, policy
        self.measurements = measurements or {}
        self.pending: dict | None = None
        self.session: Session | None = None
        self.seen: dict[str, float] = {}

    def _offer(self) -> dict:
        return {'algorithms': [a['name'] for a in available_algorithms()],
                'policy': self.policy, 'measurements': self.measurements}

    def _signed(self, body: dict) -> dict:
        return {**body, 'signature': self.identity.sign(body)}

    def _verify(self, packet: dict) -> dict:
        if not isinstance(packet, dict) or len(canonical(packet)) > 250_000:
            raise ValueError('Malformed protocol message')
        body = {k: v for k, v in packet.items() if k != 'signature'}
        if body.get('v') != VERSION or body.get('to') != self.identity.name:
            raise ValueError('Unsupported protocol version or recipient')
        public = unb64(body.get('identity', ''))
        self.identity.check_peer(body.get('from'), public)
        if not verify(public, canonical(body), unb64(packet.get('signature', ''))):
            raise ValueError('Invalid negotiation signature')
        sid = body.get('sid')
        if not isinstance(sid, str) or len(sid) != 64:
            raise ValueError('Invalid session identifier')
        return body

    def initiate(self, peer: str) -> dict:
        if self.pending:
            raise ValueError('A handshake is already in progress')
        if peer not in self.identity.trusted:
            raise ValueError('Unverified contact: compare and pin the fingerprint first')
        started = time.perf_counter_ns()
        offer = self._offer()
        keys = {name: kem_keypair(name) for name in offer['algorithms']}
        if not keys:
            raise ValueError('No supported post-quantum KEM is available')
        body = {'type': 'offer', 'v': VERSION, 'sid': secrets.token_hex(32),
                'from': self.identity.name, 'to': peer, 'identity': b64(self.identity.public),
                'nonce': secrets.token_hex(32), 'time': int(time.time()), 'offer': offer,
                'kem_keys': {name: b64(pair[0]) for name, pair in keys.items()}}
        packet = self._signed(body)
        self.pending = {'role': 'initiator', 'offer': body, 'keys': keys,
                        'start': started, 'expires': time.monotonic() + 30}
        self.session = None
        return packet

    def expire(self) -> bool:
        if self.pending and time.monotonic() > self.pending['expires']:
            self.pending = None
            return True
        return False

    def receive(self, packet: dict) -> dict | None:
        self.expire()
        kind = packet.get('type') if isinstance(packet, dict) else None
        if kind == 'offer':
            started = time.perf_counter_ns()
            body = self._verify(packet)
            if set(body) != {'type','v','sid','from','to','identity','nonce','time','offer','kem_keys'}:
                raise ValueError('Malformed handshake offer')
            if type(body['time']) is not int or abs(time.time() - body['time']) > 60:
                raise ValueError('Replay rejected: stale handshake timestamp')
            if not isinstance(body['nonce'], str) or len(body['nonce']) != 64:
                raise ValueError('Invalid handshake nonce')
            self.seen = {sid: end for sid, end in self.seen.items() if end > time.monotonic()}
            if body['sid'] in self.seen:
                raise ValueError('Replay rejected: session identifier already seen')
            if self.pending:
                raise ValueError('A handshake is already in progress')
            if len(self.seen) >= 4096:
                raise ValueError('Handshake replay cache full; retry later')
            local_offer = self._offer()
            selection = select(body['offer'], local_offer)
            algorithm = selection['algorithm']
            if not isinstance(body['kem_keys'], dict) or set(body['kem_keys']) != set(body['offer']['algorithms']):
                raise ValueError('Offered KEM keys do not match capabilities')
            ciphertext, shared = encapsulate(algorithm, unb64(body['kem_keys'][algorithm]))
            response = {'type': 'response', 'v': VERSION, 'sid': body['sid'],
                        'from': self.identity.name, 'to': body['from'],
                        'identity': b64(self.identity.public), 'nonce': secrets.token_hex(32),
                        'offer_hash': b64(digest(body)), 'offer': local_offer,
                        'selected': algorithm, 'ciphertext': b64(ciphertext)}
            transcript = digest({'offer': body, 'response': response})
            confirm_key = hkdf(shared, b'crytosage/1/confirmation', salt=transcript)
            response['confirmation'] = mac(confirm_key, b'responder', transcript)
            self.pending = {'role':'responder', 'offer':body, 'response':response,
                            'transcript':transcript,'shared':shared,'confirm_key':confirm_key,
                            'selection':selection,'start':started,
                            'expires':time.monotonic()+30}
            self.seen[body['sid']] = time.monotonic()+120
            self.session = None
            return self._signed(response)
        if kind == 'response':
            body = self._verify(packet)
            p = self.pending
            if not p or p['role'] != 'initiator' or body['sid'] != p['offer']['sid'] or body['from'] != p['offer']['to']:
                raise ValueError('Replay rejected: unexpected handshake response')
            if set(body) != {'type','v','sid','from','to','identity','nonce','offer_hash','offer','selected','ciphertext','confirmation'}:
                raise ValueError('Malformed handshake response')
            if 'keys' not in p:
                raise ValueError('Replay rejected: handshake response already consumed')
            if body['offer_hash'] != b64(digest(p['offer'])):
                raise ValueError('Negotiation transcript mismatch')
            selection = select(p['offer']['offer'], body['offer'])
            if body['selected'] != selection['algorithm']:
                raise ValueError('Policy violation: selected algorithm differs from deterministic negotiation')
            raw = {k:v for k,v in body.items() if k != 'confirmation'}
            transcript = digest({'offer':p['offer'],'response':raw})
            shared = decapsulate(selection['algorithm'], p['keys'][selection['algorithm']][1], unb64(body['ciphertext']))
            key = hkdf(shared, b'crytosage/1/confirmation', salt=transcript)
            check_mac(key, b'responder', transcript, body['confirmation'])
            p.update(transcript=transcript,shared=shared,confirm_key=key,selection=selection)
            p.pop('keys')
            return {'type':'finish','v':VERSION,'sid':body['sid'],'from':self.identity.name,
                    'to':body['from'],'confirmation':mac(key,b'initiator',transcript)}
        if kind in ('finish', 'ack'):
            if set(packet) != {'type','v','sid','from','to','confirmation'}:
                raise ValueError('Malformed key confirmation')
            p = self.pending
            role = 'responder' if kind == 'finish' else 'initiator'
            if not p or p['role'] != role or 'confirm_key' not in p:
                raise ValueError('Replay rejected: unexpected key confirmation')
            offer = p['offer']
            remote = offer['from'] if role == 'responder' else offer['to']
            if packet['sid'] != offer['sid'] or packet['v'] != VERSION or packet['from'] != remote or packet['to'] != self.identity.name:
                raise ValueError('Key confirmation session mismatch')
            check_mac(p['confirm_key'], b'initiator' if kind=='finish' else b'ack', p['transcript'], packet['confirmation'])
            self.session = Session.create(offer['sid'],self.identity.name,remote,p['selection'],p['transcript'],p['shared'],role=='initiator',
                                          (time.perf_counter_ns()-p['start'])/1e6)
            self.pending = None
            if kind == 'finish':
                return {'type':'ack','v':VERSION,'sid':offer['sid'],'from':self.identity.name,
                        'to':remote,'confirmation':mac(p['confirm_key'],b'ack',p['transcript'])}
            return None
        raise ValueError('Unsupported protocol message type')


def complete_handshake(alice: Peer, bob: Peer) -> dict:
    start = time.perf_counter_ns()
    flights = []
    packet = alice.initiate(bob.identity.name)
    for recipient in (bob, alice, bob, alice):
        flights.append(packet)
        packet = recipient.receive(packet)
    if not alice.session or not bob.session:
        raise ValueError('Handshake did not establish both sessions')
    return {'handshake_ms':(time.perf_counter_ns()-start)/1e6,
            'handshake_bytes':sum(len(canonical(p)) for p in flights)}
