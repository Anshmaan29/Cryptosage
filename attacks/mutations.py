"""Relay-only packet mutations: standard library, no client key operations."""
from __future__ import annotations
import base64
from copy import deepcopy
import os

SCENARIOS = ('downgrade', 'identity', 'replay', 'tamper', 'invalid')


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 200_000:
        raise ValueError('Invalid encoded field')
    return base64.b64decode(value, validate=True)


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode('ascii')


def mutate_packet(scenario: str, packet: dict) -> dict:
    """Copy and alter one packet. Replay duplication is the relay caller's job.

    A relay has no trusted signing keys. Identity substitution uses random bytes
    of the original public-key length; contact pins reject this before signature
    verification. The isolated simulator separately tests a real attacker key.
    """
    if scenario not in SCENARIOS:
        raise ValueError('Unsupported lab attack scenario')
    changed = deepcopy(packet)
    kind = changed.get('type')
    if scenario == 'downgrade':
        if kind == 'response':
            changed['selected'] = 'HQC-3'
        elif kind == 'offer':
            changed['offer']['algorithms'] = ['HQC-3']
    elif scenario == 'identity' and kind in ('offer', 'response'):
        public = _decode(changed['identity'])
        changed['identity'] = _encode(os.urandom(len(public)))
    elif scenario == 'tamper' and kind == 'message':
        ciphertext = bytearray(_decode(changed['ciphertext']))
        if not ciphertext:
            raise ValueError('Cannot tamper with an empty ciphertext')
        ciphertext[0] ^= 1
        changed['ciphertext'] = _encode(bytes(ciphertext))
    elif scenario == 'invalid':
        if kind == 'offer':
            changed['kem_keys']['ML-KEM-768'] = _encode(b'bad key')
        elif kind in ('response', 'message'):
            changed['ciphertext'] = _encode(b'bad ciphertext')
    return changed
