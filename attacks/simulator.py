"""Isolated, real-cryptography malicious-relay experiments for this prototype."""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from crypto.primitives import signature_keypair, sign
from policy.engine import load_policy
from protocol.identity import Identity, b64, canonical, unb64
from protocol.session import Peer, complete_handshake

from attacks.mutations import SCENARIOS, mutate_packet


@contextmanager
def make_pair():
    """Create isolated lab identities with explicit, out-of-band test pins."""
    with TemporaryDirectory(prefix='crytosage-lab-') as folder:
        alice = Identity(Path(folder) / 'alice', 'Alice')
        bob = Identity(Path(folder) / 'bob', 'Bob')
        alice.pin('Bob', bob.public, bob.fingerprint)
        bob.pin('Alice', alice.public, alice.fingerprint)
        yield Peer(alice, deepcopy(load_policy())), Peer(bob, deepcopy(load_policy()))


def run_scenario(scenario: str) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError('Unsupported lab attack scenario')
    start = time.perf_counter_ns()
    with make_pair() as (alice, bob):
        if scenario == 'downgrade':
            offer = alice.initiate('Bob')
            packet = bob.receive(offer)
            packet = mutate_packet(scenario, packet)
            operation = lambda: alice.receive(packet)
        elif scenario == 'identity':
            packet = mutate_packet(scenario, alice.initiate('Bob'))
            # This lab endpoint owns its attacker key; the relay owns no keys.
            public, secret = signature_keypair()
            packet['identity'] = b64(public)
            packet['signature'] = b64(sign(secret, canonical({k:v for k,v in packet.items() if k != 'signature'})))
            operation = lambda: bob.receive(packet)
        elif scenario == 'replay':
            complete_handshake(alice, bob)
            packet = alice.session.seal('A real encrypted lab message')
            bob.session.open(packet)
            operation = lambda: bob.session.open(packet)
        elif scenario == 'tamper':
            complete_handshake(alice, bob)
            packet = alice.session.seal('A real encrypted lab message')
            packet = mutate_packet(scenario, packet)
            operation = lambda: bob.session.open(packet)
        else:
            packet = alice.initiate('Bob')
            packet = mutate_packet(scenario, packet)
            packet['signature'] = alice.identity.sign({k:v for k,v in packet.items() if k != 'signature'})
            operation = lambda: bob.receive(packet)
        try:
            operation()
        except ValueError as exc:
            blocked, reason = True, str(exc)
        else:
            blocked, reason = False, 'Modified packet was accepted; investigate this failure'
    return {'scenario': scenario, 'attempted': True, 'blocked': blocked, 'reason': reason,
            'elapsed_ms': (time.perf_counter_ns() - start) / 1e6,
            'scope': 'isolated real client/protocol experiment; active conversation unchanged'}


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', nargs='?', choices=(*SCENARIOS, 'all'), default='all')
    args = parser.parse_args()
    results = [run_scenario(name) for name in (SCENARIOS if args.scenario == 'all' else (args.scenario,))]
    print(json.dumps(results, indent=2))
    raise SystemExit(0 if all(row['blocked'] for row in results) else 1)
