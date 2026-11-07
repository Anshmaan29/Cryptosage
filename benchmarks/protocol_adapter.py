"""Measure complete authenticated protocol computation separately from network I/O."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import asyncio
from benchmarks.transport import measure as measure_transport
from policy.engine import load_policy
from protocol.identity import Identity
from protocol.session import Peer, complete_handshake


def factory(include_network=True):
    """Prepare verified test identities once; don't charge identity creation to handshake."""
    directory = TemporaryDirectory(prefix='crytosage-bench-')
    alice = Identity(Path(directory.name)/'Alice','Alice')
    bob = Identity(Path(directory.name)/'Bob','Bob')
    alice.pin('Bob',bob.public,bob.fingerprint)
    bob.pin('Alice',alice.public,alice.fingerprint)

    def measure(name):
        policy = deepcopy(load_policy())
        policy['allow_experimental'] = name == 'HQC-3'
        for algorithm, rule in policy['algorithms'].items():
            if algorithm != name:
                rule['status'] = 'prohibited'
        a, b = Peer(alice,policy), Peer(bob,deepcopy(policy))
        result = complete_handshake(a,b)
        start = time.perf_counter_ns()
        packet = a.session.seal('benchmark ping')
        assert b.session.open(packet) == 'benchmark ping'
        reply = b.session.seal('benchmark pong')
        assert a.session.open(reply) == 'benchmark pong'
        result.update(message_roundtrip_ms=(time.perf_counter_ns()-start)/1e6,
                      encrypt_ms=a.session.encryption_us/1000,
                      decrypt_ms=b.session.decryption_us/1000)
        if include_network:
            result.update(asyncio.run(measure_transport(alice,bob,policy)))
        return result
    return measure, directory
