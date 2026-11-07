"""Isolated, real-cryptography experiments. No public or user conversation target."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from typing import Callable

from crypto.primitives import signature_keypair, sign
from policy.engine import load_policy
from protocol.identity import Identity, b64, canonical, unb64
from protocol.session import Peer, complete_handshake
from attacks.mutations import SCENARIOS, mutate_packet

# SCENARIOS remains the V1 five-item public compatibility interface.
CATALOG = [
    {
        "id": "downgrade",
        "name": "Algorithm downgrade",
        "objective": "Force an unapproved cryptographic choice.",
        "mutation": "The untrusted relay changes the selected KEM in a signed response.",
    },
    {
        "id": "modified_offers",
        "name": "Modified capability list",
        "objective": "Remove the recommended algorithm from the signed capability offer.",
        "mutation": "The relay replaces the offered algorithm list without a trusted signature.",
    },
    {
        "id": "modified_selected",
        "name": "Modified selected algorithm",
        "objective": "Make the two clients accept different negotiation outcomes.",
        "mutation": "The relay changes the selected identifier after the responder signs it.",
    },
    {
        "id": "identity",
        "name": "Identity substitution",
        "objective": "Impersonate a contact using an attacker-owned ML-DSA key.",
        "mutation": "A valid signature under a different real identity key replaces the pinned contact key.",
    },
    {
        "id": "invalid_signature",
        "name": "Invalid digital signature",
        "objective": "Make a modified signature pass authentication.",
        "mutation": "The relay flips a byte in a real ML-DSA signature.",
    },
    {
        "id": "tamper",
        "name": "Ciphertext tampering",
        "objective": "Display modified message plaintext.",
        "mutation": "The relay flips one ciphertext byte before authenticated decryption.",
    },
    {
        "id": "replay",
        "name": "Message replay",
        "objective": "Display the same encrypted message more than once.",
        "mutation": "An already consumed encrypted packet is submitted again.",
    },
    {
        "id": "handshake_replay",
        "name": "Handshake replay",
        "objective": "Reuse a previously received signed session offer.",
        "mutation": "The same signed offer and session identifier reach the receiver twice.",
    },
    {
        "id": "unsupported",
        "name": "Unsupported algorithm injection",
        "objective": "Negotiate a KEM outside the implementation whitelist.",
        "mutation": "An isolated trusted test endpoint signs an unsupported capability to exercise policy validation; a relay cannot re-sign it.",
    },
    {
        "id": "invalid",
        "name": "Corrupted cryptographic input",
        "objective": "Pass a truncated public key into the cryptographic operation.",
        "mutation": "An isolated trusted test endpoint signs a malformed KEM public key to reach size validation.",
    },
    {
        "id": "reorder",
        "name": "Reordered messages",
        "objective": "Advance the receiver chain out of sequence.",
        "mutation": "Counter one arrives before counter zero; missing-message recovery is not claimed.",
    },
    {
        "id": "rekey_interruption",
        "name": "Connection interrupted during re-key",
        "objective": "Keep using a half-established replacement session.",
        "mutation": "An isolated loopback relay drops the replacement handshake finish and closes both sockets.",
    },
]
ALL_SCENARIOS = tuple(row["id"] for row in CATALOG)
_BY_ID = {row["id"]: row for row in CATALOG}
_EXPECTED = {
    "downgrade": ("signature", "Policy violation"),
    "modified_offers": ("signature",),
    "modified_selected": ("signature", "Policy violation"),
    "identity": ("fingerprint",),
    "invalid_signature": ("signature",),
    "tamper": ("integrity",),
    "replay": ("Replay", "already consumed"),
    "handshake_replay": ("Replay",),
    "unsupported": ("unsupported", "Unsupported"),
    "invalid": ("length",),
    "reorder": ("Out-of-order", "out-of-order"),
}


@contextmanager
def make_pair():
    """Create temporary real identities with explicit, out-of-band test pins."""
    with TemporaryDirectory(prefix="crytosage-lab-") as folder:
        alice = Identity(Path(folder) / "alice", "Alice")
        bob = Identity(Path(folder) / "bob", "Bob")
        alice.pin("Bob", bob.public, bob.fingerprint)
        bob.pin("Alice", alice.public, alice.fingerprint)
        yield Peer(alice, deepcopy(load_policy())), Peer(bob, deepcopy(load_policy()))


def _prepare(scenario: str, alice: Peer, bob: Peer) -> Callable[[], object]:
    """Build a real modified packet before the validator-under-test is invoked."""
    if scenario in ("downgrade", "modified_selected"):
        response = bob.receive(alice.initiate("Bob"))
        packet = mutate_packet("downgrade", response)
        return lambda: alice.receive(packet)
    if scenario == "modified_offers":
        packet = mutate_packet("downgrade", alice.initiate("Bob"))
        return lambda: bob.receive(packet)
    if scenario == "identity":
        packet = mutate_packet(scenario, alice.initiate("Bob"))
        public, secret = signature_keypair()
        packet["identity"] = b64(public)
        packet["signature"] = b64(
            sign(
                secret, canonical({k: v for k, v in packet.items() if k != "signature"})
            )
        )
        return lambda: bob.receive(packet)
    if scenario == "invalid_signature":
        packet = alice.initiate("Bob")
        signature = bytearray(unb64(packet["signature"]))
        signature[0] ^= 1
        packet["signature"] = b64(bytes(signature))
        return lambda: bob.receive(packet)
    if scenario == "handshake_replay":
        packet = alice.initiate("Bob")
        bob.receive(packet)
        return lambda: bob.receive(packet)
    if scenario == "unsupported":
        packet = alice.initiate("Bob")
        packet["offer"]["algorithms"] = ["UNSUPPORTED-KEM"]
        packet["signature"] = alice.identity.sign(
            {k: v for k, v in packet.items() if k != "signature"}
        )
        return lambda: bob.receive(packet)
    if scenario == "invalid":
        packet = mutate_packet(scenario, alice.initiate("Bob"))
        packet["signature"] = alice.identity.sign(
            {k: v for k, v in packet.items() if k != "signature"}
        )
        return lambda: bob.receive(packet)
    complete_handshake(alice, bob)
    packet = alice.session.seal("A real encrypted lab message")
    if scenario == "replay":
        bob.session.open(packet)
        return lambda: bob.session.open(packet)
    if scenario == "tamper":
        packet = mutate_packet(scenario, packet)
        return lambda: bob.session.open(packet)
    if scenario == "reorder":
        later = alice.session.seal("This real message must not skip an earlier counter")
        return lambda: bob.session.open(later)
    raise ValueError("Unsupported lab attack scenario")


async def _interrupted_rekey(record: Callable[[str, str], None]) -> str:
    """Exercise actual Client disconnect cleanup through a private loopback relay."""
    from websockets.asyncio.server import serve
    from websockets.exceptions import ConnectionClosed
    from client.runtime import Client

    clients = {}
    armed = False
    interrupted = asyncio.Event()

    async def route(socket):
        name = None
        try:
            hello = json.loads(await asyncio.wait_for(socket.recv(), 5))
            name = hello["register"]
            clients[name] = socket
            await socket.send(json.dumps({"type": "registered", "name": name}))
            async for raw in socket:
                packet = json.loads(raw)
                if armed and packet.get("type") == "finish":
                    record(
                        "packet_received",
                        "The loopback relay received and withheld the replacement-handshake finish.",
                    )
                    interrupted.set()
                    for peer_socket in tuple(clients.values()):
                        await peer_socket.close(1011, "Isolated lab interruption")
                    return
                destination = clients.get(packet.get("to"))
                if destination:
                    await destination.send(raw)
        except (ConnectionClosed, asyncio.TimeoutError):
            pass
        finally:
            if name and clients.get(name) is socket:
                clients.pop(name, None)

    async def wait_for(check, seconds=8):
        async with asyncio.timeout(seconds):
            while not check():
                await asyncio.sleep(0.01)

    with TemporaryDirectory(prefix="crytosage-rekey-lab-") as folder:
        root = Path(folder)
        async with serve(route, "127.0.0.1", 0, max_size=262_144) as relay:
            port = relay.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}"
            alice = Client("Alice", root / "Alice", root / "contacts", url)
            bob = Client("Bob", root / "Bob", root / "contacts", url)
            alice.identity.pin("Bob", bob.identity.public, bob.identity.fingerprint)
            bob.identity.pin("Alice", alice.identity.public, alice.identity.fingerprint)
            tasks = [asyncio.create_task(client.run()) for client in (alice, bob)]
            try:
                await wait_for(lambda: alice.connected and bob.connected)
                await alice.establish("Bob")
                await wait_for(
                    lambda: alice.peer.session is not None
                    and bob.peer.session is not None
                )
                record(
                    "baseline",
                    "Two isolated real Python clients completed a baseline authenticated session over loopback WebSockets.",
                )
                old_sid = alice.peer.session.session_id
                armed = True
                record(
                    "packet_mutated",
                    "The private lab relay is armed to interrupt the next replacement-handshake finish.",
                )
                await alice.establish("Bob")
                await asyncio.wait_for(interrupted.wait(), 8)
                await wait_for(lambda: not alice.connected and not bob.connected)
                if (
                    alice.peer.session is not None
                    or bob.peer.session is not None
                    or alice.peer.pending is not None
                    or bob.peer.pending is not None
                ):
                    raise AssertionError(
                        "A client retained session state after the controlled disconnect"
                    )
                record(
                    "validation_failed",
                    "Both actual clients observed the connection loss and discarded incomplete replacement state.",
                )
                # Check the real send guard; no stale session may encrypt another message.
                try:
                    await alice.send(
                        "This message must not use a half-established session",
                        "Bob",
                        old_sid,
                    )
                except ValueError as exc:
                    if not any(
                        word in str(exc).lower()
                        for word in ("session", "authenticate", "offline", "relay")
                    ):
                        raise
                else:
                    raise AssertionError(
                        "The client allowed a message after the interrupted re-key"
                    )
                return "Connection interrupted during re-key; both clients discarded incomplete state and refused stale-session sending"
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)


def run_scenario(scenario: str) -> dict:
    """Run an isolated experiment; infrastructure failures are never attack success."""
    if scenario not in _BY_ID:
        raise ValueError("Unsupported lab attack scenario")
    start = time.perf_counter_ns()
    timeline = []

    def record(phase: str, detail: str):
        timeline.append(
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
                "phase": phase,
                "detail": detail,
            }
        )

    attempted = False
    blocked = False
    status = "infrastructure_error"
    reason = "The lab did not complete"
    record(
        "launched",
        "An isolated experiment was requested; active conversations are not a target.",
    )
    try:
        if scenario == "rekey_interruption":
            attempted = True
            reason = asyncio.run(_interrupted_rekey(record))
            blocked = True
            status = "blocked"
            record(
                "protected",
                "No incomplete replacement session or old session remained usable after disconnect.",
            )
        else:
            with make_pair() as (alice, bob):
                operation = _prepare(scenario, alice, bob)
                attempted = True
                record("packet_mutated", _BY_ID[scenario]["mutation"])
                record(
                    "packet_received",
                    "The modified or replayed packet is submitted to the real isolated client protocol validator.",
                )
                try:
                    operation()
                except ValueError as exc:
                    reason = str(exc)[:400]
                    blocked = any(
                        token.lower() in reason.lower() for token in _EXPECTED[scenario]
                    )
                    status = "blocked" if blocked else "inconclusive"
                    record("validation_failed", reason)
                    record(
                        "protected" if blocked else "inconclusive",
                        "The expected security boundary rejected this packet."
                        if blocked
                        else "A different validation error occurred; the intended attack outcome is not established.",
                    )
                else:
                    status = "accepted"
                    reason = "The altered packet was accepted by the validator; investigate the experiment"
                    record("accepted", reason)
    except Exception as exc:
        blocked = False
        status = "infrastructure_error"
        # Setup/transport/assertion failures are not cryptographic rejection and
        # arbitrary exception payloads are deliberately not exported to the UI.
        reason = f"Isolated lab infrastructure did not complete ({type(exc).__name__})"
        record("infrastructure_error", reason)
    return {
        "scenario": scenario,
        "name": _BY_ID[scenario]["name"],
        "objective": _BY_ID[scenario]["objective"],
        "mutation": _BY_ID[scenario]["mutation"],
        "attempted": attempted,
        "blocked": blocked,
        "status": status,
        "reason": reason,
        "security_reason": reason,
        "protocol_response": reason,
        "elapsed_ms": (time.perf_counter_ns() - start) / 1e6,
        "timeline": timeline,
        "scope": "isolated real local WebSocket clients"
        if scenario == "rekey_interruption"
        else "isolated real client/protocol experiment; active conversation unchanged",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario", nargs="?", choices=(*ALL_SCENARIOS, "all", "all-v2"), default="all"
    )
    args = parser.parse_args()
    chosen = (
        ALL_SCENARIOS
        if args.scenario == "all-v2"
        else SCENARIOS
        if args.scenario == "all"
        else (args.scenario,)
    )
    results = [run_scenario(name) for name in chosen]
    print(json.dumps(results, indent=2))
    raise SystemExit(0 if all(row["status"] == "blocked" for row in results) else 1)
