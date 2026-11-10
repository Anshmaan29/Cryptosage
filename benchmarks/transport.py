"""Measured loopback WebSocket transport, separate from protocol computation."""

import asyncio
import json
import math
import socket
import time
from websockets.asyncio.client import connect
from protocol.identity import canonical
from protocol.session import Peer
from protocol.registration import register_client
from server.relay import run


PROFILES = {
    "localhost": (0, None),
    "moderate": (25, None),
    "constrained": (100, 256_000),
}


def validate_delay(delay_ms):
    if (
        type(delay_ms) not in (int, float)
        or not math.isfinite(delay_ms)
        or not 0 <= delay_ms <= 1000
    ):
        raise ValueError(
            "Artificial send delay must be a finite number from 0 to 1000 ms"
        )
    return float(delay_ms)


async def measure(identity_a, identity_b, policy, delay_ms=0, *, bandwidth_bps=None):
    """Delay each test endpoint send; actual routing remains a loopback relay.

    This models endpoint-injected send delay, not a measured WAN and not a
    separately measured one-way network propagation time. Startup is not timed.
    """
    delay_ms = validate_delay(delay_ms)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    task = asyncio.create_task(run(port=port))

    async def send(ws, packet):
        payload = canonical(packet)
        pause = delay_ms / 1000
        if bandwidth_bps is not None:
            pause += len(payload) * 8 / bandwidth_bps
        if pause:
            await asyncio.sleep(pause)
        await ws.send(payload.decode("ascii"))

    async def handshake(a, b, first, second):
        started = time.perf_counter_ns()
        packet = a.initiate(identity_b.name)
        for sender, receiver, peer in (
            (first, second, b),
            (second, first, a),
            (first, second, b),
            (second, first, a),
        ):
            await send(sender, packet)
            packet = peer.receive(json.loads(await receiver.recv()))
        if (
            not a.session
            or not b.session
            or a.session.session_id != b.session.session_id
        ):
            raise RuntimeError(
                "Network benchmark handshake did not confirm both clients"
            )
        return (time.perf_counter_ns() - started) / 1e6

    try:
        for _ in range(100):
            try:
                first = await connect(f"ws://127.0.0.1:{port}", proxy=None)
                break
            except OSError:
                await asyncio.sleep(0.01)
        else:
            raise ValueError("Benchmark relay did not start")
        async with first, connect(f"ws://127.0.0.1:{port}", proxy=None) as second:
            async with asyncio.timeout(40):
                for ws, identity in ((first, identity_a), (second, identity_b)):
                    await register_client(ws, identity)
                a, b = Peer(identity_a, policy), Peer(identity_b, policy)
                handshake_ms = await handshake(a, b, first, second)
                packet = a.session.seal("Measured loopback message")
                start = time.perf_counter_ns()
                await send(first, packet)
                incoming = json.loads(await second.recv())
                if b.session.open(incoming) != "Measured loopback message":
                    raise RuntimeError("Network message verification failed")
                reply = b.session.seal("Measured loopback reply")
                await send(second, reply)
                if (
                    a.session.open(json.loads(await first.recv()))
                    != "Measured loopback reply"
                ):
                    raise RuntimeError("Network reply verification failed")
                message_ms = (time.perf_counter_ns() - start) / 1e6
                old_sid = a.session.session_id
                rekey_ms = await handshake(a, b, first, second)
                if a.session.session_id == old_sid:
                    raise RuntimeError("Network re-key reused a session identifier")
                # Echo a fixed opaque envelope without cryptographic computation.
                probe = {
                    "type": "transport_probe",
                    "from": identity_a.name,
                    "to": identity_b.name,
                    "payload": "0" * 4096,
                }
                start = time.perf_counter_ns()
                await send(first, probe)
                echoed = json.loads(await second.recv())
                echoed.update({"from": identity_b.name, "to": identity_a.name})
                await send(second, echoed)
                if json.loads(await first.recv())["payload"] != probe["payload"]:
                    raise RuntimeError("Opaque transport echo differs from request")
                rtt_ms = (time.perf_counter_ns() - start) / 1e6
                return {
                    "network_handshake_ms": handshake_ms,
                    "network_message_roundtrip_ms": message_ms,
                    "network_rekey_ms": rekey_ms,
                    "relay_transport_roundtrip_ms": rtt_ms,
                }
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
