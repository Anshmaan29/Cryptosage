"""Real WebSocket integration: process-local keys, hostile relay and recovery."""

import asyncio
import socket
from contextlib import asynccontextmanager
import pytest
from client.runtime import Client
from server.relay import run


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def until(check, timeout=6):
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.02)


async def stop(task):
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@asynccontextmanager
async def clients(tmp_path, attack=None):
    port = free_port()
    url = f"ws://127.0.0.1:{port}"
    relay = asyncio.create_task(run(port=port, attack=attack))
    a = Client("Alice", tmp_path / "alice", tmp_path / "contacts", url)
    b = Client("Bob", tmp_path / "bob", tmp_path / "contacts", url)
    a.identity.pin("Bob", b.identity.public, b.identity.fingerprint)
    b.identity.pin("Alice", a.identity.public, a.identity.fingerprint)
    tasks = [asyncio.create_task(p.run()) for p in (a, b)]
    try:
        await until(lambda: a.connected and b.connected)
        yield a, b, relay, port
    finally:
        for task in tasks + [relay]:
            await stop(task)


async def establish(a, b):
    await a.establish("Bob")
    await until(lambda: a.peer.session and b.peer.session)
    assert a.peer.session.session_id == b.peer.session.session_id


async def test_real_relay_chat_and_fresh_rekey(tmp_path):
    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        old = a.peer.session.session_id
        await a.send("Real encrypted hello — नमस्ते")
        await until(lambda: len(b.messages) == 1)
        assert b.messages[0]["text"] == "Real encrypted hello — नमस्ते"
        await b.send("Verified reply")
        await until(lambda: len(a.messages) == 2)
        assert a.messages[-1]["direction"] == "received"
        await establish(a, b)
        assert a.peer.session.session_id != old
        assert a.peer.session.send_count == 0
        await a.send("Fresh root and chains")
        await until(lambda: len(b.messages) == 3)
        assert b.messages[-1]["text"] == "Fresh root and chains"


async def test_live_malicious_relay_replay_delivers_once(tmp_path):
    async with clients(tmp_path, "replay") as (a, b, relay, port):
        await establish(a, b)
        await a.send("Deliver exactly once")
        await until(lambda: any("Replay rejected" in e["detail"] for e in b.events))
        assert [m["text"] for m in b.messages] == ["Deliver exactly once"]


async def test_live_tamper_no_plaintext_then_new_session_recovers(tmp_path):
    async with clients(tmp_path, "tamper") as (a, b, relay, port):
        await establish(a, b)
        await a.send("Never display corrupted plaintext")
        await until(lambda: any("integrity" in e["detail"] for e in b.events))
        assert not b.messages
        await a.send("Later counter fails safely")
        await until(lambda: any("Out-of-order" in e["detail"] for e in b.events))
        assert not b.messages
        await establish(a, b)
        await a.send("New session recovers")
        await until(lambda: len(b.messages) == 1)
        assert b.messages[0]["text"] == "New session recovers"


async def test_live_downgrade_rejects_handshake(tmp_path):
    async with clients(tmp_path, "downgrade") as (a, b, relay, port):
        await a.establish("Bob")
        await until(lambda: any("signature" in e["detail"] for e in b.events))
        assert a.peer.session is None and b.peer.session is None
        assert not a.messages and not b.messages


async def test_network_interruption_discards_session_then_reconnects(tmp_path):
    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        old = a.peer.session.session_id
        await stop(relay)
        await until(lambda: not a.connected and not b.connected)
        assert a.peer.session is None and b.peer.session is None
        with pytest.raises(ValueError, match="Open and authenticate"):
            await a.send("Must not reuse disconnected session")
        replacement = asyncio.create_task(run(port=port))
        try:
            await until(lambda: a.connected and b.connected)
            await establish(a, b)
            assert a.peer.session.session_id != old
            await a.send("Connection recovered securely")
            await until(lambda: len(b.messages) == 1)
        finally:
            await stop(replacement)


async def test_periodic_rekey_after_100_messages(tmp_path):
    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        old = a.peer.session.session_id
        for i in range(100):
            await a.send(f"Message {i}")
        await until(lambda: len(b.messages) == 100)
        await a.send("Periodic rekey message")
        await until(lambda: len(b.messages) == 101)
        assert a.peer.session.session_id != old
        assert a.peer.session.send_count == b.peer.session.receive_count == 1
        assert any("Periodic" in event["detail"] for event in a.events)


async def test_recipient_and_session_binding_prevents_wrong_contact_delivery(tmp_path):
    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        sid = a.peer.session.session_id
        with pytest.raises(ValueError, match="recipient changed"):
            await a.send("Must not send to the wrong person", "Carol", sid)
        with pytest.raises(ValueError, match="Session or recipient changed"):
            await a.send("Must not reuse stale browser state", "Bob", "f" * 64)
        assert not a.messages and not b.messages
        assert a.peer.session.send_count == 0
        assert a.peer.session.public()["peer"] == "Bob"
        await a.send("Intended recipient confirmed", "Bob", sid)
        await until(lambda: len(b.messages) == 1)


@pytest.mark.parametrize(
    "hello",
    [[], None, "Alice", {"register": ["Alice"]}, {"register": {"name": "Alice"}}],
)
async def test_malformed_relay_registration_closes_cleanly(hello, caplog):
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
    import json

    port = free_port()
    relay = asyncio.create_task(run(port=port))
    try:
        for attempt in range(100):
            try:
                ws = await connect(f"ws://127.0.0.1:{port}", proxy=None)
                break
            except OSError:
                await asyncio.sleep(0.01)
        else:
            pytest.fail("Relay startup failed")
        async with ws:
            await ws.send(json.dumps(hello))
            with pytest.raises(ConnectionClosed) as closed:
                await ws.recv()
            assert closed.value.rcvd.code == 1008
        assert "connection handler failed" not in caplog.text
    finally:
        await stop(relay)


async def test_delivery_receipt_and_encrypted_history_survive_restart(tmp_path):
    from client.runtime import Client

    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        await a.send("Stored private text")
        await until(lambda: a.messages and a.messages[-1].get("status") == "delivered")
        assert b.messages[-1]["text"] == "Stored private text"
        assert (
            b"Stored private text"
            not in (tmp_path / "alice" / "history.json").read_bytes()
        )
        restored = Client(
            "Alice", tmp_path / "alice", tmp_path / "contacts", f"ws://127.0.0.1:{port}"
        )
        assert restored.messages[-1]["status"] == "delivered"
        assert restored.messages[-1]["text"] == "Stored private text"
        assert restored.peer.session is None


def test_delivery_receipt_rejects_forgery_and_wrong_packet(peers):
    from protocol.session import complete_handshake

    alice, bob = peers
    complete_handshake(alice, bob)
    packet = alice.session.seal("hello")
    expectation = alice.session.receipt_expectation(packet)
    bob.session.open(packet)
    receipt = bob.session.delivery_receipt(packet)
    expectation.verify(receipt)
    receipt["confirmation"] = "forged"
    with pytest.raises(ValueError):
        expectation.verify(receipt)
