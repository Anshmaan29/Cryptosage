"""Real WebSocket integration: process-local keys, hostile relay and recovery."""

import asyncio
import socket
from contextlib import asynccontextmanager
import pytest
from client.runtime import Client
from server.relay import run, verify_registration


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
    started = await a.establish("Bob")
    await until(
        lambda: all(
            client.peer.session
            and client.peer.session.session_id == started["session_id"]
            for client in (a, b)
        )
    )
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
            assert json.loads(await ws.recv())["type"] == "challenge"
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


async def test_unconfirmed_delivery_timeout_closes_session(tmp_path):
    import time

    async with clients(tmp_path) as (a, b, relay, port):
        await establish(a, b)
        session = a.peer.session
        packet = session.seal("Unconfirmed message")
        message = {
            "id": "timeout-test",
            "direction": "sent",
            "text": "Unconfirmed message",
            "time": "2026-01-01T00:00:00Z",
            "peer": "Bob",
            "status": "sent",
        }
        a.messages.append(message)
        a.outbox[(packet["sid"], packet["counter"])] = {
            "message": message,
            "started": time.monotonic() - 31,
            "expectation": session.receipt_expectation(packet),
        }
        state = a.state()
        assert state["session"] is None
        assert state["messages"][-1]["status"] == "unconfirmed"
        assert "receipt" in state["messages"][-1]["error"]


async def test_lost_receipt_retry_after_both_clients_restart(tmp_path):
    import json

    from websockets.asyncio.server import serve

    registered = {}
    dropped = asyncio.Event()
    routed = []

    async def route(ws):
        name, _, _ = await verify_registration(ws)
        registered[name] = ws
        await ws.send(json.dumps({"type": "registered", "name": name}))
        try:
            async for raw in ws:
                packet = json.loads(raw)
                if packet["type"] == "message":
                    routed.append(packet)
                    await ws.send(
                        json.dumps(
                            {
                                "type": "relay_sent",
                                "sid": packet["sid"],
                                "counter": packet["counter"],
                            }
                        )
                    )
                if packet["type"] == "delivery" and not dropped.is_set():
                    dropped.set()
                    continue
                await registered[packet["to"]].send(raw)
        finally:
            registered.pop(name, None)

    async with serve(route, "127.0.0.1", 0) as relay:
        port = next(iter(relay.sockets)).getsockname()[1]
        url = f"ws://127.0.0.1:{port}"

        def restore():
            return tuple(
                Client(name, tmp_path / name, tmp_path / "contacts", url)
                for name in ("Alice", "Bob")
            )

        a, b = restore()
        a.identity.pin("Bob", b.identity.public, b.identity.fingerprint)
        b.identity.pin("Alice", a.identity.public, a.identity.fingerprint)
        tasks = [asyncio.create_task(c.run()) for c in (a, b)]
        try:
            await until(lambda: a.connected and b.connected)
            await establish(a, b)
            old = a.peer.session.session_id
            result = await a.send("Private message with a lost acknowledgement")
            assert result["status"] == "pending"
            await asyncio.wait_for(dropped.wait(), 6)
            await until(lambda: a.messages[0]["status"] == "sent")
            assert b.messages[0]["id"] == result["id"]
            with pytest.raises(ValueError, match="Only failed or unconfirmed"):
                await a.retry(result["id"])
        finally:
            for task in tasks:
                await stop(task)

        a, b = restore()
        assert a.messages[0]["status"] == "unconfirmed"
        assert a.peer.session is b.peer.session is None
        assert len(b.seen_messages) == 1
        tasks = [asyncio.create_task(c.run()) for c in (a, b)]
        try:
            await until(lambda: a.connected and b.connected)
            await establish(a, b)
            assert a.peer.session.session_id != old
            retried = await a.retry(result["id"])
            assert retried["id"] == result["id"]
            await until(lambda: a.messages[0]["status"] == "delivered")
            assert len(a.messages) == len(b.messages) == len(b.seen_messages) == 1
            assert any(event["kind"] == "duplicate" for event in b.events)
            assert (
                len(routed) == 2 and routed[0]["ciphertext"] != routed[1]["ciphertext"]
            )
            assert routed[0]["sid"] != routed[1]["sid"]
            for packet in routed:
                assert set(packet) == {
                    "type",
                    "v",
                    "sid",
                    "from",
                    "to",
                    "counter",
                    "ciphertext",
                }
                assert result["id"] not in json.dumps(packet)
                assert a.messages[0]["text"] not in json.dumps(packet)
            with pytest.raises(ValueError, match="Only failed or unconfirmed"):
                await a.retry(result["id"])
        finally:
            for task in tasks:
                await stop(task)


async def test_simultaneous_sends_have_independent_chains_and_receipts(tmp_path):
    async with clients(tmp_path) as (a, b, _, _):
        await establish(a, b)
        await asyncio.gather(a.send("Alice concurrently"), b.send("Bob concurrently"))
        await until(
            lambda: all(
                len(client.messages) == 2 and not client.outbox for client in (a, b)
            )
        )
        for client, expected in ((a, "Bob concurrently"), (b, "Alice concurrently")):
            assert (
                next(m for m in client.messages if m["direction"] == "sent")["status"]
                == "delivered"
            )
            assert (
                next(m for m in client.messages if m["direction"] == "received")["text"]
                == expected
            )
            assert (
                client.peer.session.send_count == client.peer.session.receive_count == 1
            )


def test_receipt_only_acknowledges_exact_authenticated_packet(peers):
    from protocol.session import complete_handshake

    alice, bob = peers
    complete_handshake(alice, bob)
    packet = alice.session.seal("Original")
    bob.session.open(packet)
    with pytest.raises(ValueError, match="authenticated, consumed"):
        bob.session.delivery_receipt({**packet, "ciphertext": "different"})
    receipt = bob.session.delivery_receipt(packet)
    with pytest.raises(ValueError, match="does not match"):
        alice.session.receipt_expectation(packet).verify({**receipt, "counter": False})


async def test_session_lifetime_expires_without_reusing_a_chain(tmp_path):
    async with clients(tmp_path) as (a, b, _, _):
        await establish(a, b)
        session = a.peer.session
        session.expires_at = 0
        with pytest.raises(ValueError, match="Session expired"):
            session.seal("must reject")
        with pytest.raises(ValueError, match="Open and authenticate"):
            await a.send("must reject")
        await establish(a, b)
        assert a.peer.session.session_id != session.session_id


async def test_real_clients_negotiate_hqc_only_with_both_policies_opted_in(tmp_path):
    async with clients(tmp_path) as (a, b, _, _):
        for client in (a, b):
            client.peer.policy["allow_experimental"] = True
            client.peer.policy["algorithms"]["ML-KEM-768"]["status"] = "prohibited"
        await establish(a, b)
        assert a.peer.session.algorithm == b.peer.session.algorithm == "HQC-3"
        await a.send("HQC session uses real loopback transport")
        await until(lambda: a.messages[0]["status"] == "delivered")
        assert b.messages[0]["text"] == a.messages[0]["text"]


async def test_previous_session_receives_in_flight_message_after_rekey(tmp_path):
    import json
    import time

    async with clients(tmp_path) as (a, b, _, _):
        await establish(a, b)
        old = a.peer.session
        await a.establish("Bob")
        # Hold an envelope from the retiring epoch until both peers install the replacement.
        packet = old.seal("In flight during re-key")
        outgoing = {
            "direction": "sent",
            "peer": "Bob",
            "text": "In flight during re-key",
            "time": "2026-11-11",
            "status": "sent",
        }
        a.messages.append(outgoing)
        a.outbox[(packet["sid"], packet["counter"])] = {
            "message": outgoing,
            "expectation": old.receipt_expectation(packet),
            "started": time.monotonic(),
        }
        await until(lambda: a.peer.session.session_id != old.session_id)
        assert a.peer.session.session_id == b.peer.session.session_id
        await a.socket.send(json.dumps(packet))
        await until(lambda: outgoing["status"] == "delivered")
        assert [row["text"] for row in b.messages] == ["In flight during re-key"]


async def test_simultaneous_automatic_rekey_keeps_both_sends(tmp_path):
    async with clients(tmp_path) as (a, b, _, _):
        for client in (a, b):
            client.peer.policy["rekey_interval"] = 1
        await establish(a, b)
        old = a.peer.session.session_id
        await asyncio.gather(a.send("first Alice"), b.send("first Bob"))
        await until(lambda: not a.outbox and not b.outbox)
        await asyncio.gather(a.send("second Alice"), b.send("second Bob"))
        await until(lambda: not a.outbox and not b.outbox)
        assert a.peer.session.session_id == b.peer.session.session_id != old
        assert [
            row["text"] for row in a.messages if row["direction"] == "received"
        ] == ["first Bob", "second Bob"]
        assert [
            row["text"] for row in b.messages if row["direction"] == "received"
        ] == ["first Alice", "second Alice"]


async def test_relay_accepts_original_key_and_refuses_unverified_key_change(tmp_path):
    from protocol.identity import Identity
    from protocol.registration import register_client
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed

    async with clients(tmp_path) as (a, _, _, _):
        await a.socket.close()
        impostor = Identity(tmp_path / "replacement", "Alice")
        async with connect(a.relay_url, proxy=None) as ws:
            with pytest.raises(ConnectionClosed, match="Routing identity key changed"):
                await register_client(ws, impostor)
        await until(
            lambda: a.connected and a.socket is not None and a.socket.close_code is None
        )
