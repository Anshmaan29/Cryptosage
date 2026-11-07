"""Local Python client: identity keys, protocol state, plaintext and local UI."""

from __future__ import annotations
import asyncio
import json
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import psutil
from websockets.asyncio.client import connect
from client.storage import LocalStore
from crypto.primitives import available_algorithms, versions
from policy.engine import load_policy
from protocol.identity import Identity, unb64, valid_name
from protocol.session import Peer


def now():
    return datetime.now(timezone.utc).isoformat()


class Client:
    def __init__(
        self,
        name: str,
        data_dir: Path,
        contacts_dir: Path,
        relay: str,
        policy_path=None,
    ):
        self.identity = Identity(data_dir, name)
        self.contacts_dir = Path(contacts_dir)
        self.policy_path = (
            Path(policy_path)
            if policy_path
            else self.identity.directory / "policy.json"
        )
        self.peer = Peer(
            self.identity,
            load_policy(self.policy_path if self.policy_path.exists() else None),
        )
        self.relay_url = relay
        self.socket = None
        self.connected = False
        self.events = deque(maxlen=200)
        self.store = LocalStore(self.identity.directory)
        self.messages = deque(self.store.load_history(), maxlen=500)
        for message in self.messages:
            if message.get("status") in ("pending", "sent"):
                message["status"] = "failed"
                message["error"] = "Client restarted before delivery was confirmed"
        self.store.save_history(list(self.messages))
        self.outbox = {}
        self.benchmarks = None
        self.attack_results = []
        self.lock = asyncio.Lock()
        self.ready = asyncio.Event()
        self.task = None
        self.benchmark_busy = False
        self.process = psutil.Process()

    def event(self, kind: str, detail: str):
        self.events.append({"time": now(), "kind": kind, "detail": detail})

    def contacts(self) -> list[dict]:
        result = []
        if not self.contacts_dir.exists():
            return result
        for path in sorted(self.contacts_dir.glob("*.json")):
            data = json.loads(path.read_text())
            if data["name"] != self.identity.name:
                key = unb64(data["public"])
                from protocol.identity import fingerprint

                fp = fingerprint(key)
                result.append(
                    {
                        "name": data["name"],
                        "fingerprint": fp,
                        "verified": self.identity.trusted.get(data["name"]) == fp,
                        "pinned_fingerprint": self.identity.trusted.get(data["name"]),
                        "identity_changed": data["name"] in self.identity.trusted
                        and self.identity.trusted[data["name"]] != fp,
                    }
                )
        return result

    def trust(
        self,
        name: str,
        expected: str,
        replace: bool = False,
        previous_fingerprint: str | None = None,
    ):
        valid_name(name)
        path = self.contacts_dir / (name + ".json")
        if not path.exists():
            raise ValueError("Contact public key is not in the local directory")
        data = json.loads(path.read_text())
        if data["name"] != name:
            raise ValueError("Contact directory name mismatch")
        old = self.identity.trusted.get(name)
        self.identity.pin(
            name,
            unb64(data["public"]),
            expected,
            replace=replace,
            previous_fingerprint=previous_fingerprint,
        )
        if old and old != self.identity.trusted[name]:
            self.peer.session = None
            self.peer.pending = None
            self.ready.clear()
        self.event("verified", f"{name}: fingerprint explicitly pinned locally")

    async def run(self):
        while True:
            try:
                async with connect(
                    self.relay_url, max_size=262_144, open_timeout=5, proxy=None
                ) as socket:
                    await socket.send(json.dumps({"register": self.identity.name}))
                    registered = json.loads(await asyncio.wait_for(socket.recv(), 5))
                    if registered.get("type") != "registered":
                        raise ValueError("Relay registration failed")
                    self.socket, self.connected = socket, True
                    self.event("connected", "Connected to ciphertext relay")
                    async for raw in socket:
                        async with self.lock:
                            try:
                                packet = json.loads(raw)
                                if not isinstance(packet, dict):
                                    raise ValueError("Malformed packet envelope")
                                if packet.get("type") == "relay_error":
                                    self.peer.pending = None
                                    self.peer.session = None
                                    for entry in self.outbox.values():
                                        entry["message"]["status"] = "failed"
                                        entry["message"]["error"] = (
                                            "Relay reported the peer offline; delivery is unconfirmed"
                                        )
                                    self.outbox.clear()
                                    self.store.save_history(list(self.messages))
                                    self.ready.clear()
                                    self.event(
                                        "offline",
                                        "Peer is offline; start the peer client and try again",
                                    )
                                    continue
                                if packet.get("type") == "delivery":
                                    entry = self.outbox.get(
                                        (packet.get("sid"), packet.get("counter"))
                                    )
                                    if not entry:
                                        raise ValueError(
                                            "Unexpected or duplicate delivery receipt"
                                        )
                                    entry["expectation"].verify(packet)
                                    entry["message"]["status"] = "delivered"
                                    entry["message"]["delivered_at"] = now()
                                    self.store.save_history(list(self.messages))
                                    del self.outbox[(packet["sid"], packet["counter"])]
                                    self.event(
                                        "delivery",
                                        "Peer authenticated and saved the encrypted message; delivery receipt verified",
                                    )
                                    continue
                                if packet.get("type") == "message":
                                    if not self.peer.session:
                                        raise ValueError(
                                            "No authenticated session for this message"
                                        )
                                    text = self.peer.session.open(packet)
                                    self.messages.append(
                                        {
                                            "id": secrets.token_hex(16),
                                            "direction": "received",
                                            "text": text,
                                            "time": now(),
                                            "peer": self.peer.session.peer,
                                        }
                                    )
                                    try:
                                        self.store.save_history(list(self.messages))
                                    except Exception:
                                        self.peer.session = None
                                        self.ready.clear()
                                        raise ValueError(
                                            "History could not be saved; session closed"
                                        )
                                    await socket.send(
                                        json.dumps(
                                            self.peer.session.delivery_receipt(packet)
                                        )
                                    )
                                    self.event(
                                        "message",
                                        "Encrypted message authenticated, decrypted and stored locally; receipt sent through relay",
                                    )
                                else:
                                    before = self.peer.session
                                    response = self.peer.receive(packet)
                                    stage = {
                                        "offer": "Signed peer offer verified; policy checked and KEM ciphertext generated locally",
                                        "response": "Signed response and negotiated policy verified; KEM secret derived and responder confirmation checked",
                                        "finish": "Initiator key confirmation verified; responder session established",
                                        "ack": "Responder final confirmation verified; initiator session established",
                                    }.get(packet.get("type"))
                                    if stage:
                                        self.event("protocol", stage)
                                    if response:
                                        await socket.send(json.dumps(response))
                                    if (
                                        self.peer.session
                                        and self.peer.session is not before
                                    ):
                                        self.ready.set()
                                        self.event(
                                            "session",
                                            f"Authenticated {self.peer.session.algorithm} session established with {self.peer.session.peer}",
                                        )
                            except (
                                ValueError,
                                KeyError,
                                TypeError,
                                OverflowError,
                            ) as exc:
                                self.event("rejected", str(exc))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.event(
                    "disconnected",
                    f"Relay connection unavailable ({type(exc).__name__}); retrying",
                )
            finally:
                self.connected = False
                self.socket = None
                self.peer.pending = None
                self.peer.session = None
                self.ready.clear()
                for entry in self.outbox.values():
                    entry["message"]["status"] = "failed"
                    entry["message"]["error"] = (
                        "Connection lost before delivery was confirmed"
                    )
                self.outbox.clear()
                self.store.save_history(list(self.messages))
            await asyncio.sleep(1)

    async def establish(self, remote: str, expected_session_id: str | None = None):
        valid_name(remote)
        if remote == self.identity.name:
            raise ValueError("Choose another local identity")
        async with self.lock:
            if not self.connected or not self.socket:
                raise ValueError("Relay is offline")
            if expected_session_id is not None and (
                not self.peer.session
                or self.peer.session.session_id != expected_session_id
            ):
                raise ValueError(
                    "Session changed; review the conversation before sending"
                )
            self.peer.expire()
            self.ready.clear()
            packet = self.peer.initiate(remote)
            await self.socket.send(json.dumps(packet))
            self.event("handshake", f"Opening an authenticated session with {remote}")
        return {"status": "negotiating", "session_id": packet["sid"]}

    async def send(
        self,
        text: str,
        expected_peer: str | None = None,
        expected_session_id: str | None = None,
    ):
        async with self.lock:
            session = self.peer.session
            if not self.connected or not self.socket or not session:
                raise ValueError("Open and authenticate a session first")
            if (expected_peer is not None and session.peer != expected_peer) or (
                expected_session_id is not None
                and session.session_id != expected_session_id
            ):
                raise ValueError(
                    "Session or recipient changed; review the conversation before sending"
                )
            expected_peer, expected_session_id = session.peer, session.session_id
            needs_rekey = session.send_count >= session.rekey_interval
        if needs_rekey:
            started = await self.establish(expected_peer, expected_session_id)
            try:
                await asyncio.wait_for(self.ready.wait(), 10)
            except asyncio.TimeoutError as exc:
                raise ValueError(
                    "Periodic re-key did not complete; message was not sent"
                ) from exc
            expected_session_id = started["session_id"]
            self.event("rekey", "Periodic post-quantum re-key completed")
        async with self.lock:
            session = self.peer.session
            if not self.connected or not self.socket or not session:
                raise ValueError("Open and authenticate a session first")
            if (
                session.peer != expected_peer
                or session.session_id != expected_session_id
            ):
                raise ValueError(
                    "Session or recipient changed; review the conversation before sending"
                )
            packet = session.seal(text)
            message = {
                "id": secrets.token_hex(16),
                "direction": "sent",
                "text": text,
                "time": now(),
                "peer": session.peer,
                "status": "pending",
            }
            self.messages.append(message)
            try:
                self.store.save_history(list(self.messages))
                self.outbox[(packet["sid"], packet["counter"])] = {
                    "message": message,
                    "expectation": session.receipt_expectation(packet),
                    "started": time.monotonic(),
                }
                await self.socket.send(json.dumps(packet))
                message["status"] = "sent"
                self.store.save_history(list(self.messages))
                self.event(
                    "message",
                    "Encrypted message sent to the relay; peer delivery remains unconfirmed",
                )
            except Exception:
                self.outbox.pop((packet["sid"], packet["counter"]), None)
                message["status"] = "failed"
                message["error"] = "Send failed; delivery is unconfirmed"
                self.peer.session = None
                self.ready.clear()
                try:
                    self.store.save_history(list(self.messages))
                except Exception:
                    pass
                raise ValueError(
                    "Message could not be stored or sent; reconnect before retrying"
                )
        return {"status": "sent", "id": message["id"]}

    def state(self):
        expired = [
            key
            for key, entry in self.outbox.items()
            if time.monotonic() - entry["started"] > 30
        ]
        for key in expired:
            entry = self.outbox.pop(key)
            entry["message"]["status"] = "failed"
            entry["message"]["error"] = (
                "No authenticated delivery receipt arrived in time"
            )
        if expired:
            if self.peer.session and any(
                key[0] == self.peer.session.session_id for key in expired
            ):
                self.peer.session = None
                self.ready.clear()
                self.event(
                    "timeout",
                    "Delivery was not confirmed; establish a fresh session before resending",
                )
            self.store.save_history(list(self.messages))
        if self.peer.expire():
            self.event("timeout", "Handshake expired; reconnect to retry")
        return {
            "identity": {
                "name": self.identity.name,
                "fingerprint": self.identity.fingerprint,
                "safety_number": self.identity.safety_number,
            },
            "contacts": self.contacts(),
            "connected": self.connected,
            "negotiating": self.peer.pending is not None,
            "selection_decision": self.peer.last_decision,
            "session": self.peer.session.public() if self.peer.session else None,
            "messages": list(self.messages),
            "events": list(self.events),
            "metrics": {
                "rss_bytes": self.process.memory_info().rss,
                "cpu_percent": self.process.cpu_percent(),
                "versions": versions(),
            },
            "algorithms": available_algorithms(),
            "policy": self.peer.policy,
            "benchmark_busy": self.benchmark_busy,
            "benchmark_completed": self.benchmarks is not None,
            "attack_results": self.attack_results[-10:],
        }
