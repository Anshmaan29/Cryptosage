"""Local Python client: identity keys, protocol state, plaintext and local UI."""

from __future__ import annotations
import asyncio
import json
import hashlib
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict
import psutil
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed
from client.storage import MAX_HISTORY, MAX_SEEN
from crypto.primitives import available_algorithms, versions
from policy.engine import load_policy
from protocol.identity import Identity, unb64, valid_name
from protocol.session import Peer, ReceiptExpectation


RETRYABLE = {"failed", "unconfirmed"}
IN_FLIGHT = {"pending", "sent"}


class InFlight(TypedDict):
    message: dict[str, Any]
    expectation: ReceiptExpectation
    started: float


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Client:
    def __init__(
        self,
        name: str,
        data_dir: Path,
        contacts_dir: Path,
        relay: str,
        policy_path: str | Path | None = None,
        *,
        storage_backend: str | None = None,
    ):
        self.identity = Identity(data_dir, name, storage_backend=storage_backend)
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
        self.socket: ClientConnection | None = None
        self.connected = False
        self.events: deque[dict[str, str]] = deque(maxlen=200)
        self.store = self.identity.store
        messages, self.seen_messages = self.store.load_conversation()
        self.messages = deque(messages, maxlen=MAX_HISTORY)
        recovered = False
        for message in self.messages:
            if message.get("status") in IN_FLIGHT:
                message["status"] = "unconfirmed"
                message["error"] = "Client restarted before delivery was confirmed"
                recovered = True
        if recovered:
            self._save()
        self.outbox: dict[tuple[str, int], InFlight] = {}
        self.benchmarks: dict[str, Any] | None = None
        self.attack_results: list[dict] = []
        self.lock = asyncio.Lock()
        self.ready = asyncio.Event()
        self.benchmark_busy = False
        self.process = psutil.Process()

    def event(self, kind: str, detail: str):
        self.events.append({"time": now(), "kind": kind, "detail": detail})

    def contacts(self) -> list[dict]:
        result: list[dict] = []
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

    def _save(self) -> None:
        self.store.save_conversation(list(self.messages), self.seen_messages)

    def _invalidate(self) -> None:
        self.peer.session = None
        self.ready.clear()

    def _mark_unconfirmed(self, keys: list[tuple[str, int]], reason: str) -> None:
        if not keys:
            return
        for key in keys:
            message = self.outbox.pop(key)["message"]
            message.update(status="unconfirmed", error=reason)
        self._save()

    def _expire(self) -> None:
        moment = time.monotonic()
        expired = [
            key for key, entry in self.outbox.items() if moment - entry["started"] > 30
        ]
        self._mark_unconfirmed(
            expired, "No authenticated delivery receipt arrived in time"
        )
        session = self.peer.session
        if session and (
            moment >= session.expires_at
            or any(key[0] == session.session_id for key in expired)
        ):
            self._invalidate()
            self.event(
                "timeout", "Establish a fresh session before sending or retrying"
            )
        if self.peer.expire():
            self.event(
                "timeout", "Handshake expired; establish a fresh session to retry"
            )

    def _routing_status(self, packet: dict) -> None:
        sid, counter = packet.get("sid"), packet.get("counter")
        if not isinstance(sid, str):
            raise ValueError("Malformed relay status")
        session, pending = self.peer.session, self.peer.pending
        if type(counter) is int:
            key = (sid, counter)
            entry = self.outbox.get(key)
            if entry is None:
                return
            if packet["type"] == "relay_sent":
                if entry["message"]["status"] == "pending":
                    entry["message"]["status"] = "sent"
                    self._save()
                return
            self._mark_unconfirmed(
                [key], "Relay reported the peer unavailable; delivery is unconfirmed"
            )
            if session and session.session_id == sid:
                self._invalidate()
        elif (
            packet["type"] == "relay_error"
            and pending
            and pending["offer"]["sid"] == sid
        ):
            self.peer.pending = None
            self.ready.clear()
        else:
            return
        self.event(
            "offline",
            "Relay reported the peer unavailable; establish a fresh session to retry",
        )

    def _receive_message(self, packet: dict) -> dict:
        session = self.peer.session
        if not session:
            raise ValueError("No authenticated session for this message")
        message_id, text = session.open_message(packet)
        fingerprint = self.identity.trusted[session.peer]
        key = (
            hashlib.sha256(f"{session.peer}:{fingerprint}".encode()).hexdigest()
            + message_id
        )
        digest = hashlib.sha256(text.encode()).hexdigest()
        previous = self.seen_messages.get(key)
        if previous is not None:
            if previous != digest:
                raise ValueError(
                    "Authenticated message ID reused with different content"
                )
            self.event(
                "duplicate",
                "Previously stored message authenticated again; acknowledging without displaying it twice",
            )
        else:
            received = {
                "id": message_id,
                "direction": "received",
                "text": text,
                "time": now(),
                "peer": session.peer,
            }
            messages = deque(self.messages, maxlen=MAX_HISTORY)
            messages.append(received)
            seen = {**self.seen_messages, key: digest}
            if len(seen) > MAX_SEEN:
                del seen[next(iter(seen))]
            try:
                self.store.save_conversation(list(messages), seen)
            except (OSError, ValueError) as exc:
                self._invalidate()
                raise ValueError("History could not be saved; session closed") from exc
            self.messages, self.seen_messages = messages, seen
            self.event("message", "Encrypted message authenticated and stored locally")
        return session.delivery_receipt(packet)

    async def run(self):
        while True:
            try:
                async with connect(
                    self.relay_url, max_size=262_144, open_timeout=5, proxy=None
                ) as socket:
                    await socket.send(
                        json.dumps(
                            {"register": self.identity.name, "routing_status": True}
                        )
                    )
                    registered = json.loads(await asyncio.wait_for(socket.recv(), 5))
                    if registered != {"type": "registered", "name": self.identity.name}:
                        raise ValueError("Relay registration failed")
                    self.socket, self.connected = socket, True
                    self.event("connected", "Connected to ciphertext relay")
                    while True:
                        try:
                            raw = await asyncio.wait_for(socket.recv(), 1)
                        except TimeoutError:
                            async with self.lock:
                                self._expire()
                            continue
                        async with self.lock:
                            self._expire()
                            try:
                                packet = json.loads(raw)
                                if not isinstance(packet, dict):
                                    raise ValueError("Malformed packet envelope")
                                if packet.get("type") in ("relay_sent", "relay_error"):
                                    self._routing_status(packet)
                                    continue
                                if packet.get("type") == "delivery":
                                    sid, counter = (
                                        packet.get("sid"),
                                        packet.get("counter"),
                                    )
                                    if (
                                        not isinstance(sid, str)
                                        or type(counter) is not int
                                    ):
                                        raise ValueError("Malformed delivery receipt")
                                    entry = self.outbox.get((sid, counter))
                                    if not entry:
                                        raise ValueError(
                                            "Unexpected or duplicate delivery receipt"
                                        )
                                    entry["expectation"].verify(packet)
                                    entry["message"].update(
                                        status="delivered", delivered_at=now()
                                    )
                                    entry["message"].pop("error", None)
                                    self._save()
                                    del self.outbox[(sid, counter)]
                                    self.event(
                                        "delivery",
                                        "Recipient authenticated and stored the message; receipt verified",
                                    )
                                    continue
                                if packet.get("type") == "message":
                                    await socket.send(
                                        json.dumps(self._receive_message(packet))
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
                async with self.lock:
                    self.connected = False
                    self.socket = None
                    self.peer.pending = None
                    self._invalidate()
                    try:
                        self._mark_unconfirmed(
                            list(self.outbox),
                            "Connection lost before delivery was confirmed",
                        )
                    except (OSError, ValueError):
                        self.event("storage", "Delivery updates could not be saved")
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
            try:
                await self.socket.send(json.dumps(packet))
            except (OSError, ConnectionClosed) as exc:
                self.peer.pending = None
                raise ValueError("Relay disconnected during handshake") from exc
            self.event("handshake", f"Opening an authenticated session with {remote}")
        return {"status": "negotiating", "session_id": packet["sid"]}

    async def send(
        self,
        text: str,
        expected_peer: str | None = None,
        expected_session_id: str | None = None,
        *,
        retry_id: str | None = None,
    ):
        async with self.lock:
            self._expire()
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
            if len(self.outbox) >= MAX_HISTORY:
                raise ValueError("Too many messages awaiting delivery confirmation")
            fingerprint = self.identity.trusted[session.peer]
            message: dict[str, Any] | None
            if retry_id is None:
                message = {
                    "id": secrets.token_hex(16),
                    "direction": "sent",
                    "text": text,
                    "time": now(),
                    "peer": session.peer,
                    "peer_fingerprint": fingerprint,
                }
            else:
                message = next(
                    (
                        m
                        for m in self.messages
                        if m["direction"] == "sent" and m.get("id") == retry_id
                    ),
                    None,
                )
                if not message or message.get("status") not in RETRYABLE:
                    raise ValueError(
                        "Only failed or unconfirmed outgoing messages can be retried"
                    )
                if (
                    message.get("peer_fingerprint") != fingerprint
                    or message["peer"] != session.peer
                ):
                    raise ValueError(
                        "The original verified recipient is required to retry"
                    )
                if (
                    not message.get("attempt_session")
                    or message["attempt_session"] == session.session_id
                ):
                    raise ValueError(
                        "Establish a fresh session with this contact before retrying"
                    )
                text = message["text"]
            packet = session.seal(text, bytes.fromhex(message["id"]))
            message.update(status="pending", attempt_session=session.session_id)
            message.pop("error", None)
            if retry_id is None:
                self.messages.append(message)
            key = (packet["sid"], packet["counter"])
            attempted = False
            try:
                self._save()
                self.outbox[key] = {
                    "message": message,
                    "expectation": session.receipt_expectation(packet),
                    "started": time.monotonic(),
                }
                attempted = True
                await self.socket.send(json.dumps(packet))
            except (
                OSError,
                ValueError,
                ConnectionClosed,
                asyncio.CancelledError,
            ) as exc:
                self.outbox.pop(key, None)
                message["status"] = "unconfirmed" if attempted else "failed"
                message["error"] = (
                    "Relay transmission was interrupted; delivery is unconfirmed"
                    if attempted
                    else "Message could not be saved before transmission"
                )
                self._invalidate()
                try:
                    self._save()
                except (OSError, ValueError):
                    self.event("storage", "Delivery update could not be saved")
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ValueError(message["error"]) from exc
        return {"status": "pending", "id": message["id"]}

    async def retry(self, message_id: str):
        return await self.send("", retry_id=message_id)

    def state(self):
        self._expire()
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
            "messages": [
                {
                    **{
                        k: v
                        for k, v in message.items()
                        if k not in {"attempt_session", "peer_fingerprint"}
                    },
                    "retry_available": bool(
                        message.get("status") in RETRYABLE
                        and message.get("attempt_session")
                        and message.get("peer_fingerprint")
                        == self.identity.trusted.get(message["peer"])
                    ),
                    "retry_ready": bool(
                        self.peer.session
                        and message["peer"] == self.peer.session.peer
                        and message.get("attempt_session")
                        != self.peer.session.session_id
                    ),
                }
                for message in self.messages
            ],
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
