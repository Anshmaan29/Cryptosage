"""A four-flight, transcript-bound research handshake and ordered hash ratchet."""

from __future__ import annotations
from cryptography.exceptions import InvalidTag
import hashlib
import hmac
import secrets
import time
from copy import deepcopy
from dataclasses import dataclass, field
from crypto.primitives import (
    kem_keypair,
    encapsulate,
    decapsulate,
    verify,
    hkdf,
    encrypt,
    decrypt,
)
from protocol.identity import Identity, b64, unb64, canonical
from policy.engine import admissible_algorithms, installed_algorithms, select

VERSION = "crytosage/2"
MAX_MESSAGE = 16_384
REKEY_AFTER = 100
SESSION_LIFETIME = 3600
MESSAGE_ID_BYTES = 16


def digest(value: dict) -> bytes:
    return hashlib.sha256(canonical(value)).digest()


def mac(key: bytes, label: bytes, transcript: bytes) -> str:
    return b64(hmac.digest(key, label + transcript, "sha256"))


def check_mac(key: bytes, label: bytes, transcript: bytes, supplied: str) -> None:
    if not isinstance(supplied, str) or not hmac.compare_digest(
        mac(key, label, transcript), supplied
    ):
        raise ValueError("Shared-key confirmation failed")


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
    rekey_interval: int = REKEY_AFTER
    decision: dict = field(default_factory=dict)
    security_level: int = 0
    _issue_receipt_key: bytes = field(default=b"", repr=False)
    _verify_receipt_key: bytes = field(default=b"", repr=False)
    expires_at: float = field(
        default_factory=lambda: time.monotonic() + SESSION_LIFETIME
    )
    _last_received_hash: bytes = field(default=b"", repr=False)

    @classmethod
    def create(
        cls, sid, local, peer, selection, transcript, shared, initiator, elapsed=0
    ):
        root = hkdf(shared, b"crytosage/2/root", salt=transcript)
        a = hkdf(root, b"crytosage/2/initiator-chain")
        b = hkdf(root, b"crytosage/2/responder-chain")
        return cls(
            sid,
            local,
            peer,
            selection["algorithm"],
            selection["reason"],
            transcript,
            a if initiator else b,
            b if initiator else a,
            elapsed,
            rekey_interval=selection.get("rekey_interval", REKEY_AFTER),
            decision=deepcopy(selection.get("decision", {})),
            security_level=selection["security_level"],
            _issue_receipt_key=hkdf(
                root,
                b"crytosage/2/responder-delivery"
                if initiator
                else b"crytosage/2/initiator-delivery",
            ),
            _verify_receipt_key=hkdf(
                root,
                b"crytosage/2/initiator-delivery"
                if initiator
                else b"crytosage/2/responder-delivery",
            ),
        )

    def seal(self, text: str, message_id: bytes | None = None) -> dict:
        if time.monotonic() >= self.expires_at:
            raise ValueError("Session expired; establish a fresh session")
        if message_id is None:
            message_id = secrets.token_bytes(MESSAGE_ID_BYTES)
        if not isinstance(message_id, bytes) or len(message_id) != MESSAGE_ID_BYTES:
            raise ValueError("Invalid message identifier")
        if not isinstance(text, str) or not text or len(text.encode()) > MAX_MESSAGE:
            raise ValueError("Message must contain 1–16384 UTF-8 bytes")
        if self.send_count >= self.rekey_interval:
            raise ValueError("Re-key required before sending more messages")
        start = time.perf_counter_ns()
        header = {
            "type": "message",
            "v": VERSION,
            "sid": self.session_id,
            "from": self.local,
            "to": self.peer,
            "counter": self.send_count,
        }
        key = hkdf(self._send_chain, b"crytosage/2/message-key")
        nonce = self.send_count.to_bytes(12, "big")
        ciphertext = encrypt(key, nonce, message_id + text.encode(), canonical(header))
        self._send_chain = hkdf(self._send_chain, b"crytosage/2/next-chain")
        self.send_count += 1
        self.encryption_us = (time.perf_counter_ns() - start) / 1000
        return {**header, "ciphertext": b64(ciphertext)}

    def open(self, packet: dict) -> str:
        return self.open_message(packet)[1]

    def open_message(self, packet: dict) -> tuple[str, str]:
        if time.monotonic() >= self.expires_at:
            raise ValueError("Session expired; establish a fresh session")
        start = time.perf_counter_ns()
        expected_keys = {"type", "v", "sid", "from", "to", "counter", "ciphertext"}
        if (
            set(packet) != expected_keys
            or packet["v"] != VERSION
            or packet["type"] != "message"
        ):
            raise ValueError("Malformed encrypted message")
        if (
            packet["sid"] != self.session_id
            or packet["from"] != self.peer
            or packet["to"] != self.local
        ):
            raise ValueError("Message belongs to a different session or identity")
        counter = packet["counter"]
        if type(counter) is not int or counter < 0 or counter >= self.rekey_interval:
            raise ValueError("Invalid message counter")
        if counter < self.receive_count:
            raise ValueError("Replay rejected: message counter already consumed")
        if counter != self.receive_count:
            raise ValueError(
                "Out-of-order message rejected; reconnect to recover a lost message"
            )
        ciphertext = unb64(packet["ciphertext"])
        if (
            not MESSAGE_ID_BYTES + 17
            <= len(ciphertext)
            <= MAX_MESSAGE + MESSAGE_ID_BYTES + 16
        ):
            raise ValueError("Invalid ciphertext length")
        header = {k: v for k, v in packet.items() if k != "ciphertext"}
        key = hkdf(self._receive_chain, b"crytosage/2/message-key")
        try:
            plaintext = decrypt(
                key, counter.to_bytes(12, "big"), ciphertext, canonical(header)
            )
            text = plaintext[MESSAGE_ID_BYTES:].decode("utf-8")
        except (ValueError, UnicodeDecodeError, InvalidTag) as exc:
            raise ValueError("Ciphertext integrity verification failed") from exc
        self._receive_chain = hkdf(self._receive_chain, b"crytosage/2/next-chain")
        self.receive_count += 1
        self.decryption_us = (time.perf_counter_ns() - start) / 1000
        self._last_received_hash = digest(packet)
        return plaintext[:MESSAGE_ID_BYTES].hex(), text

    def delivery_receipt(self, packet: dict) -> dict:
        if (
            packet.get("sid") != self.session_id
            or packet.get("from") != self.peer
            or packet.get("to") != self.local
            or type(packet.get("counter")) is not int
            or packet["counter"] != self.receive_count - 1
            or digest(packet) != self._last_received_hash
        ):
            raise ValueError(
                "Only an authenticated, consumed message can be acknowledged"
            )
        body = {
            "type": "delivery",
            "v": VERSION,
            "sid": self.session_id,
            "from": self.local,
            "to": self.peer,
            "counter": packet["counter"],
            "packet_hash": b64(digest(packet)),
        }
        return {
            **body,
            "confirmation": mac(self._issue_receipt_key, b"delivery", canonical(body)),
        }

    def receipt_expectation(self, packet: dict):
        return ReceiptExpectation(
            packet["sid"],
            packet["from"],
            packet["to"],
            packet["counter"],
            b64(digest(packet)),
            self._verify_receipt_key,
        )

    def public(self) -> dict:
        return {
            "session_id": self.session_id,
            "peer": self.peer,
            "algorithm": self.algorithm,
            "security_level": self.security_level,
            "reason": self.reason,
            "decision": self.decision,
            "rekey_interval": self.rekey_interval,
            "handshake_ms": self.handshake_ms,
            "send_count": self.send_count,
            "receive_count": self.receive_count,
            "encryption_us": self.encryption_us,
            "decryption_us": self.decryption_us,
        }


@dataclass
class ReceiptExpectation:
    session_id: str
    sender: str
    recipient: str
    counter: int
    packet_hash: str
    _key: bytes = field(repr=False)

    def verify(self, packet: dict) -> None:
        expected = {
            "type": "delivery",
            "v": VERSION,
            "sid": self.session_id,
            "from": self.recipient,
            "to": self.sender,
            "counter": self.counter,
            "packet_hash": self.packet_hash,
        }
        if (
            type(packet.get("counter")) is not int
            or set(packet) != {*expected, "confirmation"}
            or any(packet.get(k) != v for k, v in expected.items())
        ):
            raise ValueError("Delivery receipt does not match the sent packet")
        check_mac(self._key, b"delivery", canonical(expected), packet["confirmation"])


class Peer:
    def __init__(
        self, identity: Identity, policy: dict, measurements: dict | None = None
    ):
        installed_algorithms()
        self.identity, self.policy = identity, policy
        self.measurements = measurements or {}
        self.pending: dict | None = None
        self.session: Session | None = None
        self.previous: dict[str, tuple[Session, float]] = {}
        self.seen: dict[str, float] = {}
        self.last_decision: dict | None = None

    def _offer(self) -> dict:
        return {
            "algorithms": admissible_algorithms(self.policy),
            "policy": deepcopy(self.policy),
            "measurements": deepcopy(self.measurements),
        }

    def _select(self, left: dict, right: dict) -> dict:
        try:
            result = select(left, right)
        except ValueError as exc:
            self.last_decision = getattr(exc, "decision", None)
            raise
        self.last_decision = result.get("decision")
        return result

    def _signed(self, body: dict) -> dict:
        return {**body, "signature": self.identity.sign(body)}

    def _verify(self, packet: dict) -> dict:
        if not isinstance(packet, dict) or len(canonical(packet)) > 250_000:
            raise ValueError("Malformed protocol message")
        body = {k: v for k, v in packet.items() if k != "signature"}
        if body.get("v") != VERSION or body.get("to") != self.identity.name:
            raise ValueError("Unsupported protocol version or recipient")
        public = unb64(body.get("identity", ""))
        sender = body.get("from")
        if not isinstance(sender, str):
            raise ValueError("Invalid handshake sender")
        self.identity.check_peer(sender, public)
        if not verify(public, canonical(body), unb64(packet.get("signature", ""))):
            raise ValueError("Invalid negotiation signature")
        sid = body.get("sid")
        if (
            not isinstance(sid, str)
            or len(sid) != 64
            or any(c not in "0123456789abcdef" for c in sid)
        ):
            raise ValueError("Invalid session identifier")
        return body

    def initiate(self, peer: str) -> dict:
        self.expire()
        if self.pending:
            raise ValueError("A handshake is already in progress")
        if peer not in self.identity.trusted:
            raise ValueError(
                "Unverified contact: compare and pin the fingerprint first"
            )
        started = time.perf_counter_ns()
        offer = self._offer()
        keys = {name: kem_keypair(name) for name in offer["algorithms"]}
        if not keys:
            raise ValueError("No supported post-quantum KEM is available")
        body = {
            "type": "offer",
            "v": VERSION,
            "sid": secrets.token_hex(32),
            "from": self.identity.name,
            "to": peer,
            "identity": b64(self.identity.public),
            "nonce": secrets.token_hex(32),
            "time": int(time.time()),
            "offer": offer,
            "kem_keys": {name: b64(pair[0]) for name, pair in keys.items()},
        }
        packet = self._signed(body)
        self.pending = {
            "role": "initiator",
            "offer": body,
            "keys": keys,
            "start": started,
            "expires": time.monotonic() + 30,
        }
        return packet

    def receive_session(self, sid: object) -> Session | None:
        if not isinstance(sid, str):
            return None
        if self.session and sid == self.session.session_id:
            return self.session
        old = self.previous.get(sid)
        return old[0] if old and time.monotonic() < old[1] else None

    def expire(self) -> bool:
        now = time.monotonic()
        self.previous = {
            sid: entry for sid, entry in self.previous.items() if entry[1] > now
        }
        if self.pending and now > self.pending["expires"]:
            self.pending = None
            return True
        return False

    def receive(self, packet: dict) -> dict | None:
        self.expire()
        kind = packet.get("type") if isinstance(packet, dict) else None
        if kind == "offer":
            started = time.perf_counter_ns()
            body = self._verify(packet)
            if set(body) != {
                "type",
                "v",
                "sid",
                "from",
                "to",
                "identity",
                "nonce",
                "time",
                "offer",
                "kem_keys",
            }:
                raise ValueError("Malformed handshake offer")
            if type(body["time"]) is not int or abs(time.time() - body["time"]) > 60:
                raise ValueError("Replay rejected: stale handshake timestamp")
            if (
                not isinstance(body["nonce"], str)
                or len(body["nonce"]) != 64
                or any(c not in "0123456789abcdef" for c in body["nonce"])
            ):
                raise ValueError("Invalid handshake nonce")
            self.seen = {
                sid: end for sid, end in self.seen.items() if end > time.monotonic()
            }
            if body["sid"] in self.seen:
                raise ValueError("Replay rejected: session identifier already seen")
            if len(self.seen) >= 4096:
                raise ValueError("Handshake replay cache full; retry later")
            if self.pending:
                outgoing = self.pending["offer"]
                if (
                    self.pending["role"] != "initiator"
                    or "keys" not in self.pending
                    or outgoing["to"] != body["from"]
                ):
                    raise ValueError("A handshake is already in progress")
                if self.identity.name < body["from"]:
                    self.seen[body["sid"]] = time.monotonic() + 120
                    return None
            local_offer = self._offer()
            selection = self._select(body["offer"], local_offer)
            algorithm = selection["algorithm"]
            if not isinstance(body["kem_keys"], dict) or set(body["kem_keys"]) != set(
                body["offer"]["algorithms"]
            ):
                raise ValueError("Offered KEM keys do not match capabilities")
            ciphertext, shared = encapsulate(
                algorithm, unb64(body["kem_keys"][algorithm])
            )
            response = {
                "type": "response",
                "v": VERSION,
                "sid": body["sid"],
                "from": self.identity.name,
                "to": body["from"],
                "identity": b64(self.identity.public),
                "nonce": secrets.token_hex(32),
                "offer_hash": b64(digest(body)),
                "offer": local_offer,
                "selected": algorithm,
                "ciphertext": b64(ciphertext),
            }
            transcript = digest({"offer": body, "response": response})
            confirm_key = hkdf(shared, b"crytosage/2/confirmation", salt=transcript)
            response["confirmation"] = mac(confirm_key, b"responder", transcript)
            self.pending = {
                "role": "responder",
                "offer": body,
                "response": response,
                "transcript": transcript,
                "shared": shared,
                "confirm_key": confirm_key,
                "selection": selection,
                "start": started,
                "expires": time.monotonic() + 30,
            }
            self.seen[body["sid"]] = time.monotonic() + 120
            return self._signed(response)
        if kind == "response":
            body = self._verify(packet)
            p = self.pending
            if (
                not p
                or p["role"] != "initiator"
                or body["sid"] != p["offer"]["sid"]
                or body["from"] != p["offer"]["to"]
            ):
                raise ValueError("Replay rejected: unexpected handshake response")
            if set(body) != {
                "type",
                "v",
                "sid",
                "from",
                "to",
                "identity",
                "nonce",
                "offer_hash",
                "offer",
                "selected",
                "ciphertext",
                "confirmation",
            }:
                raise ValueError("Malformed handshake response")
            if (
                not isinstance(body["nonce"], str)
                or len(body["nonce"]) != 64
                or any(c not in "0123456789abcdef" for c in body["nonce"])
            ):
                raise ValueError("Invalid handshake nonce")
            if "keys" not in p:
                raise ValueError("Replay rejected: handshake response already consumed")
            if body["offer_hash"] != b64(digest(p["offer"])):
                raise ValueError("Negotiation transcript mismatch")
            selection = self._select(p["offer"]["offer"], body["offer"])
            if body["selected"] != selection["algorithm"]:
                raise ValueError(
                    "Policy violation: selected algorithm differs from deterministic negotiation"
                )
            raw = {k: v for k, v in body.items() if k != "confirmation"}
            transcript = digest({"offer": p["offer"], "response": raw})
            shared = decapsulate(
                selection["algorithm"],
                p["keys"][selection["algorithm"]][1],
                unb64(body["ciphertext"]),
            )
            key = hkdf(shared, b"crytosage/2/confirmation", salt=transcript)
            check_mac(key, b"responder", transcript, body["confirmation"])
            p.update(
                transcript=transcript,
                shared=shared,
                confirm_key=key,
                selection=selection,
            )
            p.pop("keys")
            return {
                "type": "finish",
                "v": VERSION,
                "sid": body["sid"],
                "from": self.identity.name,
                "to": body["from"],
                "confirmation": mac(key, b"initiator", transcript),
            }
        if kind in ("finish", "ack"):
            if set(packet) != {"type", "v", "sid", "from", "to", "confirmation"}:
                raise ValueError("Malformed key confirmation")
            p = self.pending
            role = "responder" if kind == "finish" else "initiator"
            if not p or p["role"] != role or "confirm_key" not in p:
                raise ValueError("Replay rejected: unexpected key confirmation")
            offer = p["offer"]
            remote = offer["from"] if role == "responder" else offer["to"]
            if (
                packet["sid"] != offer["sid"]
                or packet["v"] != VERSION
                or packet["from"] != remote
                or packet["to"] != self.identity.name
            ):
                raise ValueError("Key confirmation session mismatch")
            check_mac(
                p["confirm_key"],
                b"initiator" if kind == "finish" else b"ack",
                p["transcript"],
                packet["confirmation"],
            )
            old = self.session
            new = Session.create(
                offer["sid"],
                self.identity.name,
                remote,
                p["selection"],
                p["transcript"],
                p["shared"],
                role == "initiator",
                (time.perf_counter_ns() - p["start"]) / 1e6,
            )
            if old and old.peer == new.peer:
                self.previous[old.session_id] = (old, time.monotonic() + 10)
            elif old:
                self.previous.clear()
            self.session = new
            self.pending = None
            if kind == "finish":
                return {
                    "type": "ack",
                    "v": VERSION,
                    "sid": offer["sid"],
                    "from": self.identity.name,
                    "to": remote,
                    "confirmation": mac(p["confirm_key"], b"ack", p["transcript"]),
                }
            return None
        raise ValueError("Unsupported protocol message type")


def complete_handshake(alice: Peer, bob: Peer) -> dict:
    start = time.perf_counter_ns()
    flights = []
    packet: dict | None = alice.initiate(bob.identity.name)
    for recipient in (bob, alice, bob, alice):
        if packet is None:
            raise ValueError("Handshake ended before all flights were exchanged")
        flights.append(packet)
        packet = recipient.receive(packet)
    if not alice.session or not bob.session:
        raise ValueError("Handshake did not establish both sessions")
    return {
        "handshake_ms": (time.perf_counter_ns() - start) / 1e6,
        "handshake_bytes": sum(len(canonical(p)) for p in flights),
    }
