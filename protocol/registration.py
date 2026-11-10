"""Challenge-bound possession proof for the native relay routing name."""

import asyncio
import json
from typing import TYPE_CHECKING

from protocol.identity import b64, unb64, valid_name

if TYPE_CHECKING:
    from protocol.identity import Identity

DOMAIN = b"crytosage/relay-register/v1"


def registration_payload(challenge: bytes, name: str) -> bytes:
    if len(challenge) != 32:
        raise ValueError("Invalid relay challenge")
    return DOMAIN + challenge + valid_name(name).encode("ascii")


async def register_client(socket, identity: "Identity", *, routing_status=False):
    challenge = json.loads(await asyncio.wait_for(socket.recv(), 5))
    if (
        not isinstance(challenge, dict)
        or set(challenge) != {"type", "challenge"}
        or challenge["type"] != "challenge"
    ):
        raise ValueError("Invalid relay challenge")
    proof = identity.sign_bytes(
        registration_payload(unb64(challenge["challenge"]), identity.name)
    )
    hello: dict[str, str | bool] = {
        "register": identity.name,
        "identity": b64(identity.public),
        "signature": b64(proof),
    }
    if routing_status:
        hello["routing_status"] = True
    await socket.send(json.dumps(hello))
    registered = json.loads(await asyncio.wait_for(socket.recv(), 5))
    if registered != {"type": "registered", "name": identity.name}:
        raise ValueError("Relay registration failed")
