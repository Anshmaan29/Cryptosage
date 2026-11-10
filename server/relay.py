"""Route opaque envelopes. Only registration verifies a public ML-DSA signature."""

import argparse
import asyncio
import json
import logging
import secrets

import uvicorn
from server.observer import Observer

from crypto.primitives import verify
from protocol.identity import b64, fingerprint, unb64, valid_name
from protocol.registration import registration_payload
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

log = logging.getLogger("relay")


async def verify_registration(socket) -> tuple[str, str, bool]:
    challenge = secrets.token_bytes(32)
    await socket.send(json.dumps({"type": "challenge", "challenge": b64(challenge)}))
    hello = json.loads(await asyncio.wait_for(socket.recv(), 5))
    required = {"register", "identity", "signature"}
    if (
        not isinstance(hello, dict)
        or not required <= set(hello) <= required | {"routing_status"}
        or type(hello.get("routing_status", False)) is not bool
    ):
        raise ValueError("Malformed registration")
    name = valid_name(hello["register"])
    public = unb64(hello["identity"])
    if not verify(
        public, registration_payload(challenge, name), unb64(hello["signature"])
    ):
        raise ValueError("Invalid registration signature")
    return name, fingerprint(public), hello.get("routing_status", False)


async def run(
    host: str = "127.0.0.1",
    port: int = 8765,
    attack: str | None = None,
    *,
    observe_port: int | None = None,
    observer: Observer | None = None,
):
    if observe_port is not None and observer is None:
        observer = Observer()
    clients = {}
    pins: dict[str, str] = {}
    attack_used = False

    async def route(socket):
        nonlocal attack_used
        name = None
        try:
            # Browser JavaScript is never a relay client.
            if socket.request.headers.get("Origin") is not None:
                await socket.close(1008, "Local Python clients only")
                return
            candidate, key, routing_status = await verify_registration(socket)
            if candidate in pins and pins[candidate] != key:
                log.warning("Registration key changed for routing name %s", candidate)
                await socket.close(1008, "Routing identity key changed")
                return
            if candidate in clients or (candidate not in pins and len(pins) >= 4096):
                await socket.close(
                    1008, "Duplicate routing name or registration capacity reached"
                )
                return
            name = candidate
            pins.setdefault(name, key)
            clients[name] = socket
            await socket.send(json.dumps({"type": "registered", "name": name}))

            async def status(kind, packet):
                if routing_status:
                    await socket.send(
                        json.dumps(
                            {
                                "type": kind,
                                "sid": packet.get("sid"),
                                "counter": packet.get("counter"),
                            }
                        )
                    )
                elif kind == "relay_error":
                    await socket.send(
                        json.dumps({"type": kind, "detail": "Peer is offline"})
                    )

            async for raw in socket:
                packet = json.loads(raw)
                if (
                    not isinstance(packet, dict)
                    or packet.get("from") != name
                    or not isinstance(packet.get("to"), str)
                ):
                    await socket.close(1008, "Invalid routing envelope")
                    return
                if observer is not None:
                    observer.record(packet, raw)
                destination = clients.get(packet["to"])
                if destination is None:
                    await status("relay_error", packet)
                    continue
                try:
                    if attack and not attack_used:
                        from attacks.mutations import mutate_packet

                        altered = mutate_packet(attack, packet)
                        if altered != packet or (
                            attack == "replay" and packet.get("type") == "message"
                        ):
                            attack_used = True
                            await destination.send(json.dumps(altered))
                            if attack == "replay":
                                await destination.send(json.dumps(altered))
                        else:
                            await destination.send(raw)
                    else:
                        await destination.send(raw)
                except ConnectionClosed:
                    await status("relay_error", packet)
                else:
                    if packet.get("type") == "message":
                        await status("relay_sent", packet)
        except (ConnectionClosed, asyncio.TimeoutError):
            pass
        except (ValueError, TypeError, KeyError):
            await socket.close(1008, "Malformed packet")
        finally:
            if name and clients.get(name) is socket:
                clients.pop(name, None)

    async with serve(
        route, host, port, max_size=262_144, max_queue=16, ping_interval=20
    ):
        log.info("Ciphertext relay listening on %s:%s", host, port)
        if observer is None or observe_port is None:
            await asyncio.Future()
        else:
            config = uvicorn.Config(
                observer.app(observe_port),
                host="127.0.0.1",
                port=observe_port,
                ws="none",
                access_log=False,
                proxy_headers=False,
            )
            await uvicorn.Server(config).serve()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "0.0.0.0"])
    p.add_argument("--port", default=8765, type=int)
    p.add_argument(
        "--lan", action="store_true", help="Allow the relay to listen on LAN interfaces"
    )
    p.add_argument(
        "--observe-port", type=int, help="Enable the read-only loopback relay view"
    )
    p.add_argument(
        "--attack", choices=["downgrade", "identity", "replay", "tamper", "invalid"]
    )
    args = p.parse_args(argv)
    if args.host == "0.0.0.0" and not args.lan:
        p.error("--host 0.0.0.0 requires --lan")
    if args.lan and args.attack:
        p.error("Existing relay laboratory mode is loopback-only")
    if not 1 <= args.port <= 65535:
        p.error("--port must be between 1 and 65535")
    if args.observe_port is not None and (
        not 1 <= args.observe_port <= 65535 or args.observe_port == args.port
    ):
        p.error("--observe-port must be a separate port between 1 and 65535")
    return args


def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.lan:
        log.warning(
            "LAN relay enabled. Treat the relay as untrusted. Routing metadata is visible on this network."
        )
    asyncio.run(run(args.host, args.port, args.attack, observe_port=args.observe_port))


if __name__ == "__main__":
    main()
