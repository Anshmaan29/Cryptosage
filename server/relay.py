"""Untrusted routing only. This module deliberately has no cryptographic imports."""
import argparse
import asyncio
import json
import logging
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

log = logging.getLogger('relay')


async def run(host: str = '127.0.0.1', port: int = 8765, attack: str | None = None):
    clients = {}
    attack_used = False

    async def route(socket):
        nonlocal attack_used
        name = None
        try:
            # Browser JavaScript is never a relay client.
            if socket.request.headers.get('Origin') is not None:
                await socket.close(1008, 'Local Python clients only')
                return
            hello = json.loads(await asyncio.wait_for(socket.recv(), timeout=5))
            if not isinstance(hello, dict):
                await socket.close(1008, 'Malformed registration')
                return
            candidate = hello.get('register')
            if (set(hello) != {'register'} or not isinstance(candidate, str)
                    or not candidate.isascii() or not candidate.replace('_','').replace('-','').isalnum()
                    or not 1 <= len(candidate) <= 32 or candidate in clients):
                await socket.close(1008, 'Invalid or duplicate routing name')
                return
            name = candidate
            clients[name] = socket
            await socket.send(json.dumps({'type':'registered','name':name}))
            async for raw in socket:
                packet = json.loads(raw)
                if not isinstance(packet, dict) or packet.get('from') != name or not isinstance(packet.get('to'), str):
                    await socket.close(1008, 'Invalid routing envelope')
                    return
                destination = clients.get(packet['to'])
                if destination is None:
                    await socket.send(json.dumps({'type':'relay_error','detail':'Peer is offline'}))
                    continue
                if attack and not attack_used:
                    from attacks.mutations import mutate_packet
                    altered = mutate_packet(attack, packet)
                    if altered != packet or (attack == 'replay' and packet.get('type') == 'message'):
                        attack_used = True
                        await destination.send(json.dumps(altered))
                        if attack == 'replay':
                            await destination.send(json.dumps(altered))
                        continue
                await destination.send(raw)
        except (ConnectionClosed, asyncio.TimeoutError):
            pass
        except (ValueError, TypeError, KeyError):
            await socket.close(1008, 'Malformed packet')
        finally:
            if name and clients.get(name) is socket:
                clients.pop(name, None)

    async with serve(route, host, port, max_size=262_144, max_queue=16, ping_interval=20):
        log.info('Ciphertext relay listening on %s:%s', host, port)
        await asyncio.Future()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', default='127.0.0.1', choices=['127.0.0.1'])
    p.add_argument('--port', default=8765, type=int)
    p.add_argument('--attack', choices=['downgrade','identity','replay','tamper','invalid'])
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    asyncio.run(run(args.host, args.port, args.attack))


if __name__ == '__main__':
    main()
