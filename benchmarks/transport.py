"""Measured loopback WebSocket transport, separate from protocol computation."""
import asyncio
import json
import socket
import time
from websockets.asyncio.client import connect
from protocol.session import Peer
from server.relay import run


async def measure(identity_a, identity_b, policy):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0))
        port = probe.getsockname()[1]
    task = asyncio.create_task(run(port=port))
    try:
        for attempt in range(100):
            try:
                first = await connect(f'ws://127.0.0.1:{port}',proxy=None)
                break
            except OSError:
                await asyncio.sleep(.01)
        else:
            raise ValueError('Benchmark relay did not start')
        async with first, connect(f'ws://127.0.0.1:{port}',proxy=None) as second:
            for ws,name in ((first,identity_a.name),(second,identity_b.name)):
                await ws.send(json.dumps({'register':name}))
                assert json.loads(await ws.recv())['type']=='registered'
            a,b = Peer(identity_a,policy),Peer(identity_b,policy)
            start = time.perf_counter_ns()
            packet = a.initiate(identity_b.name)
            for sender,receiver,peer in ((first,second,b),(second,first,a),(first,second,b),(second,first,a)):
                await sender.send(json.dumps(packet))
                packet = peer.receive(json.loads(await receiver.recv()))
            handshake = (time.perf_counter_ns()-start)/1e6
            assert a.session and b.session
            packet = a.session.seal('Measured loopback message')
            start = time.perf_counter_ns()
            await first.send(json.dumps(packet))
            incoming = json.loads(await second.recv())
            assert b.session.open(incoming)=='Measured loopback message'
            reply = b.session.seal('Measured loopback reply')
            await second.send(json.dumps(reply))
            assert a.session.open(json.loads(await first.recv()))=='Measured loopback reply'
            message = (time.perf_counter_ns()-start)/1e6
            # Echo a fixed opaque envelope without any cryptographic computation.
            probe = {'type':'transport_probe','from':identity_a.name,'to':identity_b.name,'payload':'0'*4096}
            start = time.perf_counter_ns()
            await first.send(json.dumps(probe))
            echoed = json.loads(await second.recv())
            echoed.update({'from':identity_b.name,'to':identity_a.name})
            await second.send(json.dumps(echoed))
            assert json.loads(await first.recv())['payload']==probe['payload']
            rtt = (time.perf_counter_ns()-start)/1e6
            return {'network_handshake_ms':handshake,'network_message_roundtrip_ms':message,
                    'relay_transport_roundtrip_ms':rtt}
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
