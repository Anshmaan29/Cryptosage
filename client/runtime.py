"""Local Python client: identity keys, protocol state, plaintext and local UI."""
from __future__ import annotations
import asyncio
import json
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import psutil
from websockets.asyncio.client import connect
from crypto.primitives import available_algorithms, versions
from policy.engine import load_policy
from protocol.identity import Identity, b64, unb64, valid_name
from protocol.session import Peer, REKEY_AFTER


def now():
    return datetime.now(timezone.utc).isoformat()


class Client:
    def __init__(self, name: str, data_dir: Path, contacts_dir: Path, relay: str, policy_path=None):
        self.identity = Identity(data_dir, name)
        self.contacts_dir = Path(contacts_dir)
        self.peer = Peer(self.identity, load_policy(policy_path))
        self.relay_url = relay
        self.socket = None
        self.connected = False
        self.events = deque(maxlen=200)
        self.messages = deque(maxlen=500)
        self.benchmarks = None
        self.attack_results = []
        self.lock = asyncio.Lock()
        self.ready = asyncio.Event()
        self.task = None
        self.benchmark_busy = False
        self.process = psutil.Process()

    def event(self, kind: str, detail: str):
        self.events.append({'time':now(),'kind':kind,'detail':detail})

    def contacts(self) -> list[dict]:
        result = []
        if not self.contacts_dir.exists():
            return result
        for path in sorted(self.contacts_dir.glob('*.json')):
            data = json.loads(path.read_text())
            if data['name'] != self.identity.name:
                key = unb64(data['public'])
                from protocol.identity import fingerprint
                fp = fingerprint(key)
                result.append({'name':data['name'],'fingerprint':fp,
                               'verified':self.identity.trusted.get(data['name']) == fp,
                               'identity_changed':data['name'] in self.identity.trusted and self.identity.trusted[data['name']] != fp})
        return result

    def trust(self, name: str, expected: str):
        valid_name(name)
        path = self.contacts_dir / (name+'.json')
        if not path.exists():
            raise ValueError('Contact public key is not in the local directory')
        data = json.loads(path.read_text())
        if data['name'] != name:
            raise ValueError('Contact directory name mismatch')
        self.identity.pin(name, unb64(data['public']), expected)
        self.event('verified',f'{name}: fingerprint explicitly pinned locally')

    async def run(self):
        while True:
            try:
                async with connect(self.relay_url, max_size=262_144, open_timeout=5, proxy=None) as socket:
                    await socket.send(json.dumps({'register':self.identity.name}))
                    registered = json.loads(await asyncio.wait_for(socket.recv(),5))
                    if registered.get('type') != 'registered':
                        raise ValueError('Relay registration failed')
                    self.socket, self.connected = socket, True
                    self.event('connected','Connected to ciphertext relay')
                    async for raw in socket:
                        async with self.lock:
                            try:
                                packet = json.loads(raw)
                                if not isinstance(packet, dict):
                                    raise ValueError('Malformed packet envelope')
                                if packet.get('type') == 'relay_error':
                                    self.peer.pending = None
                                    self.ready.clear()
                                    self.event('offline', 'Peer is offline; start the peer client and try again')
                                    continue
                                if packet.get('type') == 'message':
                                    if not self.peer.session:
                                        raise ValueError('No authenticated session for this message')
                                    text = self.peer.session.open(packet)
                                    self.messages.append({'direction':'received','text':text,'time':now(),
                                                          'peer':self.peer.session.peer})
                                else:
                                    before = self.peer.session
                                    response = self.peer.receive(packet)
                                    if response:
                                        await socket.send(json.dumps(response))
                                    if self.peer.session and self.peer.session is not before:
                                        self.ready.set()
                                        self.event('session',f'Authenticated {self.peer.session.algorithm} session established with {self.peer.session.peer}')
                            except (ValueError, KeyError, TypeError, OverflowError) as exc:
                                self.event('rejected',str(exc))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.event('disconnected',f'Relay connection unavailable ({type(exc).__name__}); retrying')
            finally:
                self.connected = False
                self.socket = None
                self.peer.pending = None
                self.peer.session = None
                self.ready.clear()
            await asyncio.sleep(1)

    async def establish(self, remote: str, expected_session_id: str | None = None):
        valid_name(remote)
        if remote == self.identity.name:
            raise ValueError('Choose another local identity')
        async with self.lock:
            if not self.connected or not self.socket:
                raise ValueError('Relay is offline')
            if expected_session_id is not None and (not self.peer.session or self.peer.session.session_id != expected_session_id):
                raise ValueError('Session changed; review the conversation before sending')
            self.peer.expire()
            self.ready.clear()
            packet = self.peer.initiate(remote)
            await self.socket.send(json.dumps(packet))
            self.event('handshake',f'Opening an authenticated session with {remote}')
        return {'status':'negotiating', 'session_id':packet['sid']}

    async def send(self, text: str, expected_peer: str | None = None, expected_session_id: str | None = None):
        async with self.lock:
            session = self.peer.session
            if not self.connected or not self.socket or not session:
                raise ValueError('Open and authenticate a session first')
            if ((expected_peer is not None and session.peer != expected_peer)
                    or (expected_session_id is not None and session.session_id != expected_session_id)):
                raise ValueError('Session or recipient changed; review the conversation before sending')
            expected_peer, expected_session_id = session.peer, session.session_id
            needs_rekey = session.send_count >= REKEY_AFTER
        if needs_rekey:
            started = await self.establish(expected_peer, expected_session_id)
            try:
                await asyncio.wait_for(self.ready.wait(),10)
            except asyncio.TimeoutError as exc:
                raise ValueError('Periodic re-key did not complete; message was not sent') from exc
            expected_session_id = started['session_id']
            self.event('rekey','Periodic post-quantum re-key completed')
        async with self.lock:
            session = self.peer.session
            if not self.connected or not self.socket or not session:
                raise ValueError('Open and authenticate a session first')
            if session.peer != expected_peer or session.session_id != expected_session_id:
                raise ValueError('Session or recipient changed; review the conversation before sending')
            packet = session.seal(text)
            try:
                await self.socket.send(json.dumps(packet))
            except Exception:
                self.peer.session = None
                raise ValueError('Connection interrupted; reconnect before sending again')
            self.messages.append({'direction':'sent','text':text,'time':now(),'peer':session.peer})
        return {'status':'sent'}

    def state(self):
        if self.peer.expire():
            self.event('timeout','Handshake expired; reconnect to retry')
        return {'identity':{'name':self.identity.name,'fingerprint':self.identity.fingerprint},
                'contacts':self.contacts(),'connected':self.connected,
                'negotiating':self.peer.pending is not None,
                'session':self.peer.session.public() if self.peer.session else None,
                'messages':list(self.messages),'events':list(self.events),
                'metrics':{'rss_bytes':self.process.memory_info().rss,'cpu_percent':self.process.cpu_percent(),
                           'versions':versions()},'algorithms':available_algorithms(),
                'policy':self.peer.policy,'benchmark_busy':self.benchmark_busy}
