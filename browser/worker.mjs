import { DurableObject } from 'cloudflare:workers';

const assets = /* ASSETS */ {};
const headers = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' wss:; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

export default {
  fetch(request, env) {
    const url = new URL(request.url);
    const relay = /^\/relay\/([a-f0-9]{32})\/(alice|bob)$/.exec(url.pathname);
    if (relay) {
      if (request.method !== 'GET' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket' ||
          request.headers.get('Origin') !== url.origin) return new Response('WebSocket required', { status: 403, headers });
      return env.ROOMS.get(env.ROOMS.idFromName(relay[1])).fetch(request);
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response(null, { status: 405, headers });
    }
    if (!Object.hasOwn(assets, url.pathname)) return new Response(null, { status: 404, headers });
    const [type, data] = assets[url.pathname];
    let body = data;
    if (type === 'application/wasm' && request.method !== 'HEAD') {
      const binary = atob(data);
      body = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index++) body[index] = binary.charCodeAt(index);
    }
    return new Response(request.method === 'HEAD' ? null : body, {
      headers: { ...headers, 'Content-Type': type, 'Cache-Control': 'no-cache' },
    });
  },
};

const routed = new Set(['offer', 'response', 'finish', 'ack', 'message', 'receipt']);
const other = role => role === 'alice' ? 'bob' : 'alice';

export class ChatRoom extends DurableObject {
  fetch(request) {
    const role = new URL(request.url).pathname.split('/').at(-1);
    const pair = new WebSocketPair();
    const client = pair[0], server = pair[1];
    if (this.ctx.getWebSockets(role).length) {
      this.ctx.acceptWebSocket(server);
      server.close(1008, 'This place in the room is already open');
      return new Response(null, { status: 101, webSocket: client });
    }
    this.ctx.acceptWebSocket(server, [role]);
    server.serializeAttachment({ role, count: 0, window: 0 });
    const peer = this.ctx.getWebSockets(other(role))[0];
    if (peer) {
      peer.send('{"relay":"ready"}');
      server.send('{"relay":"ready"}');
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(socket, data) {
    const attachment = socket.deserializeAttachment();
    const role = attachment?.role;
    if (!role || typeof data !== 'string' || data.length > 40_000) {
      socket.close(1008, 'Invalid routing envelope');
      return;
    }
    const now = Date.now();
    if (now - attachment.window > 1_000) {
      attachment.window = now;
      attachment.count = 0;
    }
    if (++attachment.count > 60) {
      socket.close(1008, 'Room message rate exceeded');
      return;
    }
    socket.serializeAttachment(attachment);
    let packet;
    try { packet = JSON.parse(data); } catch { socket.close(1008, 'Invalid JSON'); return; }
    const destination = other(role);
    if (!packet || !routed.has(packet.type) || packet.from !== role || packet.to !== destination) {
      socket.close(1008, 'Invalid routing envelope');
      return;
    }
    const peer = this.ctx.getWebSockets(destination)[0];
    if (peer?.readyState !== WebSocket.OPEN) {
      socket.send('{"relay":"offline"}');
      return;
    }
    try { peer.send(data); }
    catch { socket.send('{"relay":"offline"}'); return; }
    if (packet.type === 'message') socket.send(JSON.stringify({
      relay: 'forwarded', sid: packet.sid, counter: packet.counter,
    }));
  }

  webSocketClose(socket) {
    const role = socket.deserializeAttachment()?.role;
    if (!role || this.ctx.getWebSockets(role).some(candidate => candidate !== socket)) return;
    const peer = this.ctx.getWebSockets(other(role))[0];
    if (peer?.readyState === WebSocket.OPEN) peer.send('{"relay":"offline"}');
  }

  webSocketError(socket) {
    socket.close(1011, 'Relay connection interrupted');
  }
}
