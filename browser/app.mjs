import { decode, derive, encode, getOqs, hash, KEMS, random } from './crypto.mjs';
import { Peer, roomId } from './protocol.mjs';
import { defaultPolicy, eligibleAlgorithms, validatePolicy } from './policy.mjs';

const $ = id => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
const invite = fragment.get('join');
const requested = fragment.get('kem');
const inviteVersion = fragment.get('v');
const legacyInvite = Boolean(invite && inviteVersion === null && requested);
if (location.hash) history.replaceState(null, '', location.pathname);
const role = invite ? 'bob' : 'alice';
let connection, peer, config, retryTimer, handshakeTimer;
let queue = Promise.resolve();
let sending = false;
const messages = [];
const pending = new Map();
const events = [];
const policyChecks = [...document.querySelectorAll('input[name="allowed-kem"]')];

function readPolicy() {
  return validatePolicy({
    allowed: policyChecks.filter(input => input.checked).map(input => input.value),
    minimumLevel: Number($('minimum-level').value),
    experimental: $('allow-experimental').checked,
    preferred: $('preferred-kem').value,
  });
}

function policySummary(policy) {
  const eligible = eligibleAlgorithms(policy);
  return 'Category ' + policy.minimumLevel + ' minimum · ' +
    (eligible.length ? eligible.join(', ') : 'No eligible key exchanges');
}

function previewPolicy() {
  const policy = readPolicy();
  $('policy-eligibility').textContent = policySummary(policy);
  $('policy-preview').textContent = legacyInvite
    ? 'This invite uses ' + requested + ' under the original room protocol.'
    : policySummary(policy);
}

function showDecision(decision) {
  $('policy-peers').hidden = !decision;
  $('policy-decision-reason').hidden = !decision;
  $('policy-candidates').replaceChildren();
  if (!decision) {
    $('policy-decision').textContent = legacyInvite
      ? 'This invite uses the original room protocol.'
      : 'Waiting for signed policies from both peers.';
    return;
  }
  $('policy-decision').textContent = decision.selected
    ? decision.selected + ' selected'
    : 'No mutually allowed key exchange';
  const eligible = decision.candidates.filter(candidate => !candidate.initiator && !candidate.responder);
  const winner = eligible.find(candidate => candidate.name === decision.selected);
  let explanation = 'Each candidate below shows which peer excluded it.';
  if (winner) {
    if (eligible.length === 1) explanation = 'This was the only key exchange both peers allowed.';
    else if (eligible.some(candidate => candidate !== winner && candidate.votes === winner.votes)) {
      explanation = 'Peer preferences tied, so the standard algorithm took priority.';
    } else {
      explanation = 'This key exchange received more explicit peer preferences.';
    }
  }
  $('policy-decision-reason').textContent = explanation;
  $('initiator-policy').textContent = policySummary(decision.initiator);
  $('responder-policy').textContent = policySummary(decision.responder);
  for (const candidate of decision.candidates) {
    const row = document.createElement('li');
    const name = document.createElement('strong');
    name.textContent = candidate.name;
    const reason = document.createElement('span');
    if (candidate.initiator || candidate.responder) {
      reason.textContent = [
        candidate.initiator && 'Room creator · ' + candidate.initiator,
        candidate.responder && 'Guest · ' + candidate.responder,
      ].filter(Boolean).join(' / ');
    } else {
      const preferences = candidate.votes === 1 ? '1 peer preference' : candidate.votes + ' peer preferences';
      reason.textContent = 'Allowed by both · ' + preferences;
      if (candidate.name === decision.selected) {
        name.dataset.selected = 'true';
        reason.textContent += ' · Selected';
      }
    }
    row.append(name, reason);
    $('policy-candidates').append(row);
  }
}

function restorePolicy() {
  let policy = defaultPolicy;
  try {
    const saved = localStorage.getItem('cryptosage-key-exchange-policy');
    if (saved) policy = validatePolicy(JSON.parse(saved));
  } catch {
    // Storage can be disabled or contain a policy from a different catalog.
  }
  for (const input of policyChecks) input.checked = policy.allowed.includes(input.value);
  $('minimum-level').value = String(policy.minimumLevel);
  $('allow-experimental').checked = policy.experimental;
  $('preferred-kem').value = policy.preferred;
  previewPolicy();
  showDecision();
}
restorePolicy();
$('policy-form').addEventListener('change', previewPolicy);
$('policy-form').addEventListener('submit', event => {
  event.preventDefault();
  enqueue(async () => {
    const policy = readPolicy();
    let saved = true;
    try { localStorage.setItem('cryptosage-key-exchange-policy', JSON.stringify(policy)); }
    catch { saved = false; }
    if (config?.policy) {
      config.policy = policy;
      $('policy-save-status').textContent = saved ? 'Policy saved. Starting a fresh handshake.' : 'Policy applied to this room.';
      await connect();
    } else {
      $('policy-save-status').textContent = saved
        ? 'Policy saved for new rooms and invites.'
        : 'Policy applies while this tab is open.';
    }
  });
});

function event(detail) {
  events.unshift({ time: new Date(), detail });
  if (events.length > 40) events.pop();
  const list = $('lab-events');
  list.replaceChildren();
  for (const entry of events) {
    const row = document.createElement('li');
    const time = document.createElement('time');
    time.dateTime = entry.time.toISOString();
    time.textContent = entry.time.toLocaleTimeString();
    row.append(time, document.createTextNode(' · ' + entry.detail));
    list.append(row);
  }
}
function counts() {
  const session = peer?.session;
  $('lab-counts').textContent = session ? `${session.sendCount} sent · ${session.receiveCount} received` : 'No active session';
}


function notify(detail) {
  $('notice').textContent = detail;
  $('notice').hidden = !detail;
}

function status(detail, ready = false) {
  $('state').textContent = ready ? 'Authenticated' : detail;
  $('state').dataset.ready = String(ready);
  $('lab-state').textContent = ready ? 'Authenticated' : detail;
  $('lab-kem').textContent = ready ? peer.session.algorithm : 'Pending';
  $('lab-session-id').textContent = ready ? peer.session.sid : 'Pending';
  if (!ready) $('lab-fingerprint').textContent = 'Pending';
  counts();
  $('session-description').textContent = detail;
  $('message').disabled = !ready;
  $('send').disabled = !ready || sending;
  $('message').placeholder = ready ? 'Write a message' : 'Wait for the authenticated session';
  if (ready) $('invite').hidden = true;
}

function update(message, label) {
  message.status = label;
  message.caption.textContent = label;
  message.retry.hidden = label !== 'Delivery unconfirmed' || !peer?.session;
}

function display(message, direction) {
  const row = document.createElement('li');
  row.className = 'message ' + direction;
  const content = document.createElement('p');
  content.textContent = message.text;
  const label = document.createElement('small');
  label.textContent = direction === 'sent' ? 'Pending' : 'Received';
  row.append(content, label);
  if (direction === 'sent') {
    message.caption = label;
    message.retry = document.createElement('button');
    message.retry.type = 'button';
    message.retry.textContent = 'Retry delivery';
    message.retry.hidden = true;
    message.retry.addEventListener('click', () => enqueue(() => send(message)));
    row.append(message.retry);
    messages.push(message);
  }
  $('messages').append(row);
  if ($('messages').children.length > 250) $('messages').firstElementChild.remove();
  $('messages').scrollTop = $('messages').scrollHeight;
}

function enqueue(action) {
  queue = queue.then(action).catch(error => notify(error.message || 'This operation did not complete'));
  return queue;
}

function reset(detail) {
  event(detail);
  peer?.reset();
  clearTimeout(handshakeTimer);
  for (const item of pending.values()) {
    clearTimeout(item.timer);
    update(item.message, 'Delivery unconfirmed');
  }
  pending.clear();
  for (const message of messages) message.retry.hidden = true;
  $('reconnect').hidden = false;
  status(detail);
}

function wire(packet) {
  if (!connection || connection.readyState !== WebSocket.OPEN) throw new Error('The relay is disconnected');
  connection.send(JSON.stringify(packet));
}

function watchHandshake() {
  clearTimeout(handshakeTimer);
  handshakeTimer = setTimeout(() => enqueue(async () => {
    reset('Handshake timed out');
    notify('Select Reconnect to try a fresh handshake.');
  }), 15_000);
}

async function incoming(raw) {
  const packet = JSON.parse(raw);
  if (packet?.relay === 'ready') {
    if (role === 'alice' && !peer.pending && !peer.session) {
      event('Starting signed key negotiation');
      status('Authenticating your guest');
      watchHandshake();
      wire(await peer.offer());
    }
    return;
  }
  if (packet?.relay === 'offline') {
    reset('Peer disconnected. Waiting for them to return');
    return;
  }
  if (packet?.relay === 'forwarded') {
    const entry = pending.get(packet.sid + '/' + packet.counter);
    if (entry) update(entry.message, 'Sent to relay');
    return;
  }
  const outcome = await peer.receive(packet);
  if (outcome.refused) {
    if (outcome.reply) wire(outcome.reply);
    showDecision(outcome.decision);
    reset('No mutually allowed key exchange');
    notify('Open Policy manager to inspect the refusal. Save a revised policy to try again.');
    return;
  }
  if (outcome.message) { display(outcome.message, 'received'); event('Authenticated message received'); counts(); }
  if (outcome.reply) wire(outcome.reply);
  if (packet.type === 'offer') watchHandshake();
  if (outcome.ready) {
    clearTimeout(handshakeTimer);
    $('reconnect').hidden = false;
    const algorithm = peer.session.algorithm;
    const fingerprint = await hash(decode(peer.roomState.pin, 1952));
    $('lab-fingerprint').textContent = Array.from(fingerprint, byte => byte.toString(16).padStart(2, '0')).join('');
    showDecision(outcome.decision);
    event('Authenticated session confirmed with ' + algorithm);
    status(algorithm + ' · ML-DSA-65 · AES-256-GCM', true);
    for (const message of messages) {
      if (message.status === 'Delivery unconfirmed') update(message, message.status);
    }
    notify('');
  }
  if (outcome.receipt) {
    const receipt = outcome.receipt;
    const key = receipt.sid + '/' + receipt.counter;
    const entry = pending.get(key);
    if (!entry || receipt.hash !== entry.hash) throw new Error('Receipt does not match a pending message');
    clearTimeout(entry.timer);
    pending.delete(key);
    update(entry.message, 'Delivered');
    event('Authenticated delivery receipt received');
  }
}

async function connect() {
  clearTimeout(retryTimer);
  const previous = connection;
  connection = null;
  reset('Connecting to the relay');
  showDecision();
  notify('');
  if (previous?.readyState < WebSocket.CLOSED) {
    await new Promise(resolve => {
      const timer = setTimeout(resolve, 800);
      previous.addEventListener('close', () => { clearTimeout(timer); resolve(); }, { once: true });
      previous.close();
    });
  }
  peer = new Peer(config);
  const endpoint = new URL('/relay/' + config.room + '/' + role, location.origin);
  endpoint.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = connection = new WebSocket(endpoint);
  ws.addEventListener('open', () => {
    if (ws === connection) status('Connected to relay. Waiting for your peer');
  });
  ws.addEventListener('message', event => enqueue(async () => {
    if (ws === connection) await incoming(event.data);
  }));
  ws.addEventListener('close', event => enqueue(async () => {
    if (ws !== connection) return;
    if (event.code === 1008) {
      reset('This role is already open or the room was closed');
      return;
    }
    reset('Relay connection interrupted. Reconnecting');
    retryTimer = setTimeout(() => enqueue(async () => connect()), 1_000);
  }));
}

async function send(existing) {
  sending = true;
  $('send').disabled = true;
  try {
    const session = peer.active();
    if (existing?.attempt === session.sid) throw new Error('Use Reconnect before retrying this message');
    const message = existing || { id: encode(random(16)), text: $('message').value.trim() };
    if (!message.text) return;
    const { packet, hash } = await peer.seal(message);
    counts();
    message.attempt = session.sid;
    if (!existing) display(message, 'sent');
    update(message, 'Pending');
    try {
      wire(packet);
      event('Encrypted message sent to relay');
    } catch (error) {
      update(message, 'Delivery unconfirmed');
      reset('Send interrupted');
      throw error;
    }
    if (!existing) $('message').value = '';
    const key = packet.sid + '/' + packet.counter;
    const timer = setTimeout(() => enqueue(async () => {
      if (!pending.has(key)) return;
      reset('Delivery unconfirmed. Reconnect to retry');
    }), 15_000);
    pending.set(key, { message, hash, timer });
  } finally {
    sending = false;
    $('send').disabled = !peer?.session;
  }
}

$('start').addEventListener('click', () => {
  $('start').disabled = true;
  enqueue(async () => {
    try {
      if (invite && inviteVersion !== '2' && !(legacyInvite && Object.hasOwn(KEMS, requested))) {
        throw new Error('This invitation uses an unsupported protocol or key exchange');
      }
      if (legacyInvite && !eligibleAlgorithms(readPolicy()).includes(requested)) {
        throw new Error('Allow ' + requested + ' in Policy manager before joining this invite');
      }
      const secret = invite ? decode(invite.replaceAll('-', '+').replaceAll('_', '/') + '=', 32) : random(32);
      const room = await roomId(secret);
      const inviteKey = await derive(secret, 'invite authentication');
      const oqs = await getOqs();
      config = { oqs, identity: oqs.identity(), inviteKey, role, room, roomState: { offers: new Set(), seen: new Map() } };
      if (legacyInvite) config.algorithm = requested;
      else config.policy = readPolicy();
      if (role === 'alice') {
        const link = new URL(location.origin);
        const share = encode(secret).replace(/=$/, '').replaceAll('+', '-').replaceAll('/', '_');
        link.hash = new URLSearchParams({ join: share, v: '2' });
        $('invite-link').value = link.href;
        $('invite').hidden = false;
      }
      secret.fill(0);
      $('lobby').hidden = $('notes').hidden = true;
      $('chat').hidden = false;
      if (!legacyInvite) $('apply-policy').textContent = 'Save policy and reconnect';
      await connect();
    } finally {
      $('start').disabled = false;
    }
  });
});
$('copy').addEventListener('click', () => enqueue(async () => {
  try {
    await navigator.clipboard.writeText($('invite-link').value);
    $('copy').textContent = 'Invite copied';
  } catch {
    $('invite-link').focus();
    $('invite-link').select();
    notify('Copy the selected invite link and share it privately.');
  }
}));
$('reconnect').addEventListener('click', () => enqueue(async () => connect()));
$('compose').addEventListener('submit', event => {
  event.preventDefault();
  if (!sending) enqueue(() => send());
});
$('message').addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    $('compose').requestSubmit();
  }
});
if (invite) {
  $('hero-title').textContent = 'Join a private chat';
  $('intro').textContent = legacyInvite
    ? 'This invite uses a fixed key exchange. Join only if you trust the sender.'
    : 'Check your policy and join only if you trust the sender.';
  $('start').textContent = 'Join private chat';
  $('notes').hidden = true;
}
