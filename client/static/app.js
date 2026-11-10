'use strict';

const $ = (id) => document.getElementById(id);
let state = null;
let selectedPeer = null;
let messageSignature = '';
let contactSignature = '';
let eventSignature = '';
let pending = new Set();
let refreshing = false;
let requestedSession = null;
const messageEncoder = new TextEncoder();
const messageLimit = 16384;
let attackCatalog = [];

function messageSize() { return messageEncoder.encode($('message-input').value.trim()).length; }

function describeAttack() {
  const selected = attackCatalog.find(row => row.id === $('attack-scenario').value);
  setText('attack-explanation', selected ? [selected.objective, selected.mutation].filter(Boolean).join(' ') : '');
  $('attack-button').disabled = !selected;
}

function warnPolicyLevel() {
  const algorithms = state?.algorithms;
  $('policy-level-warning').hidden = !algorithms || algorithms.some(
    algorithm => algorithm.security_level >= Number($('policy-level').value)
  );
}

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = String(text);
  return el;
}
function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}
function setText(id, value) { $(id).textContent = value ?? '—'; }
function peer() { return (state?.contacts || []).find((c) => c.name === selectedPeer); }
function hasSession() { return !!state?.session && state.session.peer === selectedPeer && !peer()?.identity_changed; }
function notify(message, success = false) {
  setText('notice-text', message);
  $('notice').classList.toggle('success', success);
  $('notice').hidden = false;
}
function humanLabel(value) { return String(value).replaceAll('_', ' ').replaceAll('-', ' '); }
function formatNumber(value, digits = 2) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: digits }) : String(value ?? 'Not measured');
}
function formatTime(value) {
  if (!value) return '';
  const date = typeof value === 'number' ? new Date(value > 1e12 ? value : value * 1000) : new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
async function request(path, body) {
  const options = { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    if (!state?.csrf_token) throw new Error('The local client has not initialized. Wait for connection and try again.');
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.headers['X-CSRF-Token'] = state.csrf_token;
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { throw new Error(`The local client returned an unreadable response (${response.status}).`); }
  if (!response.ok) {
    const detail = data.detail ?? data.error ?? data.message;
    const error = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail || `Request failed (${response.status})`));
    error.decision = data.decision;
    throw error;
  }
  return data;
}
async function action(key, button, callback) {
  if (pending.has(key)) return;
  pending.add(key);
  const original = button?.textContent;
  if (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); }
  try { await callback(); await refresh(); }
  catch (error) { notify(error.message || 'The operation could not complete. Try again.'); if (error.decision && typeof renderSelection === 'function') renderSelection(error.decision); }
  finally {
    pending.delete(key);
    if (button) { button.disabled = false; button.removeAttribute('aria-busy'); if (original && !button.childElementCount) button.textContent = original; }
    if (state) renderStatus();
  }
}

function renderContacts() {
  const contacts = state.contacts || [];
  if (!contacts.some((c) => c.name === selectedPeer)) selectedPeer = contacts[0]?.name || null;
  const signature = JSON.stringify([contacts, selectedPeer]);
  if (signature === contactSignature) return;
  contactSignature = signature;
  setText('contact-count', contacts.length);
  const list = $('contact-list');
  list.replaceChildren();
  if (!contacts.length) { list.append(node('p', 'loading-label', 'No contacts are available. Start the other local client.')); return; }
  for (const contact of contacts) {
    const button = node('button', 'contact-button' + (contact.name === selectedPeer ? ' selected' : ''));
    button.type = 'button';
    button.setAttribute('aria-pressed', String(contact.name === selectedPeer));
    button.append(node('span', 'contact-avatar', contact.name.slice(0, 1).toUpperCase()));
    const text = node('span', 'contact-text');
    text.append(node('strong', '', contact.name), node('span', '', contact.identity_changed ? 'Identity changed: do not connect' : contact.verified ? 'Identity verified' : 'Verify identity to begin'));
    button.append(text, icon(contact.verified ? 'shield' : 'message'));
    button.addEventListener('click', () => { selectedPeer = contact.name; messageSignature = ''; render(); });
    list.append(button);
  }
}
function renderStatus() {
  const contact = peer();
  const online = $('connection-warning').hidden && !!state.connected;
  const session = online && hasSession() ? state.session : null;
  const trusted = !!contact?.verified;
  setText('identity-name', state.identity?.name || 'Local identity');
  setText('identity-avatar', (state.identity?.name || '?').slice(0, 1).toUpperCase());
  setText('peer-name', contact?.name || 'Your next conversation');
  setText('peer-avatar', (contact?.name || '?').slice(0, 1).toUpperCase());
  setText('peer-status', contact?.identity_changed ? 'Identity changed: connection blocked' : session ? 'Authenticated encrypted session' : trusted ? 'Identity verified, ready to connect' : 'Identity not yet verified');
  $('verify-button').disabled = !contact || pending.has('trust');
  setText('session-banner-text', session ? `End-to-end encrypted with ${session.algorithm}. Identity verified locally.` : trusted ? 'Identity verified. Establish a session to exchange encrypted messages.' : 'Verify your contact before establishing an encrypted session.');
  setText('session-state-label', session ? 'Secure session established' : 'Not connected');
  setText('session-state-description', session ? 'Authenticated negotiation completed. Only the local clients hold the message keys.' : 'An authenticated connection starts with a verified contact.');
  setText('detail-algorithm', session?.algorithm || 'Not established');
  setText('detail-trust', trusted ? 'Verified fingerprint' : 'Not verified');
  setText('detail-relay', online ? 'Connected' : 'Disconnected');
  setText('detail-handshake', session?.handshake_ms != null ? `${formatNumber(session.handshake_ms)} ms` : 'Not measured');
  $('reconnect-button').disabled = !contact || !online || !!state.negotiating || pending.has('connect');
  $('reconnect-button').hidden = !!session && !state.negotiating;
  setText('reconnect-button', state.negotiating ? 'Negotiating…' : trusted ? 'Establish secure session' : 'Verify contact');
  $('rekey-button').disabled = !session || !online || !!requestedSession || !!state.negotiating || pending.has('rekey');
  $('start-button').disabled = !contact || !online || !!requestedSession || !!state.negotiating || pending.has('connect');
  $('start-button').firstChild.textContent = trusted ? 'Establish secure session' : 'Verify contact to begin';
  $('message-input').disabled = !session || !online || !!state.negotiating || pending.has('message');
  const size = messageSize();
  setText('message-bytes', `${size.toLocaleString()} / 16,384 bytes${size > messageLimit ? ' (over limit)' : ''}`);
  $('send-button').disabled = !session || !online || !!state.negotiating || pending.has('message') || !size || size > messageLimit;
  warnPolicyLevel();
  $('message-input').placeholder = session ? `Message ${contact?.name || 'your contact'}…` : 'Establish a session to write a message…';
  setText('composer-status', state.negotiating ? 'Waiting for authenticated peer confirmation' : session ? 'Encrypted locally; delivered means peer authenticated receipt' : online ? 'Reconnect securely before sending' : 'Relay offline; history remains on this client');
  setText('lab-session-status', session ? 'Authenticated session active' : 'No session established');
  setText('lab-algorithm', session?.algorithm || 'Not established');
  setText('lab-security-level', session?.security_level ? `NIST level ${session.security_level}` : '—');
  setText('lab-handshake', session?.handshake_ms != null ? `${formatNumber(session.handshake_ms)} ms` : 'Not measured');
  setText('selection-reason', session?.reason || 'The policy engine will explain its decision after authenticated negotiation.');
}
function renderMessages() {
  const messages = (state.messages || []).filter((m) => !m.peer || m.peer === selectedPeer);
  const signature = JSON.stringify(messages);
  const established = hasSession();
  $('conversation-empty').hidden = !!messages.length;
  $('messages').hidden = !messages.length;
  if (!messages.length && established) {
    $('conversation-empty').querySelector('h3').textContent = 'A private channel. An open conversation.';
    $('conversation-empty').querySelector('p').textContent = 'Your authenticated session is ready. Send the first encrypted message below.';
    $('start-button').hidden = true;
  } else if (!messages.length) {
    $('conversation-empty').querySelector('h3').textContent = 'Just between the two of you.';
    $('conversation-empty').querySelector('p').textContent = 'Start with a verified identity. Your local clients handle the encryption.';
    $('start-button').hidden = false;
  }
  if (signature === messageSignature) return;
  messageSignature = signature;
  const scroll = $('message-scroll');
  const nearEnd = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 150;
  const list = $('messages');
  if (list.dataset.peer !== selectedPeer) { list.replaceChildren(); list.dataset.peer = selectedPeer || ''; }
  const existing = new Map([...list.children].map((el) => [el.dataset.messageId, el]));
  const retained = new Set();
  let received = 0;
  for (const [index, message] of messages.entries()) {
    const id = `${message.direction}:${message.id || `${message.time}-${index}`}`;
    retained.add(id);
    const sent = message.direction === 'sent';
    let item = existing.get(id);
    if (!item) {
      item = node('li', 'message ' + (sent ? 'sent' : 'received'));
      item.dataset.messageId = id;
      item.append(node('div', 'message-content', message.text));
      item.append(node('div', 'message-meta'));
      list.append(item);
      if (!sent) received++;
    }
    const meta = item.querySelector('.message-meta');
    const statusSignature = JSON.stringify([message.status, message.error, message.retry_available, message.retry_ready]);
    if (meta.dataset.signature !== statusSignature) {
      meta.dataset.signature = statusSignature;
      meta.replaceChildren();
      const timestamp = node('time', '', `${sent ? 'You' : selectedPeer || 'Contact'}, ${formatTime(message.time || message.timestamp)}`);
      if (message.time) { timestamp.dateTime = message.time; timestamp.title = new Date(message.time).toLocaleString(); }
      meta.append(timestamp);
      if (sent) {
        const labels = {pending:'Pending',sent:'Sent to relay',delivered:'Delivered',unconfirmed:'Delivery unconfirmed',failed:'Failed'};
        const status = node('span', 'delivery-status status-' + (message.status || 'unknown'), labels[message.status] || 'Delivery unconfirmed');
        status.title = message.status === 'delivered' ? 'The peer authenticated and recorded this message. This is not a read receipt.' : message.error || '';
        meta.append(status);
        if (message.retry_available) {
          const retry = node('button', 'retry-button', 'Retry delivery');
          retry.type = 'button';
          retry.disabled = !message.retry_ready;
          retry.title = message.retry_ready ? 'Encrypt this message again in the fresh session.' : 'Establish a fresh session with this contact to retry.';
          retry.addEventListener('click', () => action('retry-' + id, retry, () => request('/api/message/' + encodeURIComponent(message.id) + '/retry', {})));
          meta.append(retry);
        }
      }
    }
  }
  for (const [id, item] of existing) if (!retained.has(id)) item.remove();
  if (received && existing.size) setText('message-announcement', `${received} new message${received === 1 ? '' : 's'} from ${selectedPeer}.`);
  if (nearEnd || messages.at(-1)?.direction === 'sent') requestAnimationFrame(() => { scroll.scrollTop = scroll.scrollHeight; });
}
function renderEvents() {
  const events = (state.events || []).slice(-80).reverse();
  const signature = JSON.stringify(events);
  if (signature === eventSignature) return;
  eventSignature = signature;
  const list = $('events-list');
  list.replaceChildren();
  if (!events.length) { list.append(node('li', 'empty-table', 'No events recorded yet.')); return; }
  for (const event of events) {
    const row = node('li', 'event-row');
    row.append(node('time', '', formatTime(event.time || event.timestamp)), node('span', 'event-kind', humanLabel(event.kind || event.type || 'Event')), node('span', 'event-detail', typeof event.detail === 'object' ? JSON.stringify(event.detail) : event.detail || event.message || ''));
    list.append(row);
  }
}
function renderMetrics() {
  const body = $('metrics-body');
  const measurements = { ...(state.metrics || {}) };
  if (state.session) for (const key of ['encryption_us', 'decryption_us', 'send_count', 'receive_count']) if (state.session[key] != null) measurements[key] = state.session[key];
  const algorithm = (state.algorithms || []).find((item) => item.name === state.session?.algorithm);
  if (algorithm) for (const key of ['public_key_bytes', 'ciphertext_bytes']) measurements[key] = algorithm[key];
  const rows = Object.entries(measurements).filter(([, v]) => v != null);
  body.replaceChildren();
  if (!rows.length) { const row = node('tr'); const cell = node('td', 'empty-table', 'Measurements appear after a session runs.'); cell.colSpan = 2; row.append(cell); body.append(row); return; }
  for (const [key, value] of rows) {
    const row = node('tr');
    row.append(node('td', '', humanLabel(key)), node('td', '', typeof value === 'object' ? JSON.stringify(value) : formatNumber(value, 3)));
    body.append(row);
  }
}
function render() {
  if (requestedSession) {
    if (state.session?.session_id === requestedSession.id && state.session.peer === requestedSession.peer) {
      notify(requestedSession.operation === 'rekey' ? 'Session keys renewed through authenticated negotiation.' : 'Authenticated session established.', true);
      requestedSession = null;
    } else if ((!state.negotiating && Date.now() - requestedSession.started > 1500) || Date.now() - requestedSession.started > 20000) {
      notify('The authenticated handshake did not complete. Check the security event history, then retry.');
      requestedSession = null;
    }
  }
  renderContacts(); renderStatus(); renderMessages(); renderEvents(); renderMetrics();
  if (typeof renderV2 === 'function') renderV2();
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    state = await request('/api/state');
    $('connection-warning').hidden = true;
    render();
  } catch {
    $('connection-warning').hidden = false;
    $('message-input').disabled = true;
    $('send-button').disabled = true;
    $('start-button').disabled = true;
    $('reconnect-button').disabled = true;
    setText('detail-relay', 'Local client unavailable');
  } finally { refreshing = false; }
}
function route() {
  const route = location.hash.slice(1);
  const sections = ['overview','selection','policy','protocol','attacks','benchmarks','research','demo'];
  const lab = sections.includes(route);
  $('messages-view').hidden = lab;
  $('lab-view').hidden = !lab;
  document.querySelectorAll('[data-view]').forEach((link) => { const active = lab ? link.dataset.view === 'overview' : link.dataset.view === 'messages'; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
  for (const name of sections) $(name + '-section').hidden = route !== name;
  document.querySelectorAll('[data-lab]').forEach((link) => { const active = link.dataset.lab === route; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
  document.body.classList.toggle('lab-active', lab);
  if (typeof loadV2Route === 'function') loadV2Route(route);
  if (route === 'benchmarks') request('/api/benchmarks').then(renderBenchmarks).catch((error) => notify(error.message));
}
function openVerification() {
  const contact = peer();
  if (!contact) return;
  setText('verify-self-name', state.identity?.name);
  setText('self-fingerprint', state.identity?.fingerprint);
  setText('verify-peer-name', contact.name);
  setText('peer-fingerprint', contact.fingerprint || 'Fingerprint unavailable. Start the peer client.');
  setText('self-safety', state.identity?.safety_number || (state.identity?.fingerprint || '').match(/.{1,4}/g)?.join(' '));
  setText('peer-safety', contact.safety_number || (contact.fingerprint || '').match(/.{1,4}/g)?.join(' '));
  $('identity-change-warning').hidden = !contact.identity_changed;
  setText('previous-fingerprint', contact.pinned_fingerprint || contact.previous_fingerprint || 'Previous pin unavailable');
  $('replace-identity').checked = false;
  $('trusted-fingerprint').value = '';
  $('verify-error').hidden = true;
  $('verify-dialog').showModal();
}
function renderAttack(result) {
  const output = $('attack-result');
  output.replaceChildren(icon('shield'));
  const status = result.status || (result.blocked === true ? 'blocked' : result.blocked === false ? 'accepted' : 'inconclusive');
  output.dataset.status = status;
  const titles = {blocked:'Attack rejected.',accepted:'Attack was not rejected.',inconclusive:'Result inconclusive.',infrastructure_error:'Experiment could not run.'};
  output.append(node('h3', '', titles[status] || 'Result inconclusive.'));
  output.append(node('p', '', result.reason || result.detail || 'No protocol outcome was recorded.'));
  const details = node('dl', 'attack-facts');
  for (const [label,value] of [['Scope',result.scope],['Objective',result.objective],['Mutation',result.mutation],['Validation under test',result.validation],['Observed response',result.protocol_response],['Execution time',result.elapsed_ms != null ? formatNumber(result.elapsed_ms,2)+' ms' : null]]) {
    if (value) { details.append(node('dt','',label),node('dd','',typeof value === 'object' ? JSON.stringify(value) : value)); }
  }
  output.append(details);
  if (Array.isArray(result.timeline)) {
    const timeline = node('ol','attack-timeline');
    for (const event of result.timeline) timeline.append(node('li','',typeof event === 'string' ? event : event.detail || event.phase || event.event || JSON.stringify(event)));
    output.append(timeline);
  }
  const raw = node('details'); raw.append(node('summary','','Inspect sanitized experiment record'),node('pre','json-output',JSON.stringify(result,null,2)));output.append(raw);
  if (typeof rememberAttack === 'function') rememberAttack(result);
}
function renderReport(report) {
  const output = $('test-report');
  output.replaceChildren();
  const tests = report.tests || report.results;
  if (!Array.isArray(tests)) { output.append(node('pre', 'json-output', JSON.stringify(report, null, 2))); return; }
  const table = node('table', 'data-table');
  const head = node('thead'); const hr = node('tr');
  for (const title of ['Test', 'Expected', 'Observed', 'Outcome']) { const th = node('th', '', title); th.scope = 'col'; hr.append(th); }
  head.append(hr); table.append(head);
  const body = node('tbody');
  for (const test of tests) {
    const row = node('tr');
    for (const value of [test.name || test.test || test.nodeid, test.expected || 'See test assertion', test.observed || test.detail || 'See runner output', test.status || test.outcome || 'Unknown']) row.append(node('td', '', value));
    body.append(row);
  }
  table.append(body); output.append(table);
}
function renderBenchmarks(data) {
  if (!data || !Object.keys(data).length || data.status === 'not_run') return;
  const output = $('benchmark-output');
  output.replaceChildren();
  const config = data.metadata?.configuration;
  if (config?.network_enabled) {
    const profile = config.network_profile || 'custom';
    const delay = config.injected_send_delay_ms || 0;
    const bandwidth = config.simulated_bandwidth_bps;
    output.append(node('p', 'benchmark-meta', delay || bandwidth
      ? `${humanLabel(profile)} · ${delay} ms added per send${bandwidth ? ` · ${bandwidth / 1000} kb/s modeled payload rate` : ''}. Loopback with injected delay.`
      : 'Localhost · Loopback WebSockets with no injected delay.'));
  }
  if (typeof rememberBenchmark === 'function') rememberBenchmark(data);
  const results = Array.isArray(data) ? data : data.algorithms || data.results || data.benchmarks;
  if (!Array.isArray(results) && (typeof results !== 'object' || !results)) { output.append(node('pre', 'json-output', JSON.stringify(data, null, 2))); return; }
  const entries = Array.isArray(results) ? results.map((r) => [r.algorithm || r.name || 'Algorithm', r]) : Object.entries(results);
  const wrap = node('div', 'benchmark-table-wrap');
  const table = node('table', 'data-table'); const head = node('thead'); const hr = node('tr');
  for (const title of ['Algorithm', 'Status', 'Keygen mean', 'Encapsulation mean', 'Decapsulation mean', 'Public key', 'Ciphertext']) { const th = node('th', '', title); th.scope = 'col'; hr.append(th); }
  head.append(hr); table.append(head); const body = node('tbody');
  const chartValues = [];
  const ms = (entry, key) => {
    const aliases = { keygen: 'keygen_ms', encapsulation: 'encapsulate_ms', decapsulation: 'decapsulate_ms' };
    const source = entry.statistics?.[aliases[key]] || entry[key] || entry[key + '_ms'] || entry[key + '_ns'];
    const value = typeof source === 'object' ? source?.mean ?? source?.mean_ms ?? source?.mean_ns : source;
    if (typeof value !== 'number') return null;
    return entry[key + '_ns'] || source?.mean_ns != null ? value / 1e6 : value;
  };
  for (const [name, entry] of entries) {
    const row = node('tr');
    const unavailable = entry.available === false || entry.status === 'unavailable' || entry.error;
    const values = ['keygen', 'encapsulation', 'decapsulation'].map((key) => ms(entry, key));
    const fields = [name, unavailable ? entry.reason || entry.error || 'Unavailable' : entry.status || 'Measured', ...values.map((v) => v == null ? 'Not measured' : formatNumber(v, 4) + ' ms'), entry.public_key_size || entry.public_key_bytes, entry.ciphertext_size || entry.ciphertext_bytes];
    for (const [i, value] of fields.entries()) row.append(node('td', '', i > 4 && value != null ? `${formatNumber(value, 0)} B` : value ?? 'Not measured'));
    body.append(row);
    if (values[1] != null && !unavailable) chartValues.push({ name, value: values[1] });
  }
  table.append(body); wrap.append(table); output.append(wrap);
  if (chartValues.length) {
    const chart = node('div', 'benchmark-chart'); chart.append(node('h3', '', 'Mean encapsulation latency'));
    const max = Math.max(...chartValues.map((r) => r.value), 0.00001);
    for (const result of chartValues) {
      const row = node('div', 'chart-row'); row.append(node('span', '', result.name));
      const track = node('div', 'chart-track'); const bar = node('div', 'chart-bar'); bar.style.width = (result.value / max * 100) + '%'; track.append(bar);
      row.append(track, node('span', 'chart-value', `${formatNumber(result.value, 4)} ms`)); chart.append(row);
    }
    output.append(chart);
  }
  for (const [metric, title, unit] of [
    ['handshake_ms','Handshake computation','ms'], ['network_handshake_ms','Loopback handshake','ms'],
    ['cpu_usage_percent','Process CPU utilization','%'], ['peak_rss_bytes','Sampled process memory','bytes'],
    ['handshake_bytes','Handshake bandwidth','bytes'], ['encrypt_ms','Message encryption','ms'],
    ['decrypt_ms','Message decryption','ms'], ['rekey_ms','Fresh session re-key','ms']
  ]) {
    const rows = entries.map(([name, entry]) => ({name, value:entry.statistics?.[metric]?.mean})).filter(row => typeof row.value === 'number' && Number.isFinite(row.value));
    if (!rows.length) continue;
    const chart = node('div','benchmark-chart'); chart.append(node('h3','',title));
    const maximum = Math.max(...rows.map(row => row.value), 0.00001);
    for (const row of rows) { const line = node('div','chart-row'); line.append(node('span','',row.name)); const track = node('div','chart-track'); const bar = node('div','chart-bar'); bar.style.width = (row.value / maximum * 100) + '%'; track.append(bar); line.append(track,node('span','chart-value',`${formatNumber(row.value, 3)} ${unit}`)); chart.append(line); }
    output.append(chart);
  }
  const distributions = node('div', 'benchmark-table-wrap');
  const statsTable = node('table', 'data-table');
  const statsHead = node('thead'); const statsHeaders = node('tr');
  for (const label of ['Algorithm', 'Handshake stage', 'Samples', 'Mean', 'Median', 'Std. dev.', 'P95']) {
    const th = node('th', '', label); th.scope = 'col'; statsHeaders.append(th);
  }
  statsHead.append(statsHeaders); statsTable.append(statsHead);
  const statsBody = node('tbody');
  for (const [name, entry] of entries) {
    for (const [key, label] of [['handshake_ms', 'Protocol'], ['network_handshake_ms', 'WebSocket'], ['network_rekey_ms', 'WebSocket re-key']]) {
      const stats = entry.statistics?.[key];
      if (!stats) continue;
      const row = node('tr');
      for (const value of [name, label, stats.n, ...['mean', 'median', 'stdev', 'p95'].map(metric => `${formatNumber(stats[metric], 3)} ms`)]) row.append(node('td', '', value));
      statsBody.append(row);
    }
  }
  if (statsBody.children.length) {
    statsTable.append(statsBody); distributions.append(statsTable);
    output.append(node('h3', '', 'Handshake latency distribution'), distributions);
  }
  const meta = node('div', 'benchmark-meta');
  for (const [key, value] of Object.entries(data.environment || data.metadata || {})) meta.append(node('span', '', `${humanLabel(key)}: ${typeof value === 'object' ? JSON.stringify(value) : value}`));
  output.append(meta);
  const details = node('details'); details.append(node('summary', 'button button-quiet', 'Inspect complete benchmark data'), node('pre', 'json-output', JSON.stringify(data, null, 2))); output.append(details);
}

$('verify-button').addEventListener('click', openVerification);
$('start-button').addEventListener('click', () => {
  if (!peer()?.verified) { openVerification(); return; }
  const intendedPeer = selectedPeer;
  action('connect', $('start-button'), async () => { const result = await request('/api/connect', { peer: intendedPeer });
    requestedSession = { id: result.session_id, peer: intendedPeer, operation: 'connect', started: Date.now() };
    notify('Authenticated handshake requested. Waiting for peer confirmation.', true); });
});
$('close-verify').addEventListener('click', () => $('verify-dialog').close());
$('verify-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  await action('trust', $('trust-submit'), async () => {
    try {
      const contact = peer();
      const replacement = !!contact?.identity_changed;
      if (replacement && !$('replace-identity').checked) throw new Error('Explicitly confirm that you independently verified the replacement identity.');
      await request('/api/trust', { peer: selectedPeer, fingerprint: $('trusted-fingerprint').value.trim(), ...(replacement ? {replace:true,previous_fingerprint:contact.pinned_fingerprint || contact.previous_fingerprint} : {}) });
      $('verify-dialog').close(); notify('Contact fingerprint verified. You can now establish a session.', true);
    } catch (error) { setText('verify-error', error.message); $('verify-error').hidden = false; throw error; }
  });
});
$('copy-fingerprint').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(state.identity.fingerprint); notify('Your identity fingerprint was copied.', true); }
  catch { notify('Clipboard is unavailable. Select and copy the fingerprint above.'); }
});
$('message-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const text = $('message-input').value.trim();
  if (!text || !hasSession() || messageSize() > messageLimit) return;
  const binding = { peer: selectedPeer, session_id: state.session.session_id };
  action('message', $('send-button'), async () => { await request('/api/message', { text, ...binding }); $('message-input').value = ''; $('message-input').style.height = ''; }).then(() => { if (!$('message-input').disabled) $('message-input').focus(); });
});
$('message-input').addEventListener('input', () => { $('message-input').style.height = 'auto'; $('message-input').style.height = Math.min($('message-input').scrollHeight, 140) + 'px'; if (state) renderStatus(); });
$('message-input').addEventListener('keydown', (event) => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); $('message-form').requestSubmit(); } });
$('rekey-button').addEventListener('click', () => {
  const intendedPeer = state?.session?.peer;
  return action('rekey', $('rekey-button'), async () => {
    const result = await request('/api/rekey', {});
    requestedSession = { id: result.session_id, peer: intendedPeer, operation: 'rekey', started: Date.now() };
    notify('Fresh key negotiation requested. Waiting for peer confirmation.', true);
  });
});
$('attack-scenario').addEventListener('change', describeAttack);
$('attack-form').addEventListener('submit', (event) => { event.preventDefault(); action('attack', $('attack-button'), async () => renderAttack(await request('/api/attack', { scenario: $('attack-scenario').value }))); });

$('report-button').addEventListener('click', () => action('report', $('report-button'), async () => renderReport(await request('/api/report'))));
$('dismiss-notice').addEventListener('click', () => { $('notice').hidden = true; });
$('reconnect-button').addEventListener('click', () => $('start-button').click());
$('theme-toggle').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  localStorage.setItem('crytosage-theme', dark ? 'dark' : 'light');
  $('theme-toggle').setAttribute('aria-pressed', String(dark));
});
document.documentElement.dataset.theme = localStorage.getItem('crytosage-theme') || 'light';
$('details-toggle').addEventListener('click', () => { const panel = $('session-details'); panel.hidden = !panel.hidden; $('details-toggle').setAttribute('aria-expanded', String(!panel.hidden)); });
$('contacts-toggle').addEventListener('click', () => { const panel = $('contacts-panel'); panel.classList.toggle('mobile-open'); $('contacts-toggle').setAttribute('aria-expanded', String(panel.classList.contains('mobile-open'))); });
$('benchmark-trials').addEventListener('change', () => { $('custom-trials-wrap').hidden = $('benchmark-trials').value !== 'custom'; });
$('benchmark-button').addEventListener('click', () => action('benchmark', $('benchmark-button'), async () => {
  const trials = Number($('benchmark-trials').value === 'custom' ? $('benchmark-custom').value : $('benchmark-trials').value);
  $('benchmark-progress').hidden = false;
  setText('benchmark-progress', 'Measuring real operations; please wait…');
  try { renderBenchmarks(await request('/api/benchmark', {trials, profile:$('benchmark-profile').value})); setText('benchmark-progress', 'Measurements completed.'); }
  catch (error) { setText('benchmark-progress', 'Benchmark did not complete.'); throw error; }
}));
let loadedPolicy = null;
async function loadPolicy() {
  const data = await request('/api/policy'); loadedPolicy = data.policy;
  $('policy-level').value = loadedPolicy.minimum_security_level;
  warnPolicyLevel();
  $('policy-performance').value = loadedPolicy.performance_preference;
  $('policy-rekey').value = loadedPolicy.rekey_interval || 100;
  $('policy-experimental').checked = loadedPolicy.allow_experimental;
  $('policy-json').textContent = JSON.stringify(loadedPolicy, null, 2);
  $('policy-algorithms').replaceChildren();
  for (const [name, rule] of Object.entries(loadedPolicy.algorithms)) {
    const label = node('label', '', name + ' '); const select = node('select'); select.dataset.algorithm = name;
    for (const value of ['recommended','experimental','prohibited']) { const option = node('option', '', value); option.value = value; select.append(option); }
    select.value = rule.status; label.append(select); $('policy-algorithms').append(label);
  }
  setText('policy-status','Changes apply to new sessions.');
}
$('policy-level').addEventListener('change', warnPolicyLevel);
$('policy-form').addEventListener('submit', (event) => { event.preventDefault(); action('policy', $('policy-save'), async () => {
  const policy = structuredClone(loadedPolicy); policy.minimum_security_level = Number($('policy-level').value);
  policy.performance_preference = $('policy-performance').value; policy.rekey_interval = Number($('policy-rekey').value);
  policy.allow_experimental = $('policy-experimental').checked;
  document.querySelectorAll('[data-algorithm]').forEach((select) => { policy.algorithms[select.dataset.algorithm].status = select.value; });
  await request('/api/policy', {policy, confirm_restrictions:$('policy-confirm').checked}); await loadPolicy(); notify('Policy saved for future sessions.', true);
}); });
$('policy-reset').addEventListener('click', () => { if (!confirm('Restore defaults for future sessions? This may relax your current policy.')) return; action('policy-reset', $('policy-reset'), async () => { await request('/api/policy/reset', {confirm_restrictions:true}); await loadPolicy(); }); });
$('protocol-refresh').addEventListener('click', refresh);
function renderV2() {
  const decision = state.session?.decision || state.selection_decision;
  const decisionOutput = $('selection-output'); decisionOutput.replaceChildren();
  if (decision) {
    const steps = node('ol');
    for (const step of decision.steps || []) { const item = node('li'); item.append(node('strong', '', humanLabel(step.stage) + ': '), node('span', '', step.detail)); steps.append(item); }
    decisionOutput.append(steps);
    for (const candidate of decision.candidates || []) { const section = node('section'); section.append(node('h3', '', `${candidate.name} · ${candidate.eligible ? 'Eligible' : 'Excluded'}`)); const checks = node('ul'); for (const check of candidate.checks || []) checks.append(node('li', '', `${check.passed ? 'Pass' : 'Not met'}: ${check.detail}`)); section.append(checks); decisionOutput.append(section); }
  } else decisionOutput.append(node('p', 'empty-table', 'Run a handshake to inspect the actual policy decision.'));
  const list = $('protocol-events'); list.replaceChildren();
  for (const event of (state.events || []).slice().reverse()) list.append(node('li', '', `${formatTime(event.time)} · ${humanLabel(event.kind)} · ${event.detail}`));
  if (!list.children.length) list.append(node('li', 'empty-table', 'No events recorded yet.'));
  const details = $('encryption-overview'); details.replaceChildren();
  if (state.session) details.append(node('p', '', `Session ${state.session.session_id.slice(0,12)} · ML-DSA-65 · re-key after ${state.session.rekey_interval} messages`));
  if (location.hash === '#demo') renderDemo();
}
function renderDemo() {
  if (!state) return;
  const other = location.port === '8001' ? '8002' : location.port === '8002' ? '8001' : null;
  $('demo-open-peer').hidden = !other;
  if (other) $('demo-open-peer').href = `${location.protocol}//${location.hostname}:${other}/`;
  const items = [
    ['Verify contact fingerprint', '#messages', peer()?.verified ? 'This client has pinned the contact' : 'Verification required'],
    ['Establish an authenticated session', '#messages', hasSession() ? 'Session established' : 'No active session'],
    ['Inspect the negotiated selection', '#selection', state.session?.decision ? 'Decision recorded' : 'Establish a session'],
    ['Exchange encrypted messages', '#messages', state.messages?.length ? 'Local history is available' : 'No messages yet'],
    ['Inspect actual protocol events', '#protocol', state.events?.length ? 'Events recorded by this client' : 'No events recorded'],
    ['Run a downgrade experiment', '#attacks', (state.attack_results || []).some(r => r.scenario === 'downgrade') ? 'Experiment recorded in this process' : 'Not yet run'],
    ['Compare measured performance', '#benchmarks', state.benchmark_completed ? 'Measurements available' : 'Not yet run in this process'],
    ['Renew session keys', '#messages', 'Use the session details control'],
    ['Export recorded reports', '#benchmarks', 'Download the available reports']
  ];
  const list = $('demo-steps'); list.replaceChildren();
  for (const [label, href, status] of items) { const li = node('li'); const link = node('a', '', label); link.href = href; li.append(link, node('span', 'muted', ` — ${status}`)); list.append(li); }
}
async function loadV2Route(routeName) {
  if (routeName === 'policy') { try { await loadPolicy(); } catch (error) { notify(error.message); } }
  if (routeName === 'attacks') {
    try {
      attackCatalog = await request('/api/attacks');
      const select = $('attack-scenario');
      const previous = select.value;
      select.replaceChildren();
      for (const row of attackCatalog) {
        const option = node('option', '', row.name);
        option.value = row.id;
        select.append(option);
      }
      select.disabled = !attackCatalog.length;
      if (attackCatalog.some(row => row.id === previous)) select.value = previous;
      describeAttack();
    } catch (error) { notify(error.message); }
  }
  if (routeName === 'demo') renderDemo();
}
window.addEventListener('hashchange', route);
setText('client-endpoint', location.origin);
route();
refresh();
setInterval(refresh, 1500);
