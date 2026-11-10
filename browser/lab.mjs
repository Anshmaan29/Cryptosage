import { derive, encode, getOqs, random } from './crypto.mjs';
import { Peer, roomId } from './protocol.mjs';

const $ = id => document.getElementById(id);
const views = ['lobby', 'notes', 'chat'];
let priorVisibility = [];

$('show-lab').addEventListener('click', () => {
  priorVisibility = views.map(id => $(id).hidden);
  for (const id of views) $(id).hidden = true;
  $('lab').hidden = false;
  $('show-lab').setAttribute('aria-pressed', 'true');
  $('show-messages').setAttribute('aria-pressed', 'false');
});
$('show-messages').addEventListener('click', () => {
  if ($('lab').hidden) return;
  views.forEach((id, index) => { $(id).hidden = priorVisibility[index]; });
  $('lab').hidden = true;
  $('show-lab').setAttribute('aria-pressed', 'false');
  $('show-messages').setAttribute('aria-pressed', 'true');
});

async function pair() {
  const oqs = await getOqs();
  const secret = random(32);
  const room = await roomId(secret);
  const inviteKey = await derive(secret, 'invite authentication');
  secret.fill(0);
  const make = role => new Peer({
    oqs, role, room, inviteKey, algorithm: 'ML-KEM-768',
    identity: oqs.identity(), roomState: { offers: new Set(), seen: new Map() },
  });
  return [make('alice'), make('bob')];
}

async function handshake(alice, bob) {
  const offer = await alice.offer();
  const response = await bob.receive(offer);
  const finish = await alice.receive(response.reply);
  const ack = await bob.receive(finish.reply);
  await alice.receive(ack.reply);
}

$('run-attack').addEventListener('click', async () => {
  const button = $('run-attack'), output = $('attack-result');
  button.disabled = true;
  output.textContent = 'Running real isolated protocol operations…';
  let alice, bob;
  try {
    [alice, bob] = await pair();
    const scenario = $('lab-attack').value;
    let attempt, expected;
    if (scenario === 'negotiation') {
      const offer = await alice.offer();
      attempt = () => bob.receive({ ...offer, algorithm: 'HQC-3' });
      expected = /different KEM/;
    } else {
      await handshake(alice, bob);
      const { packet } = await alice.seal({ id: encode(random(16)), text: 'Isolated lab message' });
      if (scenario === 'replay') {
        await bob.receive(packet);
        attempt = () => bob.receive(packet);
        expected = /Replayed/;
      } else {
        const ciphertext = (packet.ciphertext[0] === 'A' ? 'B' : 'A') + packet.ciphertext.slice(1);
        attempt = () => bob.receive({ ...packet, ciphertext });
      }
    }
    try {
      await attempt();
      output.textContent = 'Experiment failed: the altered packet was accepted.';
    } catch (error) {
      const matched = expected ? expected.test(error.message) : error.name === 'OperationError';
      output.textContent = matched
        ? 'Blocked: ' + (error.message || 'AES-GCM authentication rejected the altered ciphertext.')
        : 'Inconclusive: ' + (error.message || error.name);
    }
  } catch (error) {
    output.textContent = 'Experiment could not complete: ' + error.message;
  } finally {
    alice?.reset(); bob?.reset();
    alice?.identity.secret.fill(0); bob?.identity.secret.fill(0);
    button.disabled = false;
  }
});

$('run-benchmark').addEventListener('click', async () => {
  const button = $('run-benchmark'), output = $('benchmark-result');
  button.disabled = true;
  output.textContent = 'Measuring real operations on this device…';
  try {
    const oqs = await getOqs();
    const rows = [];
    for (const name of ['ML-KEM-768', 'HQC-3']) {
      const times = [[], [], []];
      for (let i = 0; i < 10; i++) {
        let start = performance.now();
        const keys = oqs.keypair(name);
        times[0].push(performance.now() - start);
        start = performance.now();
        const sealed = oqs.encapsulate(name, keys.public);
        times[1].push(performance.now() - start);
        start = performance.now();
        const recovered = oqs.decapsulate(name, keys.secret, sealed.ciphertext);
        times[2].push(performance.now() - start);
        if (encode(recovered) !== encode(sealed.secret)) throw new Error('Shared secrets differ');
        keys.secret.fill(0); sealed.secret.fill(0); recovered.fill(0);
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      rows.push({ name, values: times.map(samples => {
        samples.sort((a, b) => a - b);
        return (samples[4] + samples[5]) / 2;
      }) });
    }
    const table = document.createElement('table');
    const head = document.createElement('tr');
    for (const label of ['KEM', 'Keygen', 'Encaps.', 'Decaps.']) {
      const cell = document.createElement('th'); cell.scope = 'col'; cell.textContent = label; head.append(cell);
    }
    table.append(head);
    for (const row of rows) {
      const tr = document.createElement('tr');
      for (const value of [row.name, ...row.values.map(x => x.toFixed(2))]) {
        const td = document.createElement('td'); td.textContent = value; tr.append(td);
      }
      table.append(tr);
    }
    output.replaceChildren(document.createTextNode('Median milliseconds, 10 trials per KEM. HQC-3 is experimental.'), table);
  } catch (error) {
    output.textContent = 'Benchmark could not complete: ' + error.message;
  } finally {
    button.disabled = false;
  }
});
