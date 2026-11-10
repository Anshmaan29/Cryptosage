const assert = require('node:assert/strict');
const fs = require('node:fs');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const target = process.argv[2];
const output = process.argv[3];
if (!target) throw new Error('Pass the browser prototype URL');

async function exercise(browser, algorithm) {
  const host = await browser.newContext({ viewport: { width: 1440, height: 850 }, reducedMotion: 'no-preference' });
  const guest = await browser.newContext({ isMobile: true, hasTouch: true, viewport: { width: 390, height: 844 } });
  try {
    const a = await host.newPage(), b = await guest.newPage();
    const errors = [], frames = [];
    for (const page of [a, b]) {
      page.on('pageerror', error => errors.push(error.message));
      page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
      page.on('websocket', socket => socket.on('framesent', ({ payload }) => frames.push(String(payload))));
    }
    const response = await a.goto(target);
    assert.equal(response.status(), 200);
    assert.match(response.headers()['content-security-policy'], /wasm-unsafe-eval/);
    if (output && algorithm === 'ML-KEM-768') {
      await a.screenshot({ path: output + '/hosted-lobby.png' });
      if (await a.evaluate(() => CSS.supports('animation-timeline: view()'))) {
        const flight = a.locator('.flight-a');
        const before = await flight.evaluate(el => getComputedStyle(el).transform);
        await a.evaluate(() => window.scrollTo(0, 340));
        await a.waitForFunction(initial => getComputedStyle(document.querySelector('.flight-a')).transform !== initial, before);
        await a.emulateMedia({ reducedMotion: 'reduce' });
        assert.equal(await flight.evaluate(el => getComputedStyle(el).animationName), 'none');
      }
    }
    if (algorithm === 'ML-KEM-768') {
      await a.getByRole('button', { name: 'Security lab' }).click();
      for (const scenario of ['tamper', 'replay', 'negotiation']) {
        await a.locator('#lab-attack').selectOption(scenario);
        await a.getByRole('button', { name: 'Run isolated experiment' }).click();
        await a.waitForFunction(() => document.querySelector('#attack-result').textContent.startsWith('Blocked:'));
      }
      await a.getByRole('button', { name: 'Run benchmark' }).click();
      await a.locator('#benchmark-result table').waitFor();
      assert.match(await a.locator('#benchmark-result').innerText(), /HQC-3/);
      await a.getByRole('button', { name: 'Messages', exact: true }).click();
    }
    await a.getByLabel('Key exchange').selectOption(algorithm);
    await a.getByRole('button', { name: 'Create private chat' }).click();
    await a.locator('#invite-link').waitFor({ timeout: 30_000 });
    const invite = await a.locator('#invite-link').inputValue();
    assert.match(new URL(invite).hash, /^#join=[A-Za-z0-9_-]{43}&kem=/);
    await b.goto(invite);
    await b.getByRole('button', { name: /Join/ }).click();
    const waitForSession = () => Promise.all([a, b].map(page => page.locator('#state[data-ready="true"]').waitFor({ timeout: 30_000 })));
    await waitForSession();
    for (const [from, to, marker] of [[a, b, 'First encrypted browser check 🔐'], [b, a, 'Second encrypted browser check']]) {
      await from.getByRole('textbox', { name: 'Message', exact: true }).fill(marker);
      await from.getByRole('button', { name: 'Send', exact: true }).click();
      await to.getByText(marker, { exact: true }).last().waitFor();
      await from.getByText('Delivered', { exact: true }).last().waitFor();
      assert.ok(frames.every(frame => !frame.includes(marker)));
    }
    const oldOffer = frames.map(frame => JSON.parse(frame)).find(packet => packet.type === 'offer');
    assert.equal(oldOffer.algorithm, algorithm);
    await a.getByRole('button', { name: 'Reconnect' }).click();
    await a.waitForFunction(() => document.querySelector('#state').dataset.ready === 'false');
    await waitForSession();
    const offers = frames.map(frame => JSON.parse(frame)).filter(packet => packet.type === 'offer');
    assert.notEqual(offers.at(-1).sid, oldOffer.sid);
    assert.ok(await b.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    if (output && algorithm === 'ML-KEM-768') await b.screenshot({ path: output + '/hosted-chat-mobile.png', fullPage: true });
    console.log(algorithm + ': separate browser contexts, authenticated handshake, bidirectional delivery, fresh reconnect and ciphertext-only frames');
  } finally {
    await Promise.all([host.close(), guest.close()]);
  }
}

(async () => {
  if (output) fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH });
  try {
    await exercise(browser, 'ML-KEM-768');
    await exercise(browser, 'HQC-3');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
