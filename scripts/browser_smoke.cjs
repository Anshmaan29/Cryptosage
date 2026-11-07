/* Run against scripts/run_demo.sh with Playwright installed; never uses mocked APIs. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const target = process.env.CRYTOSAGE_ALICE_URL || 'http://127.0.0.1:8001';
const peerTarget = process.env.CRYTOSAGE_BOB_URL || 'http://127.0.0.1:8002';
const output = path.resolve(__dirname, '../reports/screenshots');

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium' });
  const errors = [];
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const alice = await context.newPage();
  const bob = await context.newPage();
  for (const page of [alice, bob]) {
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
  }
  try {
    await Promise.all([alice.goto(target), bob.goto(peerTarget)]);
    await Promise.all([alice.waitForFunction(() => document.querySelector('#identity-name').textContent === 'Alice'), bob.waitForFunction(() => document.querySelector('#identity-name').textContent === 'Bob')]);
    await alice.screenshot({ path: path.join(output, 'desktop-before-session.png'), fullPage: true });
    await alice.getByRole('button', { name: 'Verify identity', exact: true }).click();
    await bob.getByRole('button', { name: 'Verify identity', exact: true }).click();
    const aliceFingerprint = await alice.locator('#self-fingerprint').textContent();
    const bobFingerprint = await bob.locator('#self-fingerprint').textContent();
    assert.match(aliceFingerprint, /^[a-f0-9]{64}$/i);
    assert.notEqual(aliceFingerprint, bobFingerprint);
    await alice.getByLabel('Fingerprint confirmed through your trusted channel').fill(bobFingerprint);
    await bob.getByLabel('Fingerprint confirmed through your trusted channel').fill(aliceFingerprint);
    await Promise.all([alice.getByRole('button', { name: 'Verify and trust contact' }).click(), bob.getByRole('button', { name: 'Verify and trust contact' }).click()]);
    await Promise.all([alice.waitForFunction(() => !document.querySelector('#verify-dialog').open), bob.waitForFunction(() => !document.querySelector('#verify-dialog').open)]);
    await alice.waitForFunction(() => document.querySelector('#start-button').textContent.includes('Establish secure session'));
    if (await alice.locator('#message-input').isDisabled()) { const reconnect = alice.locator('#reconnect-button'); await (await reconnect.isVisible() ? reconnect : alice.locator('#start-button')).click(); }
    await Promise.all([alice.waitForFunction(() => !document.querySelector('#message-input').disabled), bob.waitForFunction(() => !document.querySelector('#message-input').disabled)]);
    const firstMessage = `A verified channel, experiment ${Date.now()}.`;
    await alice.getByLabel('Message', { exact: true }).fill(firstMessage);
    await alice.getByRole('button', { name: 'Send encrypted message' }).click();
    await bob.getByText(firstMessage, { exact: true }).last().waitFor();
    const reply = `Received experiment ${Date.now()}.`;
    await bob.getByLabel('Message', { exact: true }).fill(reply);
    await bob.getByRole('button', { name: 'Send encrypted message' }).click();
    await alice.getByText(reply, { exact: true }).last().waitFor();
    assert.equal(await alice.locator('#messages .message').count() >= 2, true);
    await alice.locator('#dismiss-notice').click();
    await alice.screenshot({ path: path.join(output, 'desktop-conversation.png'), fullPage: true });
    const oldSessionId = await alice.evaluate(async () => (await (await fetch('/api/state')).json()).session.session_id);
    await alice.getByRole('button', { name: 'Renew session keys' }).click();
    await alice.waitForFunction(() => document.querySelector('#notice-text').textContent.includes('Session keys renewed'));
    const renewed = await alice.evaluate(async () => (await (await fetch('/api/state')).json()).session);
    assert.notEqual(renewed.session_id, oldSessionId);
    assert.equal(renewed.peer, 'Bob');
    await alice.getByRole('link', { name: 'Security lab', exact: true }).click();
    await alice.getByRole('link', { name: 'Attack lab', exact: true }).click();
    await alice.getByLabel('Attack scenario').selectOption('tamper');
    await alice.getByRole('button', { name: 'Run controlled attack' }).click();
    await alice.getByRole('heading', { name: 'Attack rejected.', exact: true }).waitFor();
    await alice.screenshot({ path: path.join(output, 'desktop-attack-lab.png'), fullPage: true });
    await alice.getByRole('link', { name: 'Session overview', exact: true }).click();
    await alice.screenshot({ path: path.join(output, 'desktop-security-lab.png'), fullPage: true });
    await alice.getByRole('link', { name: 'Benchmarks', exact: true }).click();
    await alice.getByRole('button', { name: 'Run benchmark', exact: true }).click();
    await alice.waitForFunction(() => document.querySelector('#benchmark-output').textContent.includes('measured'), null, { timeout: 120000 });
    await alice.screenshot({ path: path.join(output, 'desktop-benchmarks.png'), fullPage: true });
    await alice.getByRole('link', { name: 'Messages', exact: true }).click();
    await alice.setViewportSize({ width: 390, height: 844 });
    await alice.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    if (await alice.locator('#notice').isVisible()) await alice.locator('#dismiss-notice').click();
    await alice.screenshot({ path: path.join(output, 'mobile-conversation.png'), fullPage: false });
    assert.equal(await alice.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Mobile horizontal overflow');
    await alice.getByRole('button', { name: 'Verify identity', exact: true }).click();
    await alice.screenshot({ path: path.join(output, 'mobile-verification.png'), fullPage: false });
    await alice.keyboard.press('Escape');
    assert.equal(await alice.locator('#verify-dialog').evaluate((dialog) => dialog.open), false);
    assert.deepEqual(errors, [], 'Browser page/console errors');
    console.log('PASS: real identity verification, authenticated connection, bidirectional chat, re-key, ciphertext attack rejection, real benchmark display, desktop/mobile render, dialog keyboard dismissal, no JS errors.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
