import { test, expect } from '@playwright/test';
const key = 'synthetic-web-e2e-admin-key-only-123456789';
test('authenticated browser uses real persisted policy, TLS broker, grants, downloads, and logout', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to Keeper Agent' })).toBeVisible();
  await page.getByLabel('Administrator access key').fill(key);
  await page.getByRole('button', { name: 'Open workspace' }).click();
  await expect(page.getByRole('heading', { name: 'fixture-check', exact: true })).toBeVisible();
  await expect(page.getByText('DESIGN PREVIEW')).toHaveCount(0);
  await page.getByRole('button', { name: 'Run action', exact: true }).click();
  await page.getByRole('button', { name: 'Run now', exact: true }).click();
  await expect(page.locator('.result-output')).toContainText('"exit_code": 0', { timeout: 30000 });
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByRole('button', { name: 'New action', exact: true }).click();
  await page.getByLabel('Action name', { exact: true }).fill('web-created');
  await page.getByLabel('HTTPS endpoint').fill('https://example.invalid');
  await page.getByLabel('Keeper record UID').fill('synthetic-record');
  await page.getByRole('button', { name: 'Save action', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'web-created', exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: /web-created/ })).toBeVisible();
  await page.getByRole('button', { name: 'Agent access', exact: true }).click();
  await page.getByRole('button', { name: 'Add agent', exact: true }).click();
  await page.getByLabel('Agent name', { exact: true }).fill('web-agent');
  await page.getByRole('checkbox', { name: /web-created/ }).check();
  await page.getByRole('button', { name: 'Create agent access' }).click();
  const row = page.locator('.agent-row').filter({ hasText: 'web-agent' });
  const downloaded = page.waitForEvent('download');
  await row.getByRole('button', { name: 'Download client' }).click();
  const file = await downloaded;
  expect(file.suggestedFilename()).toBe('web-agent-client.json');
  const { readFile } = await import('node:fs/promises');
  const client = JSON.parse(await readFile((await file.path())!, 'utf8'));
  expect(client.token.length).toBeGreaterThan(32);
  expect(await page.locator('body').innerText()).not.toContain(client.token);
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(client.token);
  await row.getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke access' }).click();
  await expect(row).toHaveCount(0);
  await page.getByRole('button', { name: 'Activity', exact: true }).click();
  await expect(page.locator('.event-row')).toContainText('fixture-check');
  await page.getByRole('button', { name: 'Vault connection', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Disconnect Keeper' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByLabel('Administrator access key')).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Administrator access key')).toBeVisible();
});

test('web login and workspace fit a phone browser', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.getByLabel('Administrator access key').fill(key);
  await page.getByRole('button', { name: 'Open workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Approved actions' })).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBeTruthy();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Install browser' })).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBeTruthy();
  await page.screenshot({ path: '../docs/images/web-mobile.png' });
});

test('password, device approval, and MFA UI clear submitted credentials', async ({ page }) => {
  // Keeper challenge fixtures only; the admin session still uses the real web server.
  let stage = 'idle';
  const challenge = () => ({
    state: 'challenge',
    challenge: {
      id: stage,
      kind: stage,
      options: [{ id: 'submit', label: 'Submit verification', secret: true }],
    },
  });
  await page.route('**/admin/request', async (route) => {
    const payload = route.request().postDataJSON();
    let response;
    if (payload.operation === 'snapshot') {
      const real = await route.fetch();
      response = { ...(await real.json()), online: stage === 'connected' };
    } else if (payload.operation === 'connection_status')
      response = ['password', 'device', 'mfa'].includes(stage) ? challenge() : { state: stage };
    else if (payload.operation === 'connect') {
      stage = 'password';
      response = challenge();
    } else if (payload.operation === 'login_answer') {
      expect(payload.value).toBe('synthetic-input');
      stage = stage === 'password' ? 'device' : stage === 'device' ? 'mfa' : 'connected';
      response = stage === 'connected' ? { state: stage } : challenge();
    } else return route.continue();
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(response),
    });
  });
  await page.goto('/');
  await page.getByLabel('Administrator access key').fill(key);
  await page.getByRole('button', { name: 'Open workspace' }).click();
  await page.getByRole('button', { name: 'Vault connection', exact: true }).click();
  await page.getByRole('button', { name: 'Connect Keeper', exact: true }).click();
  await page.getByLabel('Master password', { exact: true }).fill('synthetic-input');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Approve this broker device' })).toBeVisible();
  await expect(page.getByLabel('Verification code', { exact: true })).toHaveValue('');
  await page.getByLabel('Verification code', { exact: true }).fill('synthetic-input');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Verify your identity' })).toBeVisible();
  await expect(page.getByLabel('Verification code', { exact: true })).toHaveValue('');
  await page.getByLabel('Verification code', { exact: true }).fill('synthetic-input');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Disconnect Keeper' })).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('synthetic-input');
  await page.unrouteAll({ behavior: 'wait' });
});
