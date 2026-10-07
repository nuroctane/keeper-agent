import { test, expect } from '@playwright/test';

test('real onboarding is empty until explicitly configured', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Your secrets can stay secret.')).toBeVisible();
  await expect(page.getByText('Broker offline', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Set up your vault' }).click();
  await expect(page.getByLabel('Keeper email')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create workspace' })).toBeDisabled();
});

test('search, detail selection, and explicit run results', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/?demo=1');
  await expect(page.getByRole('heading', { name: 'Approved actions' })).toBeVisible();
  await page.getByLabel('Search actions').fill('cloudflare');
  await expect(page.getByRole('button', { name: /cloudflare-zones List/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /repository-status Check/ })).toHaveCount(0);
  await page.getByRole('button', { name: /cloudflare-zones List/ }).click();
  await page.getByRole('button', { name: 'Run action', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByText('Broker response', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Run now', exact: true }).click();
  await expect(page.getByText('Broker response', { exact: true })).toBeVisible();
  await expect(page.locator('.result-output')).toContainText('No service was contacted');
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  expect(errors).toEqual([]);
});

test('create an action, grant scoped access, then revoke', async ({ page }) => {
  await page.goto('/?demo=1');
  await page.getByRole('button', { name: 'New action' }).click();
  await page.getByLabel('Action name', { exact: true }).fill('fixture-api');
  await page.getByLabel('Description', { exact: true }).fill('Synthetic API request');
  await page.getByLabel('HTTPS endpoint').fill('https://example.invalid/test');
  await page.getByLabel('Keeper record UID').fill('SYNTHETIC_RECORD');
  await page.getByRole('button', { name: 'Save action', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'fixture-api', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Agent access', exact: true }).click();
  await page.getByRole('button', { name: 'Add agent', exact: true }).click();
  await page.getByLabel('Agent name', { exact: true }).fill('fixture-agent');
  await page.getByRole('checkbox', { name: /fixture-api/ }).check();
  await page.getByRole('button', { name: 'Create agent access' }).click();
  const row = page.locator('.agent-row').filter({ hasText: 'fixture-agent' });
  await expect(row).toContainText('1 approved action');
  await row.getByRole('button', { name: 'Revoke', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke access', exact: true }).click();
  await expect(row).toHaveCount(0);
});

test('keyboard dialog dismissal, theme, and minimum window width', async ({ page }) => {
  await page.setViewportSize({ width: 900, height: 620 });
  await page.goto('/?demo=1');
  await expect(page.getByRole('button', { name: 'Run action', exact: true })).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
  ).toBeTruthy();
  await page.getByRole('button', { name: 'New action' }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByLabel('Appearance').selectOption('light');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('document the desktop preview', async ({ page }) => {
  await page.goto('/?demo=1');
  await expect(page.getByRole('heading', { name: 'github-profile', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Settings', exact: true })).toBeInViewport();
  await page.screenshot({ path: '../docs/images/desktop-preview.png' });
  await page.getByRole('button', { name: 'New action' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.screenshot({ path: '../docs/images/action-editor.png' });
});
