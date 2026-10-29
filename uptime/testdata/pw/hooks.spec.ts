import { test, expect } from '@playwright/test';

export const base = 'https://example.com';

test.use({
  baseURL: 'https://example.com',
});

test.beforeEach(async ({ page }) => {
  await page.goto('https://example.com/');
});

test('hooks', async ({ page }) => {
  test.skip();
  await page.locator('#a').click();
});
