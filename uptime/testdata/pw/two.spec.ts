import { test, expect } from '@playwright/test';

test('home loads', async ({ page }) => {
  await page.goto('https://example.com/');
  await expect(page.locator('h1')).toContainText('Example');
});

test('docs load', async ({ page }) => {
  await page.goto('https://example.com/docs');
  await expect(page).toHaveURL('https://example.com/docs');
});
