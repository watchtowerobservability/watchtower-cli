import { test, expect } from '@playwright/test';

test('uses a call we do not translate', async ({ page }) => {
  await page.goto('https://app.example.com/');
  await page.locator('#menu').click();
  await page.waitForTimeout(500);
  await page.locator('#x').click();
});
