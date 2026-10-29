import { test, expect } from '@playwright/test';

test('sign in and reach the dashboard', async ({ page }) => {
  await page.goto('https://app.example.com/login');
  await page.getByRole('textbox', { name: 'Email' }).fill('user@example.com');
  await page.locator('#password').fill('{{secret.PW}}');
  await page.getByText('Remember me').click();
  await page.locator('select#region').selectOption('eu');
  await page.getByRole('button', {
    name: 'Sign in',
  }).click();
  await page.locator('#password').press('Enter');
  await expect(page).toHaveURL('https://app.example.com/dashboard');
  await expect(page).toHaveURL(/dashboard\/?$/);
  await expect(page.locator('h1')).toContainText('Welcome');
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();
});
