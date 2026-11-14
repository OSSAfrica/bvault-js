import { expect, test } from '@playwright/test';

test('example saves, reloads, reads, and destroys a JSON object', async ({
  page,
}) => {
  await page.goto('/examples/browser/');
  await expect(
    page.getByRole('button', { name: 'Encrypt & save' }),
  ).toBeDisabled();
  await page.getByRole('button', { name: 'Initialize vault' }).click();
  await expect(page.locator('#state')).toHaveText('Initialized');
  await page.getByRole('button', { name: 'Encrypt & save' }).click();
  await expect(page.getByRole('status')).toContainText('Encrypted and saved');
  const ciphertext = await page.locator('#ciphertext').textContent();
  expect(ciphertext).not.toContain('Ada');
  await page.reload();
  await expect(page.locator('#ciphertext')).toHaveText(ciphertext!);
  await page.getByRole('button', { name: 'Initialize vault' }).click();
  await page.getByRole('button', { name: 'Read & decrypt' }).click();
  await expect(page.locator('#plaintext')).toContainText('"name": "Ada"');
  await page.getByRole('button', { name: 'Destroy vault' }).click();
  await expect(page.locator('#state')).toHaveText('Not initialized');
  await expect(page.locator('#ciphertext')).toHaveText(
    'Nothing stored under this key.',
  );
});

test('invalid input keeps the previously saved value intact', async ({
  page,
}) => {
  await page.goto('/examples/browser/');
  await page.getByRole('button', { name: 'Initialize vault' }).click();
  await page.getByRole('button', { name: 'Encrypt & save' }).click();
  await expect(page.getByRole('status')).toContainText('Encrypted and saved');
  const ciphertext = await page.locator('#ciphertext').textContent();
  await page.getByLabel('JSON object').fill('{ invalid');
  await page.getByRole('button', { name: 'Encrypt & save' }).click();
  await expect(page.getByRole('status')).toContainText('Enter valid JSON');
  await expect(page.locator('#ciphertext')).toHaveText(ciphertext!);
  await page.getByLabel('Storage key').fill('');
  await page.getByRole('button', { name: 'Read & decrypt' }).click();
  await expect(page.getByRole('status')).toContainText('Enter a storage key');
});
