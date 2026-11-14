import { expect, test } from '@playwright/test';

declare global {
  interface Window {
    bvault: typeof import('../../src/index.js');
    readStoredKey: () => Promise<CryptoKey | undefined>;
  }
}

test.beforeEach(async ({ page }) => {
  await page.goto('/test/browser/');
  await page.waitForFunction(() => Boolean(window.bvault));
  await page.evaluate(() => window.bvault.initializeSecureStorage());
});

test('persists a native non-extractable CryptoKey through IndexedDB and reload', async ({
  page,
}) => {
  await page.evaluate(() =>
    window.bvault.secureLocalStorage.setItem('reload', 'survives'),
  );
  await page.reload();
  await page.waitForFunction(() => Boolean(window.bvault));
  const result = await page.evaluate(async () => {
    await window.bvault.initializeSecureStorage();
    const key = (await window.readStoredKey())!;
    let exportRejected = false;
    try {
      await crypto.subtle.exportKey('raw', key);
    } catch (error) {
      exportRejected =
        error instanceof DOMException && error.name === 'InvalidAccessError';
    }
    return {
      native: key instanceof CryptoKey,
      algorithm: key.algorithm,
      extractable: key.extractable,
      usages: key.usages,
      exportRejected,
      value: await window.bvault.secureLocalStorage.getItem('reload'),
    };
  });
  expect(result).toMatchObject({
    native: true,
    algorithm: { name: 'AES-GCM', length: 256 },
    extractable: false,
    exportRejected: true,
    value: 'survives',
  });
  expect(result.usages.sort()).toEqual(['decrypt', 'encrypt']);
});

for (const target of ['local', 'session'] as const) {
  test(`${target} storage round-trips objects as JSON and preserves other storage`, async ({
    page,
  }) => {
    const result = await page.evaluate(async (target) => {
      const secure =
        target === 'local'
          ? window.bvault.secureLocalStorage
          : window.bvault.secureSessionStorage;
      const raw = target === 'local' ? localStorage : sessionStorage;
      raw.setItem('another-app', 'keep');
      await secure.setItem('profile', { name: 'Ada', count: 3 });
      const value = await secure.getItem('profile');
      const ciphertext = raw.getItem('bv1:profile');
      secure.removeItem('profile');
      const removed = await secure.getItem('profile');
      await secure.setItem('again', 'clear me');
      secure.clear();
      return {
        value,
        ciphertext,
        removed,
        cleared: raw.getItem('bv1:again'),
        other: raw.getItem('another-app'),
      };
    }, target);
    expect(JSON.parse(result.value!)).toEqual({ name: 'Ada', count: 3 });
    expect(result.ciphertext).toBeTruthy();
    expect(result.ciphertext).not.toContain('Ada');
    expect(result).toMatchObject({
      removed: null,
      cleared: null,
      other: 'keep',
    });
  });
}

test('uses a fresh IV for repeated writes', async ({ page }) => {
  const payloads = await page.evaluate(async () => {
    await window.bvault.secureLocalStorage.setItem('iv', 'same plaintext');
    const first = localStorage.getItem('bv1:iv');
    await window.bvault.secureLocalStorage.setItem('iv', 'same plaintext');
    return [first, localStorage.getItem('bv1:iv')];
  });
  expect(payloads[0]).toBeTruthy();
  expect(payloads[1]).not.toBe(payloads[0]);
});

test('preserves tampered ciphertext when decryption fails', async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    await window.bvault.secureLocalStorage.setItem('tampered', 'original');
    const original = localStorage.getItem('bv1:tampered')!;
    const index = Math.floor(original.length / 2);
    const tampered =
      original.slice(0, index) +
      (original[index] === 'A' ? 'B' : 'A') +
      original.slice(index + 1);
    localStorage.setItem('bv1:tampered', tampered);
    return {
      value: await window.bvault.secureLocalStorage.getItem('tampered'),
      stored: localStorage.getItem('bv1:tampered'),
      tampered,
    };
  });
  expect(result.value).toBeNull();
  expect(result.stored).toBe(result.tampered);
});

test('shares the persisted key across tabs while session storage stays isolated', async ({
  page,
  context,
}) => {
  await page.evaluate(async () => {
    await window.bvault.secureLocalStorage.setItem(
      'shared',
      'hello from tab one',
    );
    await window.bvault.secureSessionStorage.setItem('private', 'tab one only');
  });
  // Initialize sequentially: simultaneous first-run creation is tracked in #8.
  const second = await context.newPage();
  await second.goto('/test/browser/');
  await second.waitForFunction(() => Boolean(window.bvault));
  const result = await second.evaluate(async () => {
    await window.bvault.initializeSecureStorage();
    const local = await window.bvault.secureLocalStorage.getItem('shared');
    const session = await window.bvault.secureSessionStorage.getItem('private');
    await window.bvault.secureLocalStorage.setItem(
      'reply',
      'hello from tab two',
    );
    return { local, session };
  });
  expect(result).toEqual({ local: 'hello from tab one', session: null });
  expect(
    await page.evaluate(() =>
      window.bvault.secureLocalStorage.getItem('reply'),
    ),
  ).toBe('hello from tab two');
});

test('destroys the key and owned data, then allows a fresh initialization', async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    localStorage.setItem('other', 'keep');
    await window.bvault.secureLocalStorage.setItem('secret', 'before');
    await window.bvault.secureSessionStorage.setItem('secret', 'before');
    await window.bvault.destroySecureStorage();
    const deletedKey = await window.readStoredKey();
    const initialized = window.bvault.isSecureStorageInitialized();
    const local = localStorage.getItem('bv1:secret');
    const session = sessionStorage.getItem('bv1:secret');
    await window.bvault.initializeSecureStorage();
    await window.bvault.secureLocalStorage.setItem('secret', 'after');
    return {
      deletedKey,
      initialized,
      local,
      session,
      other: localStorage.getItem('other'),
      value: await window.bvault.secureLocalStorage.getItem('secret'),
    };
  });
  expect(result).toEqual({
    deletedKey: undefined,
    initialized: false,
    local: null,
    session: null,
    other: 'keep',
    value: 'after',
  });
});
