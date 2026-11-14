import { expect, test, type BrowserContext } from '@playwright/test';

declare global {
  interface Window {
    encryptionPaused: boolean;
    resumeEncryption: () => void;
    pendingWrite: Promise<string | null>;
  }
}

async function initializedTab(context: BrowserContext) {
  const page = await context.newPage();
  await page.goto('/test/browser/');
  await page.waitForFunction(() => Boolean(window.bvault));
  await page.evaluate(() => window.bvault.initializeSecureStorage());
  return page;
}

for (const transport of [
  'broadcast',
  'storage',
  'missed-notification',
] as const) {
  test(`destruction invalidates another tab via ${transport}`, async ({
    context,
  }) => {
    await context.addInitScript((transport) => {
      if (transport !== 'broadcast') {
        Object.defineProperty(window, 'BroadcastChannel', { value: undefined });
      }
      if (transport !== 'storage') {
        const original = window.addEventListener;
        window.addEventListener = function (type: string, ...args: unknown[]) {
          if (type !== 'storage')
            Reflect.apply(original, this, [type, ...args]);
        };
      }
    }, transport);
    const first = await initializedTab(context);
    const second = await initializedTab(context);
    await first.evaluate(async () => {
      sessionStorage.setItem('other-app', 'keep');
      await window.bvault.secureLocalStorage.setItem('before', 'old local');
      await window.bvault.secureSessionStorage.setItem('before', 'old session');
    });
    await second.evaluate(() => window.bvault.destroySecureStorage());
    if (transport !== 'missed-notification') {
      await expect
        .poll(() => first.evaluate(() => sessionStorage.getItem('bv1:before')))
        .toBeNull();
    }
    const result = await first.evaluate(async () => {
      const error = await window.bvault.secureLocalStorage
        .setItem('after', 'must not be written')
        .then(
          () => null,
          (error: Error) => error.message,
        );
      return {
        error,
        initialized: window.bvault.isSecureStorageInitialized(),
        local: localStorage.getItem('bv1:after'),
        session: sessionStorage.getItem('bv1:before'),
        other: sessionStorage.getItem('other-app'),
      };
    });
    expect(result.error).toMatch(
      /not initialized|key changed|being destroyed/i,
    );
    expect(result).toMatchObject({
      initialized: false,
      local: null,
      session: null,
      other: 'keep',
    });
    await first.evaluate(async () => {
      await window.bvault.initializeSecureStorage();
      await window.bvault.secureLocalStorage.setItem('fresh', 'new key');
    });
    expect(
      await second.evaluate(async () => {
        await window.bvault.initializeSecureStorage();
        return window.bvault.secureLocalStorage.getItem('fresh');
      }),
    ).toBe('new key');
  });
}

test('a write already encrypting cannot persist under a destroyed key', async ({
  context,
}) => {
  const first = await initializedTab(context);
  const second = await initializedTab(context);
  await first.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    crypto.subtle.encrypt = async (...args) => {
      const ciphertext = await original(...args);
      window.encryptionPaused = true;
      await new Promise<void>((resolve) => {
        window.resumeEncryption = resolve;
      });
      return ciphertext;
    };
    window.pendingWrite = window.bvault.secureLocalStorage
      .setItem('late-write', 'old key')
      .then(
        () => null,
        (error: Error) => error.message,
      );
  });
  await first.waitForFunction(() => window.encryptionPaused);
  await second.evaluate(() => window.bvault.destroySecureStorage());
  const result = await first.evaluate(async () => {
    window.resumeEncryption();
    const error = await window.pendingWrite;
    return { error, stored: localStorage.getItem('bv1:late-write') };
  });
  expect(result.error).toMatch(/not initialized|key changed|being destroyed/i);
  expect(result.stored).toBeNull();
});
