// test/secure-storage.test.ts

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  initializeSecureStorage,
  isSecureStorageInitialized,
  secureLocalStorage,
  secureSessionStorage,
  destroySecureStorage,
} from '../src/index.js';
import { resetSecureStorageState } from '../src/lib/secure-storage.js';
import { getOrCreateKey, destroyKey, hasKey } from '../src/lib/keystore.js';

const PREFIX = 'bv1:';

const freshStart = async () => {
  localStorage.clear();
  sessionStorage.clear();
  resetSecureStorageState();
  await initializeSecureStorage();
};

describe('secure storage', () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
    await freshStart();
  });

  describe('the key', () => {
    it('is not extractable — exportKey must reject', async () => {
      const key = await getOrCreateKey();
      expect(key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
      await expect(crypto.subtle.exportKey('jwk', key)).rejects.toThrow();
    });

    it('persists across a simulated page reload', async () => {
      await secureLocalStorage.setItem('token', 'abc123');

      resetSecureStorageState();
      await initializeSecureStorage();

      expect(await secureLocalStorage.getItem('token')).toBe('abc123');
    });
  });

  describe('round-trip', () => {
    it('stores and retrieves a string', async () => {
      await secureLocalStorage.setItem('key', 'value');
      expect(await secureLocalStorage.getItem('key')).toBe('value');
    });

    it('stores and retrieves an object as JSON', async () => {
      const profile = { username: 'alice', email: 'alice@example.com' };
      await secureLocalStorage.setItem('profile', profile);
      expect(
        JSON.parse((await secureLocalStorage.getItem('profile'))!),
      ).toEqual(profile);
    });

    it('works for sessionStorage independently', async () => {
      await secureSessionStorage.setItem('k', 'session-value');
      expect(await secureSessionStorage.getItem('k')).toBe('session-value');
      expect(await secureLocalStorage.getItem('k')).toBeNull();
    });

    it('returns null for a key that was never set', async () => {
      expect(await secureLocalStorage.getItem('absent')).toBeNull();
    });
  });

  describe('nothing readable at rest', () => {
    it('leaves no plaintext in the raw store', async () => {
      await secureLocalStorage.setItem('token', 'super-secret-value');

      expect(localStorage.getItem(PREFIX + 'token')).not.toContain(
        'super-secret-value',
      );
      expect(JSON.stringify(localStorage)).not.toContain('super-secret-value');
      expect(Object.values({ ...localStorage }).join('')).not.toContain(
        'super-secret-value',
      );
    });
  });

  describe('key loss', () => {
    it('returns null and does NOT delete stored values', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      vi.spyOn(console, 'error').mockImplementation(() => {});

      await secureLocalStorage.setItem('token', 'abc123');
      const ciphertext = localStorage.getItem(PREFIX + 'token');

      // Simulate eviction: the key is gone, the ciphertext remains.
      await destroyKey();
      resetSecureStorageState();
      await initializeSecureStorage();

      expect(await secureLocalStorage.getItem('token')).toBeNull();
      expect(localStorage.getItem(PREFIX + 'token')).toBe(ciphertext);
      expect(warn).toHaveBeenCalled();
    });

    it('warns about possible key loss only once', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      vi.spyOn(console, 'error').mockImplementation(() => {});

      await secureLocalStorage.setItem('a', '1');
      await secureLocalStorage.setItem('b', '2');
      await destroyKey();
      resetSecureStorageState();
      await initializeSecureStorage();

      await secureLocalStorage.getItem('a');
      await secureLocalStorage.getItem('b');

      const lossWarnings = warn.mock.calls.filter((call) =>
        String(call[0]).includes('could not be decrypted'),
      );
      expect(lossWarnings).toHaveLength(1);
    });
  });

  describe('tampering', () => {
    it('returns null rather than garbage', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {});
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      await secureLocalStorage.setItem('token', 'abc123');
      const raw = localStorage.getItem(PREFIX + 'token')!;
      localStorage.setItem(PREFIX + 'token', raw.slice(0, -4) + 'AAAA');

      expect(await secureLocalStorage.getItem('token')).toBeNull();
    });
  });

  describe('removal', () => {
    it('removes a single value', async () => {
      await secureLocalStorage.setItem('key', 'value');
      secureLocalStorage.removeItem('key');
      expect(await secureLocalStorage.getItem('key')).toBeNull();
    });

    it('clear() removes only bVault entries', async () => {
      localStorage.setItem('other-library-data', 'untouched');
      await secureLocalStorage.setItem('mine', 'encrypted');

      secureLocalStorage.clear();

      expect(await secureLocalStorage.getItem('mine')).toBeNull();
      expect(localStorage.getItem('other-library-data')).toBe('untouched');
    });
  });

  describe('initialization guard', () => {
    it('reports initialization state', async () => {
      expect(isSecureStorageInitialized()).toBe(true);
      resetSecureStorageState();
      expect(isSecureStorageInitialized()).toBe(false);
    });

    it('throws when used before initialization', async () => {
      resetSecureStorageState();
      await expect(secureLocalStorage.setItem('k', 'v')).rejects.toThrow(
        /not initialized/,
      );
      await expect(secureLocalStorage.getItem('k')).rejects.toThrow(
        /not initialized/,
      );
    });
  });

  describe('destroySecureStorage', () => {
    it('removes the key and every stored value', async () => {
      await secureLocalStorage.setItem('token', 'abc123');
      await destroySecureStorage();

      expect(await hasKey()).toBe(false);
      expect(localStorage.getItem(PREFIX + 'token')).toBeNull();
      expect(isSecureStorageInitialized()).toBe(false);
    });
  });
});
