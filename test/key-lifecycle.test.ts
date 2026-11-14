import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  destroySecureStorage,
  initializeSecureStorage,
  secureLocalStorage,
  isSecureStorageInitialized,
} from '../src/index.js';
import { resetSecureStorageState } from '../src/lib/secure-storage.js';
import BVaultDB from '../src/lib/bvault-db.js';
import { hasKey } from '../src/lib/keystore.js';

const MARKER = 'bvault:key-lifecycle';

describe('key destruction coordination', () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
    resetSecureStorageState();
    localStorage.clear();
    sessionStorage.clear();
    await initializeSecureStorage();
  });

  it('does not delete the key when it cannot record the invalidation', async () => {
    const deletion = vi.spyOn(BVaultDB, 'deleteData');
    const setItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(
      function (key, value) {
        if (key === MARKER)
          throw new DOMException('full', 'QuotaExceededError');
        return setItem.call(this, key, value);
      },
    );
    await expect(destroySecureStorage()).rejects.toMatchObject({
      name: 'QuotaExceededError',
    });
    expect(deletion).not.toHaveBeenCalled();
    expect(await hasKey()).toBe(true);
  });

  it('still destroys safely if BroadcastChannel posting fails', async () => {
    const original = Object.getOwnPropertyDescriptor(
      window,
      'BroadcastChannel',
    );
    resetSecureStorageState();
    Object.defineProperty(window, 'BroadcastChannel', {
      configurable: true,
      value: class {
        onmessage = null;
        postMessage() {
          throw new Error('channel unavailable');
        }
        close() {}
      },
    });
    try {
      await initializeSecureStorage();
      await destroySecureStorage();
      expect(await BVaultDB.getData('keys', 'storage-key')).toBeUndefined();
      expect(isSecureStorageInitialized()).toBe(false);
    } finally {
      resetSecureStorageState();
      if (original) Object.defineProperty(window, 'BroadcastChannel', original);
      else Reflect.deleteProperty(window, 'BroadcastChannel');
    }
  });

  it('refuses initialization while another tab is destroying the key', async () => {
    localStorage.setItem(
      MARKER,
      JSON.stringify({ id: 'other-tab', destroying: true }),
    );
    await expect(initializeSecureStorage()).rejects.toThrow('being destroyed');
    expect(isSecureStorageInitialized()).toBe(false);
  });

  it('notices a missed notification before using its cached key', async () => {
    localStorage.setItem(
      MARKER,
      JSON.stringify({ id: 'new-generation', destroying: false }),
    );
    await expect(secureLocalStorage.setItem('stale', 'value')).rejects.toThrow(
      'not initialized',
    );
    expect(localStorage.getItem('bv1:stale')).toBeNull();
  });
});
