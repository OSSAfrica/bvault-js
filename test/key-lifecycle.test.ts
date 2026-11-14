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
