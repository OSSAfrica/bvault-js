// test/migration.test.ts

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clearLegacyData } from '../src/lib/migration.js';

/**
 * Recreates the v0.x database layout: per-item IV/salt records keyed by the
 * caller's own storage key.
 */
const seedLegacyDb = (keys: { local: string[]; session: string[] }) =>
  new Promise<void>((resolve, reject) => {
    const request = indexedDB.open('bvault', 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      db.createObjectStore('encryption_metadata_local', { keyPath: 'key' });
      db.createObjectStore('encryption_metadata_session', { keyPath: 'key' });
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(
        ['encryption_metadata_local', 'encryption_metadata_session'],
        'readwrite',
      );
      keys.local.forEach((key) =>
        tx
          .objectStore('encryption_metadata_local')
          .put({ key, iv: 'aXY', salt: 'c2FsdA' }),
      );
      keys.session.forEach((key) =>
        tx
          .objectStore('encryption_metadata_session')
          .put({ key, iv: 'aXY', salt: 'c2FsdA' }),
      );
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    };
    request.onerror = () => reject(request.error);
  });

describe('legacy data migration', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it('removes only the entries v0.x recorded', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    await seedLegacyDb({ local: ['token', 'profile'], session: ['nonce'] });
    localStorage.setItem('token', 'bGVnYWN5');
    localStorage.setItem('profile', 'bGVnYWN5Mg');
    sessionStorage.setItem('nonce', 'bGVnYWN5Mw');

    // Data belonging to other libraries must survive.
    localStorage.setItem('analytics-id', 'keep-me');
    sessionStorage.setItem('feature-flags', 'keep-me-too');

    expect(await clearLegacyData()).toBe(3);

    expect(localStorage.getItem('token')).toBeNull();
    expect(localStorage.getItem('profile')).toBeNull();
    expect(sessionStorage.getItem('nonce')).toBeNull();
    expect(localStorage.getItem('analytics-id')).toBe('keep-me');
    expect(sessionStorage.getItem('feature-flags')).toBe('keep-me-too');
  });

  it('warns once when it removes something', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    localStorage.setItem('token', 'bGVnYWN5');

    await clearLegacyData();

    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('v0.x');
  });

  it('is idempotent and silent on a second run', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    localStorage.setItem('token', 'bGVnYWN5');
    await clearLegacyData();

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await clearLegacyData()).toBe(0);
    expect(warn).not.toHaveBeenCalled();
  });

  it('does nothing when a metadata key has no stored value', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await clearLegacyData()).toBe(0);
  });
});
