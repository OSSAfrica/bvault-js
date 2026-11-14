// test/bvault-db.test.ts

import { afterEach, describe, expect, it, vi } from 'vitest';
import BVaultDB from '../src/lib/bvault-db.js';

/**
 * A hand-driven stand-in for IndexedDB. fake-indexeddb fires request success
 * and transaction completion back to back, so it cannot show which of the two
 * `addData()` waits for. Here the test decides when each event happens.
 */
const fakeDatabase = () => {
  const request: any = { result: 'storage-key', error: null };
  const transaction: any = {
    error: null,
    objectStore: () => ({ add: () => request }),
  };
  const db = { transaction: () => transaction } as unknown as IDBDatabase;

  vi.spyOn(BVaultDB, 'verifyStore').mockResolvedValue(db);

  return { request, transaction };
};

// Lets addData() reach the point where it has attached its handlers.
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

const track = (promise: Promise<unknown>) => {
  const state: {
    status: 'pending' | 'resolved' | 'rejected';
    value?: unknown;
  } = { status: 'pending' };
  promise.then(
    (value) => ((state.status = 'resolved'), (state.value = value)),
    (error) => ((state.status = 'rejected'), (state.value = error)),
  );
  return state;
};

describe('BVaultDB.addData', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('stays pending when the request succeeds but the transaction has not committed', async () => {
    const { request } = fakeDatabase();
    const state = track(BVaultDB.addData('keys', 'key', 'storage-key'));
    await settle();

    // A key must not be handed out before its write is durable.
    request.onsuccess?.(new Event('success'));
    await settle();

    expect(state.status).toBe('pending');
  });

  it('resolves once the transaction completes', async () => {
    const { request, transaction } = fakeDatabase();
    const state = track(BVaultDB.addData('keys', 'key', 'storage-key'));
    await settle();

    request.onsuccess?.(new Event('success'));
    transaction.oncomplete?.(new Event('complete'));
    await settle();

    expect(state).toEqual({ status: 'resolved', value: 'storage-key' });
  });

  it('rejects when the transaction aborts after the request succeeded', async () => {
    const { request, transaction } = fakeDatabase();
    const state = track(BVaultDB.addData('keys', 'key', 'storage-key'));
    await settle();

    const abort = new DOMException('commit failed', 'AbortError');
    request.onsuccess?.(new Event('success'));
    transaction.error = abort;
    transaction.onabort?.(new Event('abort'));
    await settle();

    expect(state).toEqual({ status: 'rejected', value: abort });
  });

  it('rejects with the ConstraintError when the key already exists', async () => {
    const { request } = fakeDatabase();
    const state = track(BVaultDB.addData('keys', 'key', 'storage-key'));
    await settle();

    const duplicate = new DOMException('exists', 'ConstraintError');
    request.error = duplicate;
    request.onerror?.(new Event('error'));
    await settle();

    expect(state).toEqual({ status: 'rejected', value: duplicate });
  });
});
