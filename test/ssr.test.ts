// @vitest-environment node
// test/ssr.test.ts

import { describe, expect, it } from 'vitest';

describe('server-side rendering safety', () => {
  it('imports without a localStorage global', async () => {
    expect(globalThis.localStorage).toBeUndefined();
    await expect(import('../src/index.js')).resolves.toBeDefined();
  });

  it('throws a clear error only when storage is actually used', async () => {
    const { secureLocalStorage } = await import('../src/index.js');
    await expect(secureLocalStorage.getItem('k')).rejects.toThrow(
      /not initialized|browser environment/,
    );
  });

  it('safely handles length and object copying in SSR environments', async () => {
    const { secureLocalStorage, secureSessionStorage } = await import(
      '../src/index.js'
    );

    // Direct access to length returns 0 rather than throwing
    expect(secureLocalStorage.length).toBe(0);
    expect(secureSessionStorage.length).toBe(0);

    // length is non-enumerable
    expect(
      Object.getOwnPropertyDescriptor(secureLocalStorage, 'length')?.enumerable,
    ).toBe(false);
    expect(
      Object.getOwnPropertyDescriptor(secureSessionStorage, 'length')
        ?.enumerable,
    ).toBe(false);

    // Object copying and serialization do not throw
    expect(() => ({ ...secureLocalStorage })).not.toThrow();
    expect(() => Object.assign({}, secureSessionStorage)).not.toThrow();
    expect(() => JSON.stringify(secureLocalStorage)).not.toThrow();

    // secureLocalStorage.keys() returns empty array in SSR
    expect(secureLocalStorage.keys()).toEqual([]);
  });
});
