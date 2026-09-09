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
});
