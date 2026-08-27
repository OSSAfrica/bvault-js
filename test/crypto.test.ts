// test/crypto.test.ts

import { beforeEach, describe, expect, it } from 'vitest';
import {
  decryptWithKey,
  encryptWithKey,
  isCurrentFormat,
} from '../src/lib/crypto.js';
import { DecryptionError } from '../src/lib/errors.js';
import {
  base64ToBuffer,
  bufferToBase64,
  bufferToString,
  stringToBuffer,
} from '../src/lib/converters.js';

/**
 * Megabyte round-trips and the 10k-iteration IV check run for seconds on a
 * developer machine and longer on CI, well past vitest's 5s default.
 */
const SLOW_TEST_TIMEOUT = 30_000;

const makeKey = () =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);

describe('crypto', () => {
  let key: CryptoKey;

  beforeEach(async () => {
    key = await makeKey();
  });

  describe('round-trip', () => {
    it('encrypts and decrypts a value', async () => {
      const payload = await encryptWithKey('secret data', key);
      expect(await decryptWithKey(payload, key)).toBe('secret data');
    });

    it('preserves multi-byte characters', async () => {
      const text = 'Hello 世界! 👋';
      const payload = await encryptWithKey(text, key);
      expect(await decryptWithKey(payload, key)).toBe(text);
    });

    it('produces URL-safe base64', async () => {
      const payload = await encryptWithKey('data', key);
      expect(payload).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it(
      'round-trips a 1MB value',
      async () => {
        const large = 'x'.repeat(1024 * 1024);
        const payload = await encryptWithKey(large, key);
        expect(await decryptWithKey(payload, key)).toBe(large);
      },
      SLOW_TEST_TIMEOUT,
    );
  });

  describe('payload format', () => {
    it('stamps the current version byte', async () => {
      const payload = await encryptWithKey('data', key);
      expect(base64ToBuffer(payload)[0]).toBe(1);
      expect(isCurrentFormat(payload)).toBe(true);
    });

    it('rejects a value with no version byte', () => {
      expect(isCurrentFormat(bufferToBase64(new Uint8Array(40)))).toBe(false);
    });

    it('rejects an unsupported version', async () => {
      const bytes = base64ToBuffer(await encryptWithKey('data', key));
      bytes[0] = 99;
      await expect(decryptWithKey(bufferToBase64(bytes), key)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('rejects a payload too short to hold a header', async () => {
      await expect(
        decryptWithKey(bufferToBase64(new Uint8Array([1, 2, 3])), key),
      ).rejects.toThrow(DecryptionError);
    });
  });

  describe('authentication', () => {
    it('rejects a tampered ciphertext', async () => {
      const bytes = base64ToBuffer(await encryptWithKey('secret', key));
      bytes[bytes.length - 1] ^= 0xff;
      await expect(decryptWithKey(bufferToBase64(bytes), key)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('rejects a tampered IV', async () => {
      const bytes = base64ToBuffer(await encryptWithKey('secret', key));
      bytes[1] ^= 0xff;
      await expect(decryptWithKey(bufferToBase64(bytes), key)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('rejects the wrong key', async () => {
      const payload = await encryptWithKey('secret', key);
      await expect(decryptWithKey(payload, await makeKey())).rejects.toThrow(
        DecryptionError,
      );
    });
  });

  describe('IV uniqueness', () => {
    it(
      'uses a distinct IV for every write',
      async () => {
        const seen = new Set<string>();
        for (let i = 0; i < 10_000; i++) {
          const iv = base64ToBuffer(await encryptWithKey('same', key)).subarray(
            1,
            13,
          );
          seen.add(bufferToBase64(iv));
        }
        expect(seen.size).toBe(10_000);
      },
      SLOW_TEST_TIMEOUT,
    );

    it('produces different ciphertext for identical input', async () => {
      const a = await encryptWithKey('same', key);
      const b = await encryptWithKey('same', key);
      expect(a).not.toBe(b);
    });
  });

  describe('converters', () => {
    it('round-trips buffer/base64', () => {
      const original = new Uint8Array([1, 2, 3, 4, 255, 0, 128]);
      expect(base64ToBuffer(bufferToBase64(original))).toEqual(original);
    });

    it(
      'round-trips 1MB without overflowing the stack',
      () => {
        // getRandomValues caps at 65,536 bytes per call, so fill in chunks.
        const bytes = new Uint8Array(1024 * 1024);
        for (let i = 0; i < bytes.length; i += 65_536) {
          crypto.getRandomValues(bytes.subarray(i, i + 65_536));
        }
        expect(base64ToBuffer(bufferToBase64(bytes))).toEqual(bytes);
      },
      SLOW_TEST_TIMEOUT,
    );

    it('handles special characters in text conversion', () => {
      const text = 'Hello 世界! 👋';
      expect(bufferToString(stringToBuffer(text))).toBe(text);
    });
  });
});
