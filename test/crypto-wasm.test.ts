// test/crypto-wasm.test.ts
//
// Interoperability tests between the TypeScript (Web Crypto) and Rust (WASM)
// encryption implementations. These tests verify that data encrypted by one
// can be decrypted by the other.
//
// These tests require the WASM module to be built first: `npm run build:wasm`

import { describe, expect, it } from 'vitest';
import { encrypt, decrypt } from '../src/index.js';

// Store original crypto for integration tests
const originalCrypto = global.crypto;

async function withRealCrypto<T>(fn: () => Promise<T>): Promise<T> {
  const current = global.crypto;
  global.crypto = originalCrypto;
  try {
    return await fn();
  } finally {
    global.crypto = current;
  }
}

// Dynamically import WASM — may not be available if not built
let wasmAvailable = false;
let wasmModule: {
  encrypt_sync: (data: string, password: string) => {
    encryptedData: string;
    iv: string;
    salt: string;
  };
  decrypt_sync: (
    ciphertext: string,
    password: string,
    iv: string,
    salt: string,
  ) => string;
};

try {
  wasmModule = await import('../src/pkg/bvault_js_rs.js');
  wasmAvailable = true;
} catch {
  // WASM not built — tests will be skipped
}

const describeWasm = wasmAvailable ? describe : describe.skip;

describeWasm('WASM Crypto Interoperability', () => {
  describe('WASM round-trip', () => {
    it('should encrypt and decrypt basic text', () => {
      const result = wasmModule.encrypt_sync('Hello, bvault!', 'password123');

      expect(result).toEqual({
        encryptedData: expect.any(String),
        iv: expect.any(String),
        salt: expect.any(String),
      });

      const decrypted = wasmModule.decrypt_sync(
        result.encryptedData,
        'password123',
        result.iv,
        result.salt,
      );
      expect(decrypted).toBe('Hello, bvault!');
    });

    it('should encrypt and decrypt empty string', () => {
      const result = wasmModule.encrypt_sync('', 'password');
      const decrypted = wasmModule.decrypt_sync(
        result.encryptedData,
        'password',
        result.iv,
        result.salt,
      );
      expect(decrypted).toBe('');
    });

    it('should encrypt and decrypt Unicode and emoji', () => {
      const text = 'Hello 世界! 👋🔐 café résumé';
      const result = wasmModule.encrypt_sync(text, 'test-password-2');
      const decrypted = wasmModule.decrypt_sync(
        result.encryptedData,
        'test-password-2',
        result.iv,
        result.salt,
      );
      expect(decrypted).toBe(text);
    });
  });

  describe('Cross-implementation: TS encrypt → WASM decrypt', () => {
    it('should decrypt TS-encrypted data with WASM', async () => {
      const encrypted = await withRealCrypto(() =>
        encrypt('cross-impl test', 'shared-password'),
      );

      const decrypted = wasmModule.decrypt_sync(
        encrypted.encryptedData,
        'shared-password',
        encrypted.iv,
        encrypted.salt,
      );
      expect(decrypted).toBe('cross-impl test');
    });

    it('should decrypt TS-encrypted Unicode with WASM', async () => {
      const text = 'Unicode: 日本語 🎉';
      const encrypted = await withRealCrypto(() => encrypt(text, 'password'));

      const decrypted = wasmModule.decrypt_sync(
        encrypted.encryptedData,
        'password',
        encrypted.iv,
        encrypted.salt,
      );
      expect(decrypted).toBe(text);
    });
  });

  describe('Cross-implementation: WASM encrypt → TS decrypt', () => {
    it('should decrypt WASM-encrypted data with TS', async () => {
      const encrypted = wasmModule.encrypt_sync(
        'reverse cross-impl',
        'shared-password',
      );

      const decrypted = await withRealCrypto(() =>
        decrypt(
          encrypted.encryptedData,
          'shared-password',
          encrypted.iv,
          encrypted.salt,
        ),
      );
      expect(decrypted).toBe('reverse cross-impl');
    });

    it('should decrypt WASM-encrypted Unicode with TS', async () => {
      const text = 'Emoji test: 🔒💾🚀';
      const encrypted = wasmModule.encrypt_sync(text, 'password');

      const decrypted = await withRealCrypto(() =>
        decrypt(encrypted.encryptedData, 'password', encrypted.iv, encrypted.salt),
      );
      expect(decrypted).toBe(text);
    });
  });

  describe('Base64 format validation', () => {
    it('should produce URL-safe base64 without padding', () => {
      const result = wasmModule.encrypt_sync('test data', 'password');

      for (const value of [result.encryptedData, result.iv, result.salt]) {
        expect(value).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(value).not.toContain('+');
        expect(value).not.toContain('/');
        expect(value).not.toContain('=');
      }
    });

    it('should produce unique IV and salt per call', () => {
      const r1 = wasmModule.encrypt_sync('same data', 'password');
      const r2 = wasmModule.encrypt_sync('same data', 'password');

      expect(r1.iv).not.toBe(r2.iv);
      expect(r1.salt).not.toBe(r2.salt);
      expect(r1.encryptedData).not.toBe(r2.encryptedData);
    });
  });

  describe('Error cases', () => {
    it('should fail with wrong password', () => {
      const encrypted = wasmModule.encrypt_sync('secret', 'correct');
      expect(() =>
        wasmModule.decrypt_sync(
          encrypted.encryptedData,
          'wrong',
          encrypted.iv,
          encrypted.salt,
        ),
      ).toThrow();
    });

    it('should fail with tampered ciphertext', () => {
      const encrypted = wasmModule.encrypt_sync('data', 'password');
      const tampered =
        (encrypted.encryptedData[0] === 'A' ? 'B' : 'A') +
        encrypted.encryptedData.slice(1);

      expect(() =>
        wasmModule.decrypt_sync(
          tampered,
          'password',
          encrypted.iv,
          encrypted.salt,
        ),
      ).toThrow();
    });

    it('should fail with invalid base64', () => {
      expect(() =>
        wasmModule.decrypt_sync('!!!invalid!!!', 'password', 'aaa', 'bbb'),
      ).toThrow();
    });
  });
});
