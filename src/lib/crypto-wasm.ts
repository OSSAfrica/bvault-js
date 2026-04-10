// src/lib/crypto-wasm.ts

import { EncryptionError, DecryptionError } from './errors.js';

// Lazy-loaded WASM module reference
let wasmModule: typeof import('../pkg/bvault_js_rs.js') | null = null;
let wasmInitPromise: Promise<void> | null = null;

/**
 * Initializes the WASM module. Must be called once before using
 * `encryptSync` or `decryptSync`.
 *
 * Safe to call concurrently — multiple calls share the same init promise.
 *
 * @example
 * ```ts
 * import { initWasm, encryptSync, decryptSync } from 'bvault-js';
 *
 * await initWasm();
 * const result = encryptSync('secret', 'password');
 * const plaintext = decryptSync(result.encryptedData, 'password', result.iv, result.salt);
 * ```
 */
export async function initWasm(): Promise<void> {
  if (wasmModule) return;
  if (!wasmInitPromise) {
    wasmInitPromise = import('../pkg/bvault_js_rs.js').then((mod) => {
      wasmModule = mod;
    });
  }
  await wasmInitPromise;
}

function getWasm(): NonNullable<typeof wasmModule> {
  if (!wasmModule) {
    throw new Error(
      'WASM module not initialized. Call initWasm() before using sync crypto functions.',
    );
  }
  return wasmModule;
}

/**
 * Synchronously encrypts data using AES-256-GCM (WASM).
 *
 * Produces output that is interoperable with the async `encrypt()` function —
 * data encrypted here can be decrypted with either `decryptSync()` or `decrypt()`.
 *
 * @param data - The plaintext string to encrypt
 * @param password - The password used to derive the encryption key
 * @returns An object with base64 URL-safe encoded `encryptedData`, `iv`, and `salt`
 */
export function encryptSync(
  data: string,
  password: string,
): { encryptedData: string; iv: string; salt: string } {
  const wasm = getWasm();
  try {
    return wasm.encrypt_sync(data, password) as {
      encryptedData: string;
      iv: string;
      salt: string;
    };
  } catch (error) {
    throw new EncryptionError(
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
}

/**
 * Synchronously decrypts data using AES-256-GCM (WASM).
 *
 * Interoperable with the async `encrypt()` function —
 * data encrypted with `encrypt()` or `encryptSync()` can be decrypted here.
 *
 * @param encryptedData - Base64 URL-safe encoded ciphertext
 * @param password - The password used to derive the decryption key
 * @param iv - Base64 URL-safe encoded initialization vector
 * @param salt - Base64 URL-safe encoded salt
 * @returns The decrypted plaintext string
 */
export function decryptSync(
  encryptedData: string,
  password: string,
  iv: string,
  salt: string,
): string {
  const wasm = getWasm();
  try {
    return wasm.decrypt_sync(encryptedData, password, iv, salt);
  } catch (error) {
    throw new DecryptionError(
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
}
