// src/lib/crypto.ts

import {
  stringToBuffer,
  bufferToString,
  base64ToBuffer,
  bufferToBase64,
} from './converters.js';
import { EncryptionError, DecryptionError } from './errors.js';

// Configuration constants
/**
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
 */
const ALGORITHM = 'AES-GCM';

/**
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
 */
const IV_LENGTH = 12; // 96 bits for AES-GCM

/**
 * Payload format marker. Values written by 0.x carry no version byte, which is
 * how legacy data is recognised and cleared on initialization.
 */
export const PAYLOAD_VERSION = 1;

/**
 * Byte offset at which the ciphertext begins.
 */
const CIPHERTEXT_OFFSET = 1 + IV_LENGTH;

/**
 * Encrypts data with a key, returning a self-describing payload.
 *
 * The layout is `version(1) || iv(12) || ciphertext+tag`, base64url-encoded.
 * Carrying the IV inline is what keeps reads free of any IndexedDB lookup.
 *
 * A fresh IV is generated per call. The key is long-lived, and repeating an IV
 * under one AES-GCM key is catastrophic, so the IV must never be derived from
 * the storage key or reused.
 *
 * @param data
 * @param key
 * @returns {Promise<string>} base64url payload
 */
export const encryptWithKey = async (
  data: string,
  key: CryptoKey,
): Promise<string> => {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: ALGORITHM, iv },
        key,
        stringToBuffer(data),
      ),
    );

    const payload = new Uint8Array(CIPHERTEXT_OFFSET + ciphertext.length);
    payload[0] = PAYLOAD_VERSION;
    payload.set(iv, 1);
    payload.set(ciphertext, CIPHERTEXT_OFFSET);

    return bufferToBase64(payload);
  } catch (error) {
    throw new EncryptionError((error as Error).message, { cause: error });
  }
};

/**
 * Decrypts a payload produced by {@link encryptWithKey}.
 *
 * Throws if the payload is malformed, is not in the current format, or fails
 * AES-GCM authentication — tampered ciphertext is rejected rather than
 * returned as garbage.
 *
 * @param payload
 * @param key
 * @returns {Promise<string>}
 */
export const decryptWithKey = async (
  payload: string,
  key: CryptoKey,
): Promise<string> => {
  try {
    const bytes = base64ToBuffer(payload);

    if (bytes.length <= CIPHERTEXT_OFFSET) {
      throw new Error('Payload is too short to contain a header');
    }

    if (bytes[0] !== PAYLOAD_VERSION) {
      throw new Error(`Unsupported payload version: ${bytes[0]}`);
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv: bytes.subarray(1, CIPHERTEXT_OFFSET) },
      key,
      bytes.subarray(CIPHERTEXT_OFFSET),
    );

    return bufferToString(decrypted);
  } catch (error) {
    throw new DecryptionError((error as Error).message, { cause: error });
  }
};

/**
 * Reports whether a stored value carries the current payload format.
 * Used to identify 0.x values so they can be cleared.
 *
 * @param payload
 * @returns {boolean}
 */
export const isCurrentFormat = (payload: string): boolean => {
  try {
    const bytes = base64ToBuffer(payload);
    return bytes.length > CIPHERTEXT_OFFSET && bytes[0] === PAYLOAD_VERSION;
  } catch {
    return false;
  }
};
