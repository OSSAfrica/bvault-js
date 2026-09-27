// src/lib/converters.ts

/**
 * Chunk size used when converting bytes to a binary string.
 * Kept well below the engine's argument limit so `String.fromCharCode`
 * is never handed more arguments than it can accept.
 */
const CHUNK_SIZE = 0x2000; // 8 KiB

// Text <-> Uint8Array conversion
/**
 * Converts a string to a UTF-8 byte array
 * @param str
 * @returns Uint8Array
 */
export const stringToBuffer = (str: string): Uint8Array => {
  return new TextEncoder().encode(str);
};

/**
 * Converts a UTF-8 byte array to a string
 * @param buffer
 * @returns string
 */
export const bufferToString = (buffer: ArrayBuffer | Uint8Array): string => {
  return new TextDecoder().decode(buffer);
};

// Base64 URL-safe encoding
/**
 * Converts a base64 (standard or URL-safe) string to a byte array
 * @param base64
 * @returns Uint8Array
 */
export const base64ToBuffer = (base64: string): Uint8Array => {
  // Convert URL-safe base64 to standard base64
  let standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');

  // Reject invalid characters and padding before atob, whose validation differs
  // between runtimes.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(standardBase64)) {
    throw new Error('Invalid base64 string');
  }

  const dataLength = standardBase64.replace(/=+$/, '').length;
  const existingPadding = standardBase64.length - dataLength;
  const requiredPadding = (4 - (dataLength % 4)) % 4;
  if (
    dataLength % 4 === 1 ||
    (existingPadding > 0 &&
      (standardBase64.length % 4 !== 0 || existingPadding !== requiredPadding))
  ) {
    throw new Error('Invalid base64 string');
  }

  // Add padding when the input is valid but unpadded.
  if (existingPadding === 0 && requiredPadding > 0) {
    standardBase64 += '='.repeat(requiredPadding);
  }

  const binaryString = atob(standardBase64);
  const bytes = new Uint8Array(binaryString.length);

  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
};

/**
 * Converts a byte array to a URL-safe base64 string.
 *
 * Bytes are converted in chunks; spreading the whole array into
 * `String.fromCharCode` overflows the call stack on large payloads.
 *
 * @param buffer
 * @returns string
 */
export const bufferToBase64 = (buffer: ArrayBuffer | Uint8Array): string => {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  let binaryString = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binaryString += String.fromCharCode(...bytes.subarray(i, i + CHUNK_SIZE));
  }

  return btoa(binaryString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};
