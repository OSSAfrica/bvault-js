// src/index.ts

export { EncryptionError, DecryptionError } from './lib/errors.js';
export {
  isSecureStorageInitialized,
  secureLocalStorage,
  secureSessionStorage,
  initializeSecureStorage,
  destroySecureStorage,
} from './lib/secure-storage.js';
