// src/lib/errors.ts

/**
 * Base class for cryptographic errors.
 * Provides standardized handling of error causes and context.
 */
class CryptoError extends Error {
  public cause?: unknown;
  public context?: Record<string, unknown>;

  constructor(
    message: string,
    options: {
      cause?: unknown;
      context?: Record<string, unknown>;
    } = {},
  ) {
    super(message);
    this.name = this.constructor.name;
    this.cause = options.cause;
    this.context = options.context;

    if (options.cause instanceof Error && options.cause.stack) {
      this.stack += '\nCaused by: ' + options.cause.stack;
    }
  }

  /**
   * Returns a developer-friendly JSON object of the error,
   * including context and cause if available.
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      context: this.context,
      cause:
        this.cause instanceof Error
          ? { name: this.cause.name, message: this.cause.message }
          : this.cause,
      stack: this.stack,
    };
  }
}

/**
 * Error thrown when encryption fails.
 */
export class EncryptionError extends CryptoError {
  constructor(
    message = 'Encryption failed',
    options: {
      cause?: unknown;
      context?: Record<string, unknown>;
    } = {},
  ) {
    super(message, options);
  }
}

/**
 * Error thrown when decryption fails.
 */
export class DecryptionError extends CryptoError {
  constructor(
    message = 'Decryption failed',
    options: {
      cause?: unknown;
      context?: Record<string, unknown>;
    } = {},
  ) {
    super(message, options);
  }
}
