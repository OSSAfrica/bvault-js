mod utils;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

const PBKDF2_ITERATIONS: u32 = 100_000;
const IV_LENGTH: usize = 12;
const SALT_LENGTH: usize = 16;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptResult {
    encrypted_data: String,
    iv: String,
    salt: String,
}

/// Decode a URL-safe no-pad base64 string into bytes.
fn b64_decode(input: &str) -> Result<Vec<u8>, JsValue> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| JsValue::from_str("invalid base64"))
}

/// Encode bytes as URL-safe no-pad base64.
fn b64_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, PBKDF2_ITERATIONS)
}

/// Synchronously encrypts a string using AES-256-GCM with PBKDF2 key derivation.
///
/// Returns a JS object `{ encryptedData, iv, salt }` with URL-safe base64 strings.
/// Fully interoperable with the TypeScript `encrypt()` function.
///
/// # Errors
///
/// Returns an error if random byte generation or encryption fails.
#[wasm_bindgen]
pub fn encrypt_sync(data: &str, password: &str) -> Result<JsValue, JsValue> {
    utils::set_panic_hook();

    // Generate random salt and IV
    let mut salt = [0u8; SALT_LENGTH];
    getrandom::getrandom(&mut salt).map_err(|_| JsValue::from_str("failed to generate salt"))?;

    let mut iv = [0u8; IV_LENGTH];
    getrandom::getrandom(&mut iv).map_err(|_| JsValue::from_str("failed to generate IV"))?;

    // Derive key and encrypt
    let key = derive_key(password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("invalid key length"))?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|_| JsValue::from_str("encryption failed"))?;

    let result = EncryptResult {
        encrypted_data: b64_encode(&ciphertext),
        iv: b64_encode(&iv),
        salt: b64_encode(&salt),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|_| JsValue::from_str("serialization failed"))
}

/// Synchronously decrypts a base64-encoded ciphertext using AES-256-GCM.
///
/// Fully interoperable with the TypeScript `decrypt()` function.
///
/// # Errors
///
/// Returns an error if inputs are invalid base64, the IV is not 12 bytes,
/// or decryption/authentication fails.
#[wasm_bindgen]
pub fn decrypt_sync(
    b64_ciphertext: &str,
    password: &str,
    b64_iv: &str,
    b64_salt: &str,
) -> Result<String, JsValue> {
    utils::set_panic_hook();

    // Decode inputs
    let ciphertext = b64_decode(b64_ciphertext)?;
    let iv = b64_decode(b64_iv)?;
    let salt = b64_decode(b64_salt)?;

    if iv.len() != IV_LENGTH {
        return Err(JsValue::from_str("IV must be 12 bytes"));
    }

    // Derive key and decrypt
    let key = derive_key(password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| JsValue::from_str("invalid key length"))?;
    let nonce = Nonce::from_slice(&iv);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| JsValue::from_str("decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| JsValue::from_str("invalid utf-8"))
}
