mod utils;

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Synchronously decrypts a base64-encoded ciphertext using a password,
/// a base64-encoded IV, and a base64-encoded salt.
///
/// # Errors
///
/// - If the inputs are invalid base64, an error is returned.
/// - If the IV is not 16 bytes, an error is returned.
/// - If the key derivation, decryption or padding fails, an error is returned.
/// - If the decrypted bytes are not valid utf-8, an error is returned.
#[wasm_bindgen]
pub fn decrypt_sync(
    b64_ciphertext: &str,
    password: &str,
    b64_iv: &str,
    b64_salt: &str,
) -> Result<String, JsValue> {
    // --- helpers -------------------------------------------------------------
    fn b64_to_bytes(string: &str) -> Result<Vec<u8>, JsValue> {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, string)
            .map_err(|_| JsValue::from_str("invalid base64"))
    }

    // --- inputs --------------------------------------------------------------
    let ciphertext = b64_to_bytes(b64_ciphertext)?;
    let iv = b64_to_bytes(b64_iv)?;
    let salt = b64_to_bytes(b64_salt)?;

    if iv.len() != 16 {
        return Err(JsValue::from_str("IV must be 16 bytes"));
    }

    // --- key derivation (PBKDF2-HMAC-SHA256, 600 000 iters) ------------------
    let key = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &salt, 600_000);

    // --- decryption ----------------------------------------------------------
    let mut buf = ciphertext;
    let dec = Aes256CbcDec::new_from_slices(&key, &iv)
        .map_err(|_| JsValue::from_str("invalid key/iv length"))?;

    dec.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_| JsValue::from_str("decryption / padding error"))?;

    // --- utf-8 ---------------------------------------------------------------
    String::from_utf8(buf).map_err(|_| JsValue::from_str("invalid utf-8"))
}
