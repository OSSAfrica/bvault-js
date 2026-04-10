#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use bvault_js_rs::{decrypt_sync, encrypt_sync};

/// Helper: extract a string field from a JsValue object.
fn get_field(obj: &JsValue, field: &str) -> String {
    js_sys::Reflect::get(obj, &JsValue::from_str(field))
        .unwrap()
        .as_string()
        .unwrap()
}

#[wasm_bindgen_test]
fn round_trip_basic() {
    let plaintext = "Hello, bvault!";
    let password = "strongpassword123";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    let decrypted = decrypt_sync(&encrypted_data, password, &iv, &salt).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn round_trip_empty_string() {
    let plaintext = "";
    let password = "password";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    let decrypted = decrypt_sync(&encrypted_data, password, &iv, &salt).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn round_trip_unicode_and_emoji() {
    let plaintext = "Hello 世界! 👋🔐 café résumé";
    let password = "p@$$w0rd!";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    let decrypted = decrypt_sync(&encrypted_data, password, &iv, &salt).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn wrong_password_fails() {
    let plaintext = "secret data";
    let password = "correct_password";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    let err = decrypt_sync(&encrypted_data, "wrong_password", &iv, &salt);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn tampered_ciphertext_fails() {
    let plaintext = "important data";
    let password = "password";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    // Tamper with the ciphertext by replacing a character
    let mut tampered = encrypted_data.into_bytes();
    if !tampered.is_empty() {
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    }
    let tampered = String::from_utf8(tampered).unwrap();

    let err = decrypt_sync(&tampered, password, &iv, &salt);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn invalid_base64_fails() {
    let err = decrypt_sync(
        "!!!invalid!!!",
        "password",
        "AAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAA",
    );
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn wrong_iv_length_fails() {
    let plaintext = "test";
    let password = "password";

    let result = encrypt_sync(plaintext, password).unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let salt = get_field(&result, "salt");

    // Use a 16-byte IV instead of 12-byte — should fail
    let bad_iv = "AAAAAAAAAAAAAAAAAAAAAA"; // 16 bytes in URL-safe base64
    let err = decrypt_sync(&encrypted_data, password, bad_iv, &salt);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn base64_output_is_url_safe() {
    let result = encrypt_sync("test data", "password").unwrap();
    let encrypted_data = get_field(&result, "encryptedData");
    let iv = get_field(&result, "iv");
    let salt = get_field(&result, "salt");

    // URL-safe base64 should not contain +, /, or =
    for s in [&encrypted_data, &iv, &salt] {
        assert!(!s.contains('+'), "contains '+': {s}");
        assert!(!s.contains('/'), "contains '/': {s}");
        assert!(!s.contains('='), "contains '=': {s}");
    }
}

#[wasm_bindgen_test]
fn unique_iv_and_salt_per_encryption() {
    let password = "password";
    let plaintext = "same data";

    let r1 = encrypt_sync(plaintext, password).unwrap();
    let r2 = encrypt_sync(plaintext, password).unwrap();

    // IV and salt should differ between calls
    assert_ne!(get_field(&r1, "iv"), get_field(&r2, "iv"));
    assert_ne!(get_field(&r1, "salt"), get_field(&r2, "salt"));
    // Ciphertext should also differ (different IV/salt → different output)
    assert_ne!(
        get_field(&r1, "encryptedData"),
        get_field(&r2, "encryptedData")
    );
}
