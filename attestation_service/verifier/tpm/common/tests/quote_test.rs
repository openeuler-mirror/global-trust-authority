use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use openssl::pkey::PKey;
use plugin_manager::PluginError;
use tpm_common_verifier::{QuoteVerifier, AlgorithmId};

#[test]
fn test_quote_verification_with_valid_quote() {
    // Test data
    let nonce = "leutgR1v2kWhbg4qvvrpHg==";
    
    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABCV662BHW/aRaFuDiq++uke",
        "AAAACAb8fKYekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );
    
    let signature = concat!(
        "ABQACwEAYoLBwBfIqVYp9wqIxR8fSL2DaVH6jsilgpZ3dRfA6W8k60OwZlJrtgO6Pqn+dLg9WJ/rVDEh",
        "gJR80i/vWhOONwzM6vwsc9Qw9jfOhxDbHaj/5zqYUNsEp+V89qf31VXmZ1x/x0qZ3h2NXeGpxtN4uXB6",
        "Q/PCXvto1TNSSfN/wUtd3nuUCG3JMUT9QuESzR6B30CVPryVo92ZtCilBxy6Yn4i9/0SV1lCsksG3rJG",
        "ff37QaUc/ujqF9HwsHeC3SWkTVhKqUnyRCRKdQIVZGLsIOT2iG7juT6HcHHG2uHh+hbouW/YUN+bySiU",
        "NTjUEqda0J+TvmxDi7PNxE144KIrHg=="
    );
    
    let ak_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApnxF+8clLTkPJYfLThOS
L4QbLZCX1DDZTkPqkh8P6B+J0zNhc5isROiCx9Bl7m0qCj7EEEBabUdtxQMSA3dn
NDQFuLtiIJZtSRgf0YPKPXqBYaRlZ08W16vWvCfScGOas8JpmViZBSVwxKl7wcby
nVxATnQ/WFCCgY/1hB6yrK6EbYtHtvbWah3UsDKUf8k3gpo0nDFYThrDL2NL2BlY
ibAl8Xzte3ArPDG9QQbBRDKV4o5Kl0/lplD0SbY611HTPz8zw7j+AAU2feITT+hl
u1yoxHtwv8i7wrRomOW6xLbbL0Te4zteoIxrefgy5a5gTdqPLxX4WONYn4VhH6VX
SwIDAQAB
-----END PUBLIC KEY-----"#;

    // Decode test data
    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let signature_bytes = BASE64.decode(signature).unwrap();
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    // Create QuoteVerifier instance
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();

    // Load AK public key
    let public_ak = PKey::public_key_from_pem(ak_public_key.as_bytes())
        .expect("Failed to load AK public key");

    assert!(quote_verifier.verify(&quote_bytes, &public_ak, Some(&nonce_decoded)).is_ok());

    // 2. Verify hash algorithm
    let hash_alg = quote_verifier.get_hash_algorithm();
    assert_eq!(hash_alg, AlgorithmId::Sha256);
    
    // 3. Verify PCR digest is not empty
    assert!(!quote_verifier.get_pcr_digest().is_empty());
    
    // 4. Verify PCR digest length matches hash algorithm
    let digest_len = quote_verifier.get_pcr_digest().len();
    assert_eq!(digest_len, 32); // SHA-256 digest length is 32 bytes
}

// Test Objective: Verify that the plugin correctly handles malformed Quote data
// Expected Result: Returns a InputError
#[test]
fn test_quote_verification_with_invalid_format() {
    
    // Create malformed Quote data (truncated data)
    let invalid_quote = vec![0x01, 0x02, 0x03]; // Too short to parse
    let signature_bytes = vec![0x04, 0x05, 0x06]; // Also too short
    
    // Try to create QuoteVerifier instance
    let result = QuoteVerifier::new(&invalid_quote, &signature_bytes);
    
    // Verify the result is an error
    assert!(result.is_err());
    
    // Verify error type and message content
    if let Err(err) = result {
        if let PluginError::InputError(msg) = err {
            assert!(msg.contains("Failed to parse"), "Error message should mention parsing failure");
        } else {
            panic!("Expected InputError, got different error type");
        }
    }
}

// Test Objective: Verify the magic value checking functionality
// Expected Result: Returns a QuoteError error, indicating an invalid magic value
#[test]
fn test_quote_verification_with_invalid_magic() {
    
    // Create Quote data with invalid magic value
    // Normal magic value: 0xff544347, modify the first byte
    let mut quote_data = BASE64.decode(concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABCV662BHW/aRaFuDiq++uke",
        "AAAACAb8fKYekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    )).unwrap();
    
    // Modify the first byte of the magic value
    quote_data[0] = 0xAA; // Change to a non-FF value
    
    let signature = BASE64.decode(concat!(
        "ABQACwEAYoLBwBfIqVYp9wqIxR8fSL2DaVH6jsilgpZ3dRfA6W8k60OwZlJrtgO6Pqn+dLg9WJ/rVDEh",
        "gJR80i/vWhOONwzM6vwsc9Qw9jfOhxDbHaj/5zqYUNsEp+V89qf31VXmZ1x/x0qZ3h2NXeGpxtN4uXB6",
        "Q/PCXvto1TNSSfN/wUtd3nuUCG3JMUT9QuESzR6B30CVPryVo92ZtCilBxy6Yn4i9/0SV1lCsksG3rJG",
        "ff37QaUc/ujqF9HwsHeC3SWkTVhKqUnyRCRKdQIVZGLsIOT2iG7juT6HcHHG2uHh+hbouW/YUN+bySiU",
        "NTjUEqda0J+TvmxDi7PNxE144KIrHg=="
    )).unwrap();
    
    // Try to create QuoteVerifier instance
    let result = QuoteVerifier::new(&quote_data, &signature);
    
    // Verify the result is an error
    assert!(result.is_err());
    
    // Verify error type and message content
    if let Err(err) = result {
        if let PluginError::InputError(msg) = err {
            assert!(msg.contains("magic value"), "Error message should mention invalid magic value");
        } else {
            panic!("Expected InputError, got different error type");
        }
    }
}

// Test Objective: Verify signature validation functionality
// Expected Result: Verification fails
#[test]
fn test_quote_verification_with_invalid_signature() {
    
    let nonce = "leutgR1v2kWhbg4qvvrpHg==";
    
    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABCV662BHW/aRaFuDiq++uke",
        "AAAACAb8fKYekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );
    
    // Modify signature data (tamper with one bit)
    let mut signature = BASE64.decode(concat!(
        "ABQACwEAYoLBwBfIqVYp9wqIxR8fSL2DaVH6jsilgpZ3dRfA6W8k60OwZlJrtgO6Pqn+dLg9WJ/rVDEh",
        "gJR80i/vWhOONwzM6vwsc9Qw9jfOhxDbHaj/5zqYUNsEp+V89qf31VXmZ1x/x0qZ3h2NXeGpxtN4uXB6",
        "Q/PCXvto1TNSSfN/wUtd3nuUCG3JMUT9QuESzR6B30CVPryVo92ZtCilBxy6Yn4i9/0SV1lCsksG3rJG",
        "ff37QaUc/ujqF9HwsHeC3SWkTVhKqUnyRCRKdQIVZGLsIOT2iG7juT6HcHHG2uHh+hbouW/YUN+bySiU",
        "NTjUEqda0J+TvmxDi7PNxE144KIrHg=="
    )).unwrap();
    
    // Tamper with signature content
    if signature.len() > 50 {
        signature[50] ^= 0xFF; // Flip all bits in a single byte
    }
    
    let ak_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApnxF+8clLTkPJYfLThOS
L4QbLZCX1DDZTkPqkh8P6B+J0zNhc5isROiCx9Bl7m0qCj7EEEBabUdtxQMSA3dn
NDQFuLtiIJZtSRgf0YPKPXqBYaRlZ08W16vWvCfScGOas8JpmViZBSVwxKl7wcby
nVxATnQ/WFCCgY/1hB6yrK6EbYtHtvbWah3UsDKUf8k3gpo0nDFYThrDL2NL2BlY
ibAl8Xzte3ArPDG9QQbBRDKV4o5Kl0/lplD0SbY611HTPz8zw7j+AAU2feITT+hl
u1yoxHtwv8i7wrRomOW6xLbbL0Te4zteoIxrefgy5a5gTdqPLxX4WONYn4VhH6VX
SwIDAQAB
-----END PUBLIC KEY-----"#;

    // Decode test data
    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let nonce_decoded = BASE64.decode(nonce).unwrap();

    // Create QuoteVerifier instance
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature).unwrap();

    // Load AK public key
    let public_ak = PKey::public_key_from_pem(ak_public_key.as_bytes())
        .expect("Failed to load AK public key");

    // Try to verify Quote, should fail
    let result = quote_verifier.verify(&quote_bytes, &public_ak, Some(&nonce_decoded));
    assert!(result.is_err(), "Verification should fail with invalid signature {:?}", result);
    
    // Check error type and message
    if let Err(err) = result {
        if let PluginError::InputError(msg) = err {
            assert!(
                msg.contains("signature does not match data"),
                "Error message should mention signature verification failure"
            );
        } else {
            panic!("Expected InputError, got different error type: {:?}", err);
        }
    }
}

// Test Objective: Verify Nonce matching functionality
// Expected Result: Verification fails, returns ValidationError
#[test]
fn test_quote_verification_with_invalid_nonce() {
    
    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABCV662BHW/aRaFuDiq++uke",
        "AAAACAb8fKYekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );
    
    let signature = concat!(
        "ABQACwEAYoLBwBfIqVYp9wqIxR8fSL2DaVH6jsilgpZ3dRfA6W8k60OwZlJrtgO6Pqn+dLg9WJ/rVDEh",
        "gJR80i/vWhOONwzM6vwsc9Qw9jfOhxDbHaj/5zqYUNsEp+V89qf31VXmZ1x/x0qZ3h2NXeGpxtN4uXB6",
        "Q/PCXvto1TNSSfN/wUtd3nuUCG3JMUT9QuESzR6B30CVPryVo92ZtCilBxy6Yn4i9/0SV1lCsksG3rJG",
        "ff37QaUc/ujqF9HwsHeC3SWkTVhKqUnyRCRKdQIVZGLsIOT2iG7juT6HcHHG2uHh+hbouW/YUN+bySiU",
        "NTjUEqda0J+TvmxDi7PNxE144KIrHg=="
    );
    
    // Using mismatched nonce (original nonce: "leutgR1v2kWhbg4qvvrpHg==")
    let incorrect_nonce = "VGhpc0lzQURpZmZlcmVudE5vbmNlVmFsdWU=";
    
    let ak_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApnxF+8clLTkPJYfLThOS
L4QbLZCX1DDZTkPqkh8P6B+J0zNhc5isROiCx9Bl7m0qCj7EEEBabUdtxQMSA3dn
NDQFuLtiIJZtSRgf0YPKPXqBYaRlZ08W16vWvCfScGOas8JpmViZBSVwxKl7wcby
nVxATnQ/WFCCgY/1hB6yrK6EbYtHtvbWah3UsDKUf8k3gpo0nDFYThrDL2NL2BlY
ibAl8Xzte3ArPDG9QQbBRDKV4o5Kl0/lplD0SbY611HTPz8zw7j+AAU2feITT+hl
u1yoxHtwv8i7wrRomOW6xLbbL0Te4zteoIxrefgy5a5gTdqPLxX4WONYn4VhH6VX
SwIDAQAB
-----END PUBLIC KEY-----"#;

    // Decode test data
    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let signature_bytes = BASE64.decode(signature).unwrap();
    let incorrect_nonce_decoded = BASE64.decode(incorrect_nonce).unwrap();

    // Create QuoteVerifier instance
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();

    // Load AK public key
    let public_ak = PKey::public_key_from_pem(ak_public_key.as_bytes())
        .expect("Failed to load AK public key");

    // Try to verify with mismatched nonce, should fail
    let result = quote_verifier.verify(&quote_bytes, &public_ak, Some(&incorrect_nonce_decoded));
    assert!(result.is_err(), "Verification should fail with incorrect nonce");
    
    // Check error type and message
    if let Err(err) = result {
        if let PluginError::InputError(msg) = err {
            assert!(msg.contains("Nonce"), "Error message should mention nonce mismatch");
        } else {
            panic!("Expected InputError, got different error type");
        }
    }
}
