/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use openssl::pkey::PKey;
use serde_json::Value;
use tpm_common_verifier::{QuoteVerifier, PcrValues, AlgorithmId};
use plugin_manager::PluginError;

#[test]
fn test_pcr_verify_with_valid_quote() {
    // Test data
    let nonce = "Rlvy7qyqLdVHgkAcUl3gbw==";

    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABBGW/LurKot1UeCQBxSXeBv",
        "AAAACAemgS0ekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );
    
    let signature = concat!(
        "ABQACwEAMbPyNICmUBuQQNU3jNEnexOaTSLV1sXLRMEvZtxVvB9bvcRCUqkhW/5IdarIlsBoeKos+fwA",
        "tdY/rHmGkc5WJVQbuq6CiT72058oSscYV1wt7phle2ipS9sA9DNm6U6Fja3D4fdoP7BiHwMq16v0VDG1",
        "0lgbtqlqYjKMkmOsRVpaVgm06ujfOLRiATCoT7VYazOl2yYC18ErsqsSFZAuWkusdLHnm1H9z9orY37r",
        "3Ub20CTqHs7dcbUAtGXlNYQCnwl79nZcHfnHkJr5mXtxfCk0bKr8mr1FTtmcfQEYKsn90nK5I7Aa7KTI",
        "ZBtf9LRB1coblcA+ZnmdkZXV21gShQ=="
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

    let pcr_str = r#"{
        "pcrs": {
            "hash_alg": "sha256",
            "pcr_values": [
                {
                    "pcr_index": 0,
                    "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83dd0c0592fd9b1c3b16770c35"
                },
                {
                    "pcr_index": 1, 
                    "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be"
                },
                {
                    "pcr_index": 2,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 3,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 4,
                    "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931"
                },
                {
                    "pcr_index": 5,
                    "pcr_value": "66121d5bcdb8ab6d628b49827590ac8e1f2f09e26aa2d1dd1cfec5358854cd3a"
                },
                {
                    "pcr_index": 6,
                    "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                },
                {
                    "pcr_index": 7,
                    "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b"
                }
            ]
        }
    }"#;

    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let signature_bytes = BASE64.decode(signature).unwrap();
    let nonce_decoded = BASE64.decode(nonce).unwrap();
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();
    let public_ak = PKey::public_key_from_pem(ak_public_key.as_bytes())
        .expect("Failed to load AK public key");

    assert!(quote_verifier.verify(&quote_bytes, &public_ak, Some(&nonce_decoded)).is_ok());

    let pcr_json: Value = serde_json::from_str(pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json["pcrs"]).unwrap();
    
    let verify_result = pcr_values.verify(&quote_verifier);
    assert!(verify_result.is_ok(), "PCR verification failed");
}

// Test Objective: Verify ability to detect mismatched PCR digests
// Expected Result: Verification fails with digest mismatch error
#[test]
fn test_pcr_digest_with_invalid_pcr_digest() {
    // Test data
    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABBGW/LurKot1UeCQBxSXeBv",
        "AAAACAemgS0ekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );

    let signature = concat!(
        "ABQACwEAMbPyNICmUBuQQNU3jNEnexOaTSLV1sXLRMEvZtxVvB9bvcRCUqkhW/5IdarIlsBoeKos+fwA",
        "tdY/rHmGkc5WJVQbuq6CiT72058oSscYV1wt7phle2ipS9sA9DNm6U6Fja3D4fdoP7BiHwMq16v0VDG1",
        "0lgbtqlqYjKMkmOsRVpaVgm06ujfOLRiATCoT7VYazOl2yYC18ErsqsSFZAuWkusdLHnm1H9z9orY37r",
        "3Ub20CTqHs7dcbUAtGXlNYQCnwl79nZcHfnHkJr5mXtxfCk0bKr8mr1FTtmcfQEYKsn90nK5I7Aa7KTI",
        "ZBtf9LRB1coblcA+ZnmdkZXV21gShQ=="
    );

    // PCR values with modified PCR values that will not match quote digest
    let modified_pcr_str = r#"{
        "hash_alg": "sha256",
        "pcr_values": [
            {
                "pcr_index": 0,
                "pcr_value": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            {
                "pcr_index": 1,
                "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0bb154fe494a1dda198da29be"
            },
            {
                "pcr_index": 2,
                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
            },
            {
                "pcr_index": 3,
                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
            },
            {
                "pcr_index": 4,
                "pcr_value": "8ed12c415056362c7a4d403e6e2acadf090e78bfb4798a87b0a327c838064931"
            },
            {
                "pcr_index": 5,
                "pcr_value": "66121d5bcdb8ab6d628b49827590ac8e1f2f09e26aa2d1dd1cfec5358854cd3a"
            },
            {
                "pcr_index": 6,
                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
            },
            {
                "pcr_index": 7,
                "pcr_value": "74fa2c067892faa74bfb0cafacc4c7102dd2c9cf73efdfa41f07fdfc7c1eea1b"
            }
        ]
    }"#;

    // Setup test
    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let signature_bytes = BASE64.decode(signature).unwrap();
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();
    let pcr_json: Value = serde_json::from_str(modified_pcr_str).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();

    // Verify PCR digest mismatch is detected
    let verify_result = pcr_values.verify(&quote_verifier);

    // Verification should fail
    assert!(verify_result.is_err(), "PCR verification should fail with mismatched digest");

    // Check error message
    if let Err(PluginError::InputError(msg)) = verify_result {
        assert!(msg.contains("PCR digest mismatch"),
                "Error message should mention PCR digest mismatch");
    } else {
        panic!("Expected InputError with 'PCR digest mismatch' message");
    }
}

// Test Objective: Verify algorithm mismatch detection between PCR values and Quote
// Expected Result: Verification fails with algorithm mismatch error
#[test]
fn test_pcr_algorithm_mismatch_with_invalid_pcr_algorithm() {
    // Test data with SHA-256 algorithm
    let quote_data = concat!(
        "/1RDR4AYACIAC4AUbRH7b7Tx6NWCEXXAfTkXtGVl28mbdO8mgjtmLc3dABBGW/LurKot1UeCQBxSXeBv",
        "AAAACAemgS0ekmZKo0yPswG4TAdhkO8QbgAAAAEACwP/AAAAIPM1m5EaC4D9tYvMGKh/xRAgDvxo8KTn",
        "yLeNljrSeBMY"
    );

    let signature = concat!(
        "ABQACwEAMbPyNICmUBuQQNU3jNEnexOaTSLV1sXLRMEvZtxVvB9bvcRCUqkhW/5IdarIlsBoeKos+fwA",
        "tdY/rHmGkc5WJVQbuq6CiT72058oSscYV1wt7phle2ipS9sA9DNm6U6Fja3D4fdoP7BiHwMq16v0VDG1",
        "0lgbtqlqYjKMkmOsRVpaVgm06ujfOLRiATCoT7VYazOl2yYC18ErsqsSFZAuWkusdLHnm1H9z9orY37r",
        "3Ub20CTqHs7dcbUAtGXlNYQCnwl79nZcHfnHkJr5mXtxfCk0bKr8mr1FTtmcfQEYKsn90nK5I7Aa7KTI",
        "ZBtf9LRB1coblcA+ZnmdkZXV21gShQ=="
    );

    // PCR values with SHA-1 algorithm (different from Quote's SHA-256)
    let pcr_str_sha1 = r#"{
        "hash_alg": "sha1",
        "pcr_values": [
            {
                "pcr_index": 0,
                "pcr_value": "9d7504bb0d32f62d43310f38df37cdd5e42bdb83"
            },
            {
                "pcr_index": 1,
                "pcr_value": "38846271e2a86d6bf43ef388be2d1cb83a89f1c0"
            },
            {
                "pcr_index": 2,
                "pcr_value": "3d458cfe55cc03ea1f443f1562beec8df51c75e1"
            }
        ]
    }"#;

    // Setup test
    let quote_bytes = BASE64.decode(quote_data).unwrap();
    let signature_bytes = BASE64.decode(signature).unwrap();
    let quote_verifier = QuoteVerifier::new(&quote_bytes, &signature_bytes).unwrap();
    let pcr_json: Value = serde_json::from_str(pcr_str_sha1).unwrap();
    let pcr_values = PcrValues::from_json(&pcr_json).unwrap();

    // Verify algorithm mismatch is detected
    let verify_result = pcr_values.verify(&quote_verifier);

    // Verification should fail
    assert!(verify_result.is_err(), "PCR verification should fail with algorithm mismatch");

    // Check error message
    if let Err(PluginError::InputError(msg)) = verify_result {
        println!("Error message: {}", msg);
        assert!(msg.contains("mismatch"), 
                "Error message should mention mismatch");
    } else {
        panic!("Expected InputError with algorithm mismatch message");
    }

    // Additional verification: confirm the quote uses SHA-256
    let quote_hash_alg = quote_verifier.get_hash_algorithm();
    assert_eq!(quote_hash_alg, AlgorithmId::Sha256, "Quote should use SHA-256 algorithm");
}
