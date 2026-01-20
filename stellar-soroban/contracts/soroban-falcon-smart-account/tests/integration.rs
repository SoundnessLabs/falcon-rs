//! Integration tests for Falcon Smart Account Verifier.
//!
//! These tests verify the full end-to-end flow:
//! 1. Deploy Falcon verifier contract
//! 2. Deploy Smart Account verifier contract
//! 3. Initialize Smart Account verifier with Falcon verifier address
//! 4. Verify signatures through the Smart Account interface

#![cfg(feature = "testutils")]

use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

// Import both contracts
use soroban_falcon_smart_account::{FalconSmartAccountVerifier, FalconSmartAccountVerifierClient};
use soroban_falcon_verifier::{FalconVerifierContract, FalconVerifierContractClient};

// Test fixtures - same as used in falcon verifier tests
const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");
const TEST_MESSAGE: &[u8] = b"Hello, Falcon!";

/// Test the full integration flow with real Falcon signatures.
///
/// This test:
/// 1. Deploys the Falcon verifier contract
/// 2. Deploys the Smart Account verifier contract
/// 3. Initializes the SA verifier with the Falcon verifier address
/// 4. Verifies a real Falcon-512 signature through the SA interface
#[test]
fn test_full_integration_flow() {
    let env = Env::default();

    // Skip if fixtures don't exist
    if TEST_PUBKEY_HEX.is_empty() {
        println!("Skipping test - fixtures not generated yet");
        return;
    }

    // 1. Deploy Falcon verifier contract
    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let falcon_client = FalconVerifierContractClient::new(&env, &falcon_verifier_id);

    // 2. Deploy Smart Account verifier contract
    let sa_verifier_id = env.register(FalconSmartAccountVerifier, ());
    let sa_client = FalconSmartAccountVerifierClient::new(&env, &sa_verifier_id);

    // 3. Initialize SA verifier with Falcon verifier address
    sa_client.initialize(&falcon_verifier_id);

    // Verify initialization
    let stored_addr = sa_client.get_falcon_verifier();
    assert_eq!(stored_addr, falcon_verifier_id);

    // 4. Decode test fixtures
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX.trim()).expect("Invalid signature hex");

    // Convert to Soroban Bytes
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, TEST_MESSAGE);
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // 5. First verify directly with Falcon verifier (sanity check)
    let direct_result = falcon_client.verify(&pubkey, &message, &signature);
    assert!(direct_result, "Direct Falcon verification should succeed");

    // 6. Now verify through Smart Account verifier
    // In the Smart Account flow, the "hash" is what gets signed
    // Here we're using the message directly as the hash for testing
    let result = sa_client.verify(&message, &pubkey, &signature);
    assert!(result, "Smart Account verification should succeed");

    // 7. Test with wrong message - should fail
    let wrong_message = Bytes::from_slice(&env, b"Wrong message!!!");
    let result = sa_client.verify(&wrong_message, &pubkey, &signature);
    assert!(!result, "Verification with wrong message should fail");

    // 8. Test with invalid pubkey size - should fail
    let bad_pubkey = Bytes::from_slice(&env, &[0u8; 100]);
    let result = sa_client.verify(&message, &bad_pubkey, &signature);
    assert!(!result, "Verification with invalid pubkey should fail");

    // 9. Test with invalid signature size - should fail
    let bad_sig = Bytes::from_slice(&env, &[0u8; 10]);
    let result = sa_client.verify(&message, &pubkey, &bad_sig);
    assert!(!result, "Verification with invalid signature should fail");
}

/// Test that verification fails when contract is not initialized.
#[test]
fn test_verify_without_initialization() {
    let env = Env::default();

    // Deploy only the Smart Account verifier (not initialized)
    let sa_verifier_id = env.register(FalconSmartAccountVerifier, ());
    let sa_client = FalconSmartAccountVerifierClient::new(&env, &sa_verifier_id);

    // Try to verify without initialization - should return false
    let hash = Bytes::from_slice(&env, &[0u8; 32]);
    let pubkey = Bytes::from_slice(&env, &[0u8; 897]);
    let signature = Bytes::from_slice(&env, &[0u8; 666]);

    let result = sa_client.verify(&hash, &pubkey, &signature);
    assert!(!result, "Verification should fail when not initialized");
}

/// Test double initialization prevention.
#[test]
#[should_panic(expected = "Error(Contract, #5)")] // AlreadyInitialized = 5
fn test_double_initialization_fails() {
    let env = Env::default();

    let falcon_verifier_addr = Address::generate(&env);
    let sa_verifier_id = env.register(FalconSmartAccountVerifier, ());
    let sa_client = FalconSmartAccountVerifierClient::new(&env, &sa_verifier_id);

    // First initialization should succeed
    sa_client.initialize(&falcon_verifier_addr);

    // Second initialization should fail
    let another_addr = Address::generate(&env);
    sa_client.initialize(&another_addr);
}

/// Test with a 32-byte hash (simulating Smart Account authorization payload).
#[test]
fn test_with_32_byte_hash() {
    let env = Env::default();

    // Deploy contracts
    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let sa_verifier_id = env.register(FalconSmartAccountVerifier, ());
    let sa_client = FalconSmartAccountVerifierClient::new(&env, &sa_verifier_id);

    // Initialize
    sa_client.initialize(&falcon_verifier_id);

    // Validate inputs with a 32-byte hash
    let hash_32 = Bytes::from_slice(&env, &[0xAB; 32]);
    let pubkey = Bytes::from_slice(&env, &[0u8; 897]);
    let signature = Bytes::from_slice(&env, &[0u8; 666]);

    // validate_inputs should return true for correct sizes
    let valid = sa_client.validate_inputs(&hash_32, &pubkey, &signature);
    assert!(valid, "32-byte hash should be valid input");

    // Invalid hash sizes should fail validation
    let hash_16 = Bytes::from_slice(&env, &[0xAB; 16]);
    let invalid = sa_client.validate_inputs(&hash_16, &pubkey, &signature);
    assert!(!invalid, "16-byte hash should be invalid");

    let hash_64 = Bytes::from_slice(&env, &[0xAB; 64]);
    let invalid = sa_client.validate_inputs(&hash_64, &pubkey, &signature);
    assert!(!invalid, "64-byte hash should be invalid");
}

/// Test get_expected_sizes returns correct values.
#[test]
fn test_expected_sizes() {
    let env = Env::default();

    let sa_verifier_id = env.register(FalconSmartAccountVerifier, ());
    let sa_client = FalconSmartAccountVerifierClient::new(&env, &sa_verifier_id);

    let (hash_size, pubkey_size, sig_min, sig_max, sig_padded) = sa_client.get_expected_sizes();

    assert_eq!(hash_size, 32, "Hash size should be 32");
    assert_eq!(pubkey_size, 897, "Pubkey size should be 897");
    assert_eq!(sig_min, 42, "Min signature size should be 42");
    assert_eq!(sig_max, 700, "Max signature size should be 700");
    assert_eq!(sig_padded, 666, "Padded signature size should be 666");
}
