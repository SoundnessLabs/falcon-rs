//! Integration tests for Falcon Smart Account.

#![cfg(feature = "testutils")]

use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

use soroban_falcon_smart_account::{FalconSmartAccount, FalconSmartAccountClient};
use soroban_falcon_verifier::{FalconVerifierContract, FalconVerifierContractClient};

const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");

#[test]
fn test_smart_account_initialization() {
    let env = Env::default();

    // Deploy contracts
    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let smart_account_id = env.register(FalconSmartAccount, ());
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    // Decode pubkey
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

    // Initialize
    client.initialize(&pubkey, &falcon_verifier_id);

    // Verify stored values
    assert_eq!(client.get_pubkey(), pubkey);
    assert_eq!(client.get_verifier(), falcon_verifier_id);
}

#[test]
fn test_invalid_pubkey_size_on_init() {
    let env = Env::default();

    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let smart_account_id = env.register(FalconSmartAccount, ());
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    let bad_pubkey = Bytes::from_slice(&env, &[0u8; 100]);
    let result = client.try_initialize(&bad_pubkey, &falcon_verifier_id);
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_double_init_fails() {
    let env = Env::default();

    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let smart_account_id = env.register(FalconSmartAccount, ());
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    let pubkey = Bytes::from_slice(&env, &[9u8; 897]); // Header byte 9 for Falcon-512

    client.initialize(&pubkey, &falcon_verifier_id);
    client.initialize(&pubkey, &falcon_verifier_id); // Should panic
}

#[test]
fn test_falcon_verifier_direct() {
    // Sanity check: verify the Falcon verifier works directly
    let env = Env::default();

    if TEST_PUBKEY_HEX.is_empty() {
        return;
    }

    let falcon_verifier_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &falcon_verifier_id);

    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX.trim()).expect("Invalid signature hex");

    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, b"Hello, Falcon!");
    let signature = Bytes::from_slice(&env, &sig_bytes);

    let result = client.verify(&pubkey, &message, &signature);
    assert!(result, "Falcon verification should succeed");
}
