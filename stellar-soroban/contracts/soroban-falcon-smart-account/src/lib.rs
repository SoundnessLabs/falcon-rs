#![no_std]

//! Falcon-512 Smart Account for Soroban.
//!
//! Implements `CustomAccountInterface` for post-quantum signature authentication.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl,
    crypto::Hash,
    symbol_short, Address, Bytes, Env, Symbol, Vec,
};

const FALCON_PUBKEY_KEY: Symbol = symbol_short!("F_PUBKEY");
const FALCON_VERIFIER_KEY: Symbol = symbol_short!("F_VERIFY");

pub const FALCON_512_PUBKEY_SIZE: usize = 897;
pub const FALCON_SIG_MIN_SIZE: u32 = 42;
pub const FALCON_SIG_MAX_SIZE: u32 = 700;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidPublicKeySize = 3,
    InvalidSignatureSize = 4,
    VerificationFailed = 5,
}

mod falcon_verifier {
    use soroban_sdk::{contractclient, Bytes, Env};

    #[contractclient(name = "FalconVerifierClient")]
    pub trait FalconVerifier {
        fn verify(env: Env, public_key: Bytes, message: Bytes, signature: Bytes) -> bool;
    }
}

#[contract]
pub struct FalconSmartAccount;

#[contractimpl]
impl FalconSmartAccount {
    /// Initialize the smart account with a Falcon public key and verifier contract.
    pub fn initialize(
        env: Env,
        falcon_pubkey: Bytes,
        falcon_verifier: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&FALCON_PUBKEY_KEY) {
            return Err(Error::AlreadyInitialized);
        }
        if falcon_pubkey.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return Err(Error::InvalidPublicKeySize);
        }

        env.storage()
            .instance()
            .set(&FALCON_PUBKEY_KEY, &falcon_pubkey);
        env.storage()
            .instance()
            .set(&FALCON_VERIFIER_KEY, &falcon_verifier);
        Ok(())
    }

    /// Get the stored Falcon public key.
    pub fn get_pubkey(env: Env) -> Result<Bytes, Error> {
        env.storage()
            .instance()
            .get(&FALCON_PUBKEY_KEY)
            .ok_or(Error::NotInitialized)
    }

    /// Get the Falcon verifier contract address.
    pub fn get_verifier(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&FALCON_VERIFIER_KEY)
            .ok_or(Error::NotInitialized)
    }
}

#[contractimpl]
impl CustomAccountInterface for FalconSmartAccount {
    /// Use Bytes directly for the signature - simpler SCVal encoding.
    type Signature = Bytes;
    type Error = Error;

    /// Verify authorization using Falcon-512 signature.
    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Bytes,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Get stored public key
        let pubkey: Bytes = env
            .storage()
            .instance()
            .get(&FALCON_PUBKEY_KEY)
            .ok_or(Error::NotInitialized)?;

        // Get verifier contract address
        let verifier_addr: Address = env
            .storage()
            .instance()
            .get(&FALCON_VERIFIER_KEY)
            .ok_or(Error::NotInitialized)?;

        // Validate signature size
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE || sig_len > FALCON_SIG_MAX_SIZE {
            return Err(Error::InvalidSignatureSize);
        }

        // Convert the 32-byte hash to Bytes for the verifier
        let payload_bytes = Bytes::from_slice(&env, signature_payload.to_array().as_slice());

        // Call the external Falcon verifier contract
        let client = falcon_verifier::FalconVerifierClient::new(&env, &verifier_addr);
        let is_valid = client.verify(&pubkey, &payload_bytes, &signature);

        if is_valid {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_initialization() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccount, ());
        let client = FalconSmartAccountClient::new(&env, &contract_id);

        let pubkey = Bytes::from_array(&env, &[0u8; 897]);
        let verifier_addr = Address::generate(&env);

        client.initialize(&pubkey, &verifier_addr);

        assert_eq!(client.get_pubkey(), pubkey);
        assert_eq!(client.get_verifier(), verifier_addr);
    }

    #[test]
    fn test_invalid_pubkey_size() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccount, ());
        let client = FalconSmartAccountClient::new(&env, &contract_id);

        let bad_pubkey = Bytes::from_array(&env, &[0u8; 100]);
        let verifier_addr = Address::generate(&env);

        let result = client.try_initialize(&bad_pubkey, &verifier_addr);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #2)")]
    fn test_double_init() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccount, ());
        let client = FalconSmartAccountClient::new(&env, &contract_id);

        let pubkey = Bytes::from_array(&env, &[0u8; 897]);
        let verifier_addr = Address::generate(&env);

        client.initialize(&pubkey, &verifier_addr);
        client.initialize(&pubkey, &verifier_addr); // Should panic
    }
}
