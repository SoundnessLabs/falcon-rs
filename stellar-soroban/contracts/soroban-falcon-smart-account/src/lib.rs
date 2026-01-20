#![no_std]

//! Falcon-512 Smart Account Verifier for Soroban.
//!
//! Implements a signature verifier compatible with OpenZeppelin's Soroban Smart Accounts.
//! Delegates to an external Falcon verifier contract.

use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Address, Bytes, Env, Symbol};

const FALCON_VERIFIER_KEY: Symbol = symbol_short!("FV_ADDR");

pub const FALCON_512_PUBKEY_SIZE: u32 = 897;
pub const FALCON_SIG_MIN_SIZE: u32 = 42;
pub const FALCON_SIG_MAX_SIZE: u32 = 700;
pub const FALCON_512_SIG_PADDED_SIZE: u32 = 666;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    InvalidPublicKeySize = 2,
    InvalidSignatureSize = 3,
    InvalidHashSize = 4,
    AlreadyInitialized = 5,
}

#[contract]
pub struct FalconSmartAccountVerifier;

mod falcon_verifier {
    use soroban_sdk::{contractclient, Bytes, Env};

    #[contractclient(name = "FalconVerifierClient")]
    pub trait FalconVerifier {
        fn verify(env: Env, public_key: Bytes, message: Bytes, signature: Bytes) -> bool;
    }
}

#[contractimpl]
impl FalconSmartAccountVerifier {
    pub fn initialize(env: Env, falcon_verifier: Address) -> Result<(), Error> {
        if env.storage().instance().has(&FALCON_VERIFIER_KEY) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&FALCON_VERIFIER_KEY, &falcon_verifier);
        Ok(())
    }

    pub fn get_falcon_verifier(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&FALCON_VERIFIER_KEY)
            .ok_or(Error::NotInitialized)
    }

    /// Verify a Falcon-512 signature (Smart Account interface).
    pub fn verify(env: Env, payload: Bytes, key_data: Bytes, sig_data: Bytes) -> bool {
        if key_data.len() != FALCON_512_PUBKEY_SIZE {
            return false;
        }
        if sig_data.len() < FALCON_SIG_MIN_SIZE || sig_data.len() > FALCON_SIG_MAX_SIZE {
            return false;
        }

        let falcon_verifier_addr: Address = match env.storage().instance().get(&FALCON_VERIFIER_KEY)
        {
            Some(addr) => addr,
            None => return false,
        };

        let client = falcon_verifier::FalconVerifierClient::new(&env, &falcon_verifier_addr);
        client.verify(&key_data, &payload, &sig_data)
    }

    pub fn validate_inputs(env: Env, hash: Bytes, key_data: Bytes, sig_data: Bytes) -> bool {
        let _ = env;
        hash.len() == 32
            && key_data.len() == FALCON_512_PUBKEY_SIZE
            && sig_data.len() >= FALCON_SIG_MIN_SIZE
            && sig_data.len() <= FALCON_SIG_MAX_SIZE
    }

    pub fn get_expected_sizes(env: Env) -> (u32, u32, u32, u32, u32) {
        let _ = env;
        (32, FALCON_512_PUBKEY_SIZE, FALCON_SIG_MIN_SIZE, FALCON_SIG_MAX_SIZE, FALCON_512_SIG_PADDED_SIZE)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_contract_initialization() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccountVerifier, ());
        let client = FalconSmartAccountVerifierClient::new(&env, &contract_id);

        let falcon_verifier_addr = Address::generate(&env);
        client.initialize(&falcon_verifier_addr);

        let stored_addr = client.get_falcon_verifier();
        assert_eq!(stored_addr, falcon_verifier_addr);
    }

    #[test]
    fn test_validate_inputs() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccountVerifier, ());
        let client = FalconSmartAccountVerifierClient::new(&env, &contract_id);

        let hash = Bytes::from_array(&env, &[0u8; 32]);
        let pubkey = Bytes::from_array(&env, &[0u8; 897]);
        let sig = Bytes::from_array(&env, &[0u8; 666]);

        assert!(client.validate_inputs(&hash, &pubkey, &sig));
        assert!(!client.validate_inputs(&Bytes::from_array(&env, &[0u8; 16]), &pubkey, &sig));
        assert!(!client.validate_inputs(&hash, &Bytes::from_array(&env, &[0u8; 100]), &sig));
        assert!(!client.validate_inputs(&hash, &pubkey, &Bytes::from_array(&env, &[0u8; 10])));
    }

    #[test]
    fn test_get_expected_sizes() {
        let env = Env::default();
        let contract_id = env.register(FalconSmartAccountVerifier, ());
        let client = FalconSmartAccountVerifierClient::new(&env, &contract_id);

        let (hash_size, pubkey_size, sig_min, sig_max, sig_padded) = client.get_expected_sizes();
        assert_eq!(hash_size, 32);
        assert_eq!(pubkey_size, 897);
        assert_eq!(sig_min, 42);
        assert_eq!(sig_max, 700);
        assert_eq!(sig_padded, 666);
    }
}
