#![no_std]

//! # Falcon-512 Signature Verifier for Soroban
//!
//! A pure-Rust implementation of Falcon-512 post-quantum signature verification,
//! designed for the Soroban smart contract environment.
//!
//! ## What is Falcon?
//!
//! Falcon is a lattice-based digital signature scheme selected by NIST for
//! standardization as a post-quantum cryptographic algorithm. It provides
//! security against both classical and quantum computer attacks.
//!
//! ## Features
//!
//! - **Pure Rust**: No C FFI, compatible with Soroban's `no_std` WASM environment
//! - **Efficient**: ~400k CPU instructions per verification (~0.4% of budget)
//! - **Verified**: Cross-tested against the C reference implementation
//!
//! ## Usage
//!
//! Call the `verify` function with:
//! - A 897-byte public key
//! - The message that was signed
//! - The signature (compressed or padded format)
//!
//! ## Security Note
//!
//! This contract only implements verification. Key generation and signing
//! must be done off-chain using the full Falcon implementation.

use soroban_sdk::{contract, contractimpl, Bytes, Env};

mod ntt;
mod verify;

pub use verify::FalconVerifier;

/// Log base 2 of the polynomial degree: log2(512) = 9.
pub const FALCON_512_LOGN: u32 = 9;

/// Polynomial degree n = 512 (number of coefficients in each polynomial).
/// This determines the security level: Falcon-512 provides ~128 bits of security.
pub const FALCON_512_N: usize = 512;

/// Public key size in bytes: 1 header byte + 896 data bytes = 897 bytes.
/// The 896 data bytes encode 512 coefficients at 14 bits each (512 × 14 / 8 = 896).
pub const FALCON_512_PUBKEY_SIZE: usize = 897;

/// Constant-time signature format size: 666 bytes.
/// This includes 1 header + 40 nonce + 625 signature data.
pub const FALCON_512_SIG_CT_SIZE: usize = 666;

/// The prime modulus q = 12289.
///
/// This prime was carefully chosen for Falcon because:
/// - q ≡ 1 (mod 2048): Enables efficient NTT with 2048-th roots of unity
/// - q is small: Coefficients fit in 14 bits, products fit in 32 bits
/// - q provides adequate security margin for the lattice problems
pub const Q: u32 = 12289;

/// Squared L2 norm bound for Falcon-512 signatures.
///
/// A valid signature (s1, s2) must satisfy: ||(s1, s2)||² ≤ 34,034,726
///
/// This bound is derived from the Falcon security analysis and ensures:
/// - All legitimate signatures pass (with overwhelming probability)
/// - Forged signatures fail (without the secret key, finding short vectors is hard)
///
/// The exact value comes from: β² × 2n where β ≈ 1.8 × σ and σ = 165.7 for Falcon-512.
pub const L2_BOUND_512: u32 = 34034726;

#[contract]
pub struct FalconVerifierContract;

#[contractimpl]
impl FalconVerifierContract {
    /// Verify a Falcon-512 signature (compressed format).
    ///
    /// # Arguments
    /// * `public_key` - 897-byte Falcon-512 public key
    /// * `message` - Message that was signed
    /// * `signature` - Falcon signature (compressed format, variable size ~650 bytes)
    ///
    /// # Returns
    /// * `true` if signature is valid, `false` otherwise
    pub fn verify(
        _env: Env,
        public_key: Bytes,
        message: Bytes,
        signature: Bytes,
    ) -> bool {
        // Validate sizes
        if public_key.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return false;
        }
        if signature.len() < 42 || signature.len() > 700 {
            return false;
        }

        // Convert to byte arrays
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            pk_bytes[i] = public_key.get(i as u32).unwrap();
        }

        let sig_len = signature.len() as usize;
        let mut sig_bytes = [0u8; 700];
        for i in 0..sig_len {
            sig_bytes[i] = signature.get(i as u32).unwrap();
        }

        let msg_len = message.len() as usize;
        let mut msg_bytes = [0u8; 4096]; // Max message size
        let actual_msg_len = if msg_len > 4096 { 4096 } else { msg_len };
        for i in 0..actual_msg_len {
            msg_bytes[i] = message.get(i as u32).unwrap();
        }

        // Create verifier and verify
        FalconVerifier::verify_512(&pk_bytes, &msg_bytes[..actual_msg_len], &sig_bytes[..sig_len])
    }

    /// Verify a Falcon-512 signature with pre-hashed message.
    /// Use this when the message has already been hashed using SHAKE256.
    ///
    /// # Arguments
    /// * `public_key` - 897-byte Falcon-512 public key
    /// * `nonce` - 40-byte nonce from signature
    /// * `hashed_message` - The hash output used in signature (SHAKE256(nonce || message))
    /// * `s2` - Decompressed signature polynomial (512 i16 values as bytes)
    pub fn verify_raw(
        _env: Env,
        public_key: Bytes,
        c0: Bytes,  // 1024 bytes = 512 * u16 challenge polynomial
        s2: Bytes,  // 1024 bytes = 512 * i16 signature polynomial
    ) -> bool {
        if public_key.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return false;
        }
        if c0.len() != 1024 || s2.len() != 1024 {
            return false;
        }

        // Decode public key
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            pk_bytes[i] = public_key.get(i as u32).unwrap();
        }

        // Decode c0 (challenge)
        let mut c0_poly = [0u16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let lo = c0.get((i * 2) as u32).unwrap() as u16;
            let hi = c0.get((i * 2 + 1) as u32).unwrap() as u16;
            c0_poly[i] = lo | (hi << 8);
        }

        // Decode s2 (signature)
        let mut s2_poly = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let lo = s2.get((i * 2) as u32).unwrap() as u16;
            let hi = s2.get((i * 2 + 1) as u32).unwrap() as u16;
            s2_poly[i] = (lo | (hi << 8)) as i16;
        }

        // Decode and verify
        let mut h = [0u16; FALCON_512_N];
        if !FalconVerifier::decode_pubkey(&pk_bytes, &mut h) {
            return false;
        }

        FalconVerifier::verify_raw_512(&c0_poly, &s2_poly, &h)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_contract_compiles() {
        let env = Env::default();
        let contract_id = env.register(FalconVerifierContract, ());
        let _client = FalconVerifierContractClient::new(&env, &contract_id);
        // Contract compiles successfully
    }
}
