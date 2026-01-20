//! # Falcon Post-Quantum Digital Signature Scheme
//!
//! This crate provides safe Rust bindings for the Falcon signature scheme,
//! a NIST Post-Quantum Cryptography finalist.
//!
//! ## Features
//!
//! - **Type-safe API**: Generic parameter sets prevent mixing Falcon-512 and Falcon-1024 keys
//! - **WASM compatible**: Works in WebAssembly with entropy injection from JavaScript
//! - **Zeroization**: Private key material is zeroized on drop
//! - **No heap allocations in core operations**: Temporary buffers are stack-allocated
//!
//! ## Quick Start
//!
//! ```
//! use falcon::{Falcon512, KeyPair, SignatureFormat};
//!
//! // Generate a key pair from a seed (deterministic)
//! let seed = [0x42u8; 48];
//! let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = keypair.sign_with_seed(message, SignatureFormat::Compressed, &seed).unwrap();
//!
//! // Verify the signature
//! assert!(keypair.public_key().verify(message, &signature).unwrap());
//! ```
//!
//! ## Parameter Sets
//!
//! Falcon supports two parameter sets:
//!
//! | Parameter Set | Security Level | Private Key | Public Key | Signature (avg) |
//! |---------------|---------------|-------------|------------|-----------------|
//! | Falcon-512    | 128-bit       | 1,281 bytes | 897 bytes  | ~666 bytes      |
//! | Falcon-1024   | 256-bit       | 2,305 bytes | 1,793 bytes| ~1,261 bytes    |
//!
//! ## Signature Formats
//!
//! - **Compressed**: Variable length, smallest on average
//! - **Padded**: Fixed length, slightly larger
//! - **ConstantTime**: Fixed length, largest, constant-time processing
//!
//! ## WASM Usage
//!
//! In WASM environments, you need to provide entropy from JavaScript:
//!
//! ```ignore
//! // JavaScript
//! const entropy = crypto.getRandomValues(new Uint8Array(48));
//! const keypair = new Falcon512KeyPair(entropy);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod keypair;
mod params;
mod shake256;
mod signature;

/// NIST KAT (Known Answer Test) support.
pub mod kat;

#[cfg(feature = "wasm")]
mod wasm;

// Re-export main types
pub use error::{Error, Result};
pub use keypair::{ExpandedPrivateKey, KeyPair, PrivateKey, PublicKey};
pub use params::{Falcon1024, Falcon512, FalconParams};
pub use shake256::{Shake256, Shake256Rng};
pub use signature::{Signature, SignatureFormat};

/// Re-export of the raw FFI bindings for advanced users.
pub mod sys {
    pub use falcon_sys::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_keygen_sign_verify() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        let message = b"Test message for Falcon-512";
        let signature = keypair
            .sign_with_seed(message, SignatureFormat::Compressed, &seed)
            .unwrap();

        assert!(keypair.public_key().verify(message, &signature).unwrap());
    }

    #[test]
    fn test_falcon1024_keygen_sign_verify() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon1024>::generate_from_seed(&seed).unwrap();

        let message = b"Test message for Falcon-1024";
        let signature = keypair
            .sign_with_seed(message, SignatureFormat::Padded, &seed)
            .unwrap();

        assert!(keypair.public_key().verify(message, &signature).unwrap());
    }

    #[test]
    fn test_signature_formats() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();
        let message = b"Format test";

        for format in [
            SignatureFormat::Compressed,
            SignatureFormat::Padded,
            SignatureFormat::ConstantTime,
        ] {
            let sig = keypair.sign_with_seed(message, format, &seed).unwrap();
            assert!(keypair.public_key().verify(message, &sig).unwrap());
        }
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let signature = keypair
            .sign_with_seed(message, SignatureFormat::Compressed, &seed)
            .unwrap();

        assert!(!keypair
            .public_key()
            .verify(wrong_message, &signature)
            .unwrap());
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [0x42u8; 48];

        let keypair1 = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();
        let keypair2 = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        assert_eq!(
            keypair1.private_key().as_bytes(),
            keypair2.private_key().as_bytes()
        );
        assert_eq!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        let privkey_bytes = keypair.private_key().as_bytes().to_vec();
        let pubkey_bytes = keypair.public_key().as_bytes().to_vec();

        let privkey2 = PrivateKey::<Falcon512>::from_bytes(&privkey_bytes).unwrap();
        let pubkey2 = PublicKey::<Falcon512>::from_bytes(&pubkey_bytes).unwrap();

        // Verify derived public key matches
        let derived_pubkey = privkey2.public_key().unwrap();
        assert_eq!(derived_pubkey.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn test_expanded_key_signing() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        let expanded = keypair.private_key().expand().unwrap();

        let message = b"Expanded key test";
        let sig = expanded
            .sign_with_seed(message, SignatureFormat::Compressed, &seed)
            .unwrap();

        assert!(keypair.public_key().verify(message, &sig).unwrap());
    }

    #[test]
    fn test_public_key_derivation() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        // Derive public key from private key
        let derived_pubkey = keypair.private_key().public_key().unwrap();

        // Should match the original public key
        assert_eq!(
            keypair.public_key().as_bytes(),
            derived_pubkey.as_bytes()
        );
    }

    #[test]
    fn test_verify_strict() {
        let seed = [0x42u8; 48];
        let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();

        let message = b"Test message";
        let signature = keypair
            .sign_with_seed(message, SignatureFormat::Compressed, &seed)
            .unwrap();

        // Should succeed
        assert!(keypair
            .public_key()
            .verify_strict(message, &signature)
            .is_ok());

        // Should fail
        assert!(keypair
            .public_key()
            .verify_strict(b"Wrong message", &signature)
            .is_err());
    }
}
