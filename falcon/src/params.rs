//! Parameter set definitions for Falcon-512 and Falcon-1024.
//!
//! Falcon supports two main parameter sets:
//! - **Falcon-512** (logn=9): 128-bit classical security, smaller keys/signatures
//! - **Falcon-1024** (logn=10): 256-bit classical security, larger keys/signatures

use falcon_sys as ffi;

/// Trait defining Falcon parameter set constants.
///
/// This trait is sealed and cannot be implemented outside this crate.
/// The only valid implementations are [`Falcon512`] and [`Falcon1024`].
pub trait FalconParams: private::Sealed + Clone + Copy + Default {
    /// Logarithm of the degree (9 for Falcon-512, 10 for Falcon-1024).
    const LOGN: u32;

    /// Degree of the polynomial ring (512 or 1024).
    const N: usize = 1 << Self::LOGN;

    /// Private key size in bytes.
    const PRIVKEY_SIZE: usize = ffi::privkey_size(Self::LOGN);

    /// Public key size in bytes.
    const PUBKEY_SIZE: usize = ffi::pubkey_size(Self::LOGN);

    /// Maximum compressed signature size in bytes.
    const SIG_COMPRESSED_MAXSIZE: usize = ffi::sig_compressed_maxsize(Self::LOGN);

    /// Padded signature size (exact) in bytes.
    const SIG_PADDED_SIZE: usize = ffi::sig_padded_size(Self::LOGN);

    /// CT (constant-time) signature size (exact) in bytes.
    const SIG_CT_SIZE: usize = ffi::sig_ct_size(Self::LOGN);

    /// Temporary buffer size for key generation.
    const TMPSIZE_KEYGEN: usize = ffi::tmpsize_keygen(Self::LOGN);

    /// Temporary buffer size for making public key from private.
    const TMPSIZE_MAKEPUB: usize = ffi::tmpsize_makepub(Self::LOGN);

    /// Temporary buffer size for dynamic signing.
    const TMPSIZE_SIGNDYN: usize = ffi::tmpsize_signdyn(Self::LOGN);

    /// Temporary buffer size for tree signing (with expanded key).
    const TMPSIZE_SIGNTREE: usize = ffi::tmpsize_signtree(Self::LOGN);

    /// Temporary buffer size for expanding private key.
    const TMPSIZE_EXPANDPRIV: usize = ffi::tmpsize_expandpriv(Self::LOGN);

    /// Expanded private key size in bytes.
    const EXPANDEDKEY_SIZE: usize = ffi::expandedkey_size(Self::LOGN);

    /// Temporary buffer size for signature verification.
    const TMPSIZE_VERIFY: usize = ffi::tmpsize_verify(Self::LOGN);
}

mod private {
    pub trait Sealed {}
}

/// Falcon-512 parameter set (128-bit classical security).
///
/// This is the recommended parameter set for most applications.
/// It provides smaller keys and signatures while still offering
/// strong post-quantum security.
///
/// # Key and Signature Sizes
/// - Private key: 1,281 bytes
/// - Public key: 897 bytes
/// - Signature: ~666 bytes (compressed, average)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Falcon512;

impl private::Sealed for Falcon512 {}

impl FalconParams for Falcon512 {
    const LOGN: u32 = 9;
}

/// Falcon-1024 parameter set (256-bit classical security).
///
/// This parameter set offers higher security margins at the cost
/// of larger keys and signatures.
///
/// # Key and Signature Sizes
/// - Private key: 2,305 bytes
/// - Public key: 1,793 bytes
/// - Signature: ~1,261 bytes (compressed, average)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Falcon1024;

impl private::Sealed for Falcon1024 {}

impl FalconParams for Falcon1024 {
    const LOGN: u32 = 10;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_sizes() {
        assert_eq!(Falcon512::LOGN, 9);
        assert_eq!(Falcon512::N, 512);
        assert_eq!(Falcon512::PRIVKEY_SIZE, 1281);
        assert_eq!(Falcon512::PUBKEY_SIZE, 897);
    }

    #[test]
    fn test_falcon1024_sizes() {
        assert_eq!(Falcon1024::LOGN, 10);
        assert_eq!(Falcon1024::N, 1024);
        assert_eq!(Falcon1024::PRIVKEY_SIZE, 2305);
        assert_eq!(Falcon1024::PUBKEY_SIZE, 1793);
    }
}
