//! Raw FFI bindings to the Falcon post-quantum signature library.
//!
//! This crate provides unsafe, low-level bindings. Users should prefer
//! the safe `falcon` crate wrapper.

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::c_int;

// ============================================================================
// Constants
// ============================================================================

/// Error: Random number generation failed
pub const FALCON_ERR_RANDOM: c_int = -1;
/// Error: Buffer too small
pub const FALCON_ERR_SIZE: c_int = -2;
/// Error: Invalid format in key or signature
pub const FALCON_ERR_FORMAT: c_int = -3;
/// Error: Signature verification failed
pub const FALCON_ERR_BADSIG: c_int = -4;
/// Error: Invalid argument
pub const FALCON_ERR_BADARG: c_int = -5;
/// Error: Internal error (should not happen)
pub const FALCON_ERR_INTERNAL: c_int = -6;

/// Signature type: Variable-length compressed format
pub const FALCON_SIG_COMPRESSED: c_int = 1;
/// Signature type: Fixed-length padded format
pub const FALCON_SIG_PADDED: c_int = 2;
/// Signature type: Constant-time format
pub const FALCON_SIG_CT: c_int = 3;

// ============================================================================
// Size calculation functions (const fn equivalents of C macros)
// ============================================================================

/// Private key size for a given logn (1-10).
#[inline]
pub const fn privkey_size(logn: u32) -> usize {
    if logn <= 3 {
        ((3u32 << logn) + 1) as usize
    } else {
        (((10 - (logn >> 1)) << (logn - 2)) + (1 << logn) + 1) as usize
    }
}

/// Public key size for a given logn (1-10).
#[inline]
pub const fn pubkey_size(logn: u32) -> usize {
    if logn <= 1 {
        5
    } else {
        ((7u32 << (logn - 2)) + 1) as usize
    }
}

/// Maximum compressed signature size for a given logn.
#[inline]
pub const fn sig_compressed_maxsize(logn: u32) -> usize {
    (((((11u32 << logn) + (101u32 >> (10 - logn))) + 7) >> 3) + 41) as usize
}

/// Padded signature size (exact) for a given logn.
#[inline]
pub const fn sig_padded_size(logn: u32) -> usize {
    let shift = 10 - logn;
    (44 + 3 * (256 >> shift) + 2 * (128 >> shift)
        + 3 * (64 >> shift) + 2 * (16 >> shift)
        - 2 * (2 >> shift) - 8 * (1 >> shift)) as usize
}

/// CT signature size (exact) for a given logn.
#[inline]
pub const fn sig_ct_size(logn: u32) -> usize {
    let base = 3u32 << (logn - 1);
    let adj = if logn == 3 { 1 } else { 0 };
    (base - adj + 41) as usize
}

/// Temporary buffer size for key generation.
#[inline]
pub const fn tmpsize_keygen(logn: u32) -> usize {
    if logn <= 3 {
        (272u32 + (3u32 << logn) + 7) as usize
    } else {
        ((28u32 << logn) + (3u32 << logn) + 7) as usize
    }
}

/// Temporary buffer size for making public key from private.
#[inline]
pub const fn tmpsize_makepub(logn: u32) -> usize {
    ((6u32 << logn) + 1) as usize
}

/// Temporary buffer size for signature (dynamic).
#[inline]
pub const fn tmpsize_signdyn(logn: u32) -> usize {
    ((78u32 << logn) + 7) as usize
}

/// Temporary buffer size for signature (tree/expanded key).
#[inline]
pub const fn tmpsize_signtree(logn: u32) -> usize {
    ((50u32 << logn) + 7) as usize
}

/// Temporary buffer size for expanding private key.
#[inline]
pub const fn tmpsize_expandpriv(logn: u32) -> usize {
    ((52u32 << logn) + 7) as usize
}

/// Expanded key size.
#[inline]
pub const fn expandedkey_size(logn: u32) -> usize {
    (((8 * logn + 40) << logn) + 8) as usize
}

/// Temporary buffer size for verification.
#[inline]
pub const fn tmpsize_verify(logn: u32) -> usize {
    ((8u32 << logn) + 1) as usize
}

// ============================================================================
// Types
// ============================================================================

/// SHAKE256 context. Opaque structure (208 bytes = 26 * 8).
#[repr(C)]
#[derive(Clone)]
pub struct shake256_context {
    pub opaque_contents: [u64; 26],
}

impl Default for shake256_context {
    fn default() -> Self {
        Self {
            opaque_contents: [0u64; 26],
        }
    }
}

// ============================================================================
// FFI Functions
// ============================================================================

extern "C" {
    // ------------------------------------------------------------------------
    // SHAKE256 functions
    // ------------------------------------------------------------------------

    /// Initialize a SHAKE256 context to its initial state.
    pub fn shake256_init(sc: *mut shake256_context);

    /// Inject data bytes into the SHAKE256 context ("absorb" operation).
    pub fn shake256_inject(sc: *mut shake256_context, data: *const u8, len: usize);

    /// Flip the SHAKE256 state to output mode.
    pub fn shake256_flip(sc: *mut shake256_context);

    /// Extract bytes from the SHAKE256 context ("squeeze" operation).
    pub fn shake256_extract(sc: *mut shake256_context, out: *mut u8, len: usize);

    /// Initialize a SHAKE256 context as a PRNG from a seed.
    pub fn shake256_init_prng_from_seed(
        sc: *mut shake256_context,
        seed: *const u8,
        seed_len: usize,
    );

    /// Initialize a SHAKE256 context as a PRNG from system RNG.
    /// Returns 0 on success, negative error code on failure.
    pub fn shake256_init_prng_from_system(sc: *mut shake256_context) -> c_int;

    // ------------------------------------------------------------------------
    // Key generation
    // ------------------------------------------------------------------------

    /// Generate a new key pair.
    ///
    /// # Arguments
    /// * `rng` - SHAKE256 context in output mode for randomness
    /// * `logn` - Logarithm of degree (9 for Falcon-512, 10 for Falcon-1024)
    /// * `privkey` - Buffer for private key output
    /// * `privkey_len` - Size of privkey buffer
    /// * `pubkey` - Buffer for public key output (may be NULL)
    /// * `pubkey_len` - Size of pubkey buffer
    /// * `tmp` - Temporary buffer
    /// * `tmp_len` - Size of temporary buffer
    ///
    /// # Returns
    /// 0 on success, negative error code on failure.
    pub fn falcon_keygen_make(
        rng: *mut shake256_context,
        logn: c_int,
        privkey: *mut u8,
        privkey_len: usize,
        pubkey: *mut u8,
        pubkey_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Recompute the public key from the private key.
    pub fn falcon_make_public(
        pubkey: *mut u8,
        pubkey_len: usize,
        privkey: *const u8,
        privkey_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Get the Falcon degree (logn) from an encoded key or signature.
    pub fn falcon_get_logn(obj: *const u8, len: usize) -> c_int;

    // ------------------------------------------------------------------------
    // Signing
    // ------------------------------------------------------------------------

    /// Sign data with the private key (dynamic computation).
    ///
    /// # Arguments
    /// * `rng` - SHAKE256 context in output mode for randomness
    /// * `sig` - Buffer for signature output
    /// * `sig_len` - Pointer to size (input: max size, output: actual size)
    /// * `sig_type` - Signature format (COMPRESSED, PADDED, or CT)
    /// * `privkey` - Private key bytes
    /// * `privkey_len` - Private key length
    /// * `data` - Message data to sign
    /// * `data_len` - Message length
    /// * `tmp` - Temporary buffer
    /// * `tmp_len` - Size of temporary buffer
    ///
    /// # Returns
    /// 0 on success, negative error code on failure.
    pub fn falcon_sign_dyn(
        rng: *mut shake256_context,
        sig: *mut u8,
        sig_len: *mut usize,
        sig_type: c_int,
        privkey: *const u8,
        privkey_len: usize,
        data: *const u8,
        data_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Expand a private key for faster repeated signing.
    pub fn falcon_expand_privkey(
        expanded_key: *mut u8,
        expanded_key_len: usize,
        privkey: *const u8,
        privkey_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Sign data using an expanded private key.
    pub fn falcon_sign_tree(
        rng: *mut shake256_context,
        sig: *mut u8,
        sig_len: *mut usize,
        sig_type: c_int,
        expanded_key: *const u8,
        data: *const u8,
        data_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    // ------------------------------------------------------------------------
    // Streamed signing API
    // ------------------------------------------------------------------------

    /// Start a signature generation context.
    pub fn falcon_sign_start(
        rng: *mut shake256_context,
        nonce: *mut u8,
        hash_data: *mut shake256_context,
    ) -> c_int;

    /// Finish signature generation with dynamic key.
    pub fn falcon_sign_dyn_finish(
        rng: *mut shake256_context,
        sig: *mut u8,
        sig_len: *mut usize,
        sig_type: c_int,
        privkey: *const u8,
        privkey_len: usize,
        hash_data: *mut shake256_context,
        nonce: *const u8,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Finish signature generation with expanded key.
    pub fn falcon_sign_tree_finish(
        rng: *mut shake256_context,
        sig: *mut u8,
        sig_len: *mut usize,
        sig_type: c_int,
        expanded_key: *const u8,
        hash_data: *mut shake256_context,
        nonce: *const u8,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    // ------------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------------

    /// Verify a signature over data.
    ///
    /// # Arguments
    /// * `sig` - Signature bytes
    /// * `sig_len` - Signature length
    /// * `sig_type` - Expected signature format (0 to auto-detect)
    /// * `pubkey` - Public key bytes
    /// * `pubkey_len` - Public key length
    /// * `data` - Message data
    /// * `data_len` - Message length
    /// * `tmp` - Temporary buffer
    /// * `tmp_len` - Size of temporary buffer
    ///
    /// # Returns
    /// 0 on success, FALCON_ERR_BADSIG if signature is invalid,
    /// other negative error code on other failures.
    pub fn falcon_verify(
        sig: *const u8,
        sig_len: usize,
        sig_type: c_int,
        pubkey: *const u8,
        pubkey_len: usize,
        data: *const u8,
        data_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;

    /// Start a streamed signature verification.
    pub fn falcon_verify_start(
        hash_data: *mut shake256_context,
        sig: *const u8,
        sig_len: usize,
    ) -> c_int;

    /// Finish a streamed signature verification.
    pub fn falcon_verify_finish(
        sig: *const u8,
        sig_len: usize,
        sig_type: c_int,
        pubkey: *const u8,
        pubkey_len: usize,
        hash_data: *mut shake256_context,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> c_int;
}

// ============================================================================
// Internal FFI Functions (for NIST KAT testing)
// ============================================================================
//
// These functions bypass the public API and provide direct access to
// internal Falcon operations. They are needed for byte-exact NIST KAT
// reproduction.

/// Internal SHAKE256 context (same layout as shake256_context but
/// used by internal functions).
pub type inner_shake256_context = shake256_context;

extern "C" {
    // ------------------------------------------------------------------------
    // Internal SHAKE256 functions
    // ------------------------------------------------------------------------

    /// Initialize internal SHAKE256 context.
    pub fn falcon_inner_i_shake256_init(sc: *mut inner_shake256_context);

    /// Inject data into internal SHAKE256 context.
    pub fn falcon_inner_i_shake256_inject(
        sc: *mut inner_shake256_context,
        data: *const u8,
        len: usize,
    );

    /// Flip internal SHAKE256 context to output mode.
    pub fn falcon_inner_i_shake256_flip(sc: *mut inner_shake256_context);

    /// Extract output from internal SHAKE256 context.
    pub fn falcon_inner_i_shake256_extract(
        sc: *mut inner_shake256_context,
        out: *mut u8,
        len: usize,
    );

    // ------------------------------------------------------------------------
    // Internal key generation
    // ------------------------------------------------------------------------

    /// Generate raw key polynomials.
    ///
    /// # Arguments
    /// * `rng` - Internal SHAKE256 context in output mode
    /// * `f` - Output buffer for f polynomial (n int8_t)
    /// * `g` - Output buffer for g polynomial (n int8_t)
    /// * `F` - Output buffer for F polynomial (n int8_t)
    /// * `G` - Output buffer for G polynomial (n int8_t, can be computed from others)
    /// * `h` - Output buffer for public key polynomial (n uint16_t)
    /// * `logn` - Degree logarithm (9 or 10)
    /// * `tmp` - Temporary buffer (must be 64-bit aligned)
    pub fn falcon_inner_keygen(
        rng: *mut inner_shake256_context,
        f: *mut i8,
        g: *mut i8,
        F: *mut i8,
        G: *mut i8,
        h: *mut u16,
        logn: u32,
        tmp: *mut u8,
    );

    // ------------------------------------------------------------------------
    // Internal signing
    // ------------------------------------------------------------------------

    /// Hash message to polynomial point (variable time).
    ///
    /// The SHAKE256 context must already be flipped (in output mode).
    pub fn falcon_inner_hash_to_point_vartime(
        sc: *mut inner_shake256_context,
        x: *mut u16,
        logn: u32,
    );

    /// Hash message to polynomial point (constant time).
    ///
    /// tmp[] must have room for 2*2^logn bytes.
    pub fn falcon_inner_hash_to_point_ct(
        sc: *mut inner_shake256_context,
        x: *mut u16,
        logn: u32,
        tmp: *mut u8,
    );

    /// Sign with raw key components (dynamic computation).
    ///
    /// # Arguments
    /// * `sig` - Output buffer for raw signature (n int16_t)
    /// * `rng` - SHAKE256 context in output mode for randomness
    /// * `f`, `g`, `F`, `G` - Raw key polynomials
    /// * `hm` - Hashed message (n uint16_t from hash_to_point)
    /// * `logn` - Degree logarithm
    /// * `tmp` - Temporary buffer (72*2^logn bytes, 64-bit aligned)
    pub fn falcon_inner_sign_dyn(
        sig: *mut i16,
        rng: *mut inner_shake256_context,
        f: *const i8,
        g: *const i8,
        F: *const i8,
        G: *const i8,
        hm: *const u16,
        logn: u32,
        tmp: *mut u8,
    );

    /// Sign with expanded key (tree form).
    pub fn falcon_inner_sign_tree(
        sig: *mut i16,
        rng: *mut inner_shake256_context,
        expanded_key: *const u64, // fpr is 64-bit
        hm: *const u16,
        logn: u32,
        tmp: *mut u8,
    );

    /// Expand private key to tree form.
    pub fn falcon_inner_expand_privkey(
        expanded_key: *mut u64, // fpr is 64-bit
        f: *const i8,
        g: *const i8,
        F: *const i8,
        G: *const i8,
        logn: u32,
        tmp: *mut u8,
    );

    // ------------------------------------------------------------------------
    // Internal encoding functions
    // ------------------------------------------------------------------------

    /// Encode public key polynomial (modq encoding).
    ///
    /// Returns number of bytes written, or 0 on error.
    pub fn falcon_inner_modq_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const u16,
        logn: u32,
    ) -> usize;

    /// Encode signed 8-bit coefficients with specified bit width.
    ///
    /// Returns number of bytes written, or 0 on error.
    pub fn falcon_inner_trim_i8_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i8,
        logn: u32,
        bits: u32,
    ) -> usize;

    /// Encode signed 16-bit coefficients with specified bit width.
    pub fn falcon_inner_trim_i16_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i16,
        logn: u32,
        bits: u32,
    ) -> usize;

    /// Compress-encode a signature.
    ///
    /// Returns number of bytes written, or 0 on error.
    pub fn falcon_inner_comp_encode(
        out: *mut u8,
        max_out_len: usize,
        x: *const i16,
        logn: u32,
    ) -> usize;

    /// Decode modq-encoded polynomial.
    pub fn falcon_inner_modq_decode(
        x: *mut u16,
        logn: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;

    /// Decode compressed signature.
    pub fn falcon_inner_comp_decode(
        x: *mut i16,
        logn: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;

    // ------------------------------------------------------------------------
    // Internal verification
    // ------------------------------------------------------------------------

    /// Verify signature against raw public key polynomial.
    ///
    /// The public key h must already be in NTT+Montgomery form.
    /// Returns 1 if valid, 0 if invalid.
    pub fn falcon_inner_verify_raw(
        c0: *const u16,
        s2: *const i16,
        h: *const u16,
        logn: u32,
        tmp: *mut u8,
    ) -> c_int;

    /// Convert public key to NTT+Montgomery form.
    pub fn falcon_inner_to_ntt_monty(h: *mut u16, logn: u32);
}

/// Maximum bits for f and g coefficients, indexed by logn.
/// Access: `max_fg_bits[logn]` for logn in 1..=10.
#[link(name = "falcon")]
extern "C" {
    #[link_name = "falcon_inner_max_fg_bits"]
    pub static max_fg_bits: [u8; 11];

    #[link_name = "falcon_inner_max_FG_bits"]
    pub static max_FG_bits: [u8; 11];

    #[link_name = "falcon_inner_max_sig_bits"]
    pub static max_sig_bits: [u8; 11];
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants_falcon512() {
        // Falcon-512: logn = 9
        assert_eq!(privkey_size(9), 1281);
        assert_eq!(pubkey_size(9), 897);
        assert_eq!(tmpsize_keygen(9), 15879);
        assert_eq!(tmpsize_signdyn(9), 39943);
        assert_eq!(tmpsize_verify(9), 4097);
    }

    #[test]
    fn test_size_constants_falcon1024() {
        // Falcon-1024: logn = 10
        assert_eq!(privkey_size(10), 2305);
        assert_eq!(pubkey_size(10), 1793);
        assert_eq!(tmpsize_keygen(10), 31751);
        assert_eq!(tmpsize_signdyn(10), 79879);
        assert_eq!(tmpsize_verify(10), 8193);
    }
}
