//! SHAKE256-based PRNG wrapper.
//!
//! This module provides a wrapper around the Falcon library's internal
//! SHAKE256 context, used as a pseudorandom number generator (PRNG).

use falcon_sys as ffi;

/// A SHAKE256 context configured as a PRNG.
///
/// This wraps the Falcon library's internal SHAKE256 PRNG, which is used
/// for both key generation and signature generation.
///
/// # Example
///
/// ```
/// use falcon::Shake256Rng;
///
/// // Create from a seed
/// let seed = [0x42u8; 48];
/// let mut rng = Shake256Rng::from_seed(&seed);
///
/// // Extract random bytes
/// let mut buffer = [0u8; 32];
/// rng.fill_bytes(&mut buffer);
/// ```
pub struct Shake256Rng {
    ctx: ffi::shake256_context,
}

impl Shake256Rng {
    /// Create a new PRNG from a seed.
    ///
    /// The seed should be at least 48 bytes of high-quality entropy for
    /// cryptographic security. Shorter seeds are accepted but not recommended.
    ///
    /// This operation is deterministic: the same seed always produces the
    /// same sequence of random bytes.
    #[inline]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut ctx = ffi::shake256_context::default();
        unsafe {
            ffi::shake256_init_prng_from_seed(&mut ctx, seed.as_ptr(), seed.len());
        }
        Self { ctx }
    }

    /// Get a mutable pointer to the underlying context.
    ///
    /// This is for internal use by the FFI layer.
    #[inline]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::shake256_context {
        &mut self.ctx
    }

    /// Extract random bytes from the PRNG.
    ///
    /// This can be called any number of times to extract arbitrary amounts
    /// of pseudorandom data.
    #[inline]
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            ffi::shake256_extract(&mut self.ctx, dest.as_mut_ptr(), dest.len());
        }
    }

    /// Extract a single random byte.
    #[inline]
    pub fn next_u8(&mut self) -> u8 {
        let mut bytes = [0u8; 1];
        self.fill_bytes(&mut bytes);
        bytes[0]
    }

    /// Extract a random u32.
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Extract a random u64.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

impl Clone for Shake256Rng {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

// Implement rand_core traits for interoperability
impl rand_core::RngCore for Shake256Rng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        Shake256Rng::next_u32(self)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        Shake256Rng::next_u64(self)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Shake256Rng::fill_bytes(self, dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// SHAKE256-based PRNG is cryptographically secure
impl rand_core::CryptoRng for Shake256Rng {}

/// A raw SHAKE256 hasher for direct hashing operations.
///
/// This is useful for implementing the streaming signature API
/// or for other hashing needs.
pub struct Shake256 {
    ctx: ffi::shake256_context,
    flipped: bool,
}

impl Shake256 {
    /// Create a new SHAKE256 context.
    #[inline]
    pub fn new() -> Self {
        let mut ctx = ffi::shake256_context::default();
        unsafe {
            ffi::shake256_init(&mut ctx);
        }
        Self { ctx, flipped: false }
    }

    /// Absorb data into the hash state.
    ///
    /// This can be called multiple times before finalizing.
    ///
    /// # Panics
    /// Panics if called after [`flip`](Self::flip) has been called.
    #[inline]
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.flipped, "Cannot absorb after flip");
        unsafe {
            ffi::shake256_inject(&mut self.ctx, data.as_ptr(), data.len());
        }
    }

    /// Transition from absorbing to squeezing mode.
    ///
    /// After this call, [`absorb`](Self::absorb) can no longer be called,
    /// but [`squeeze`](Self::squeeze) can be used to extract output.
    #[inline]
    pub fn flip(&mut self) {
        if !self.flipped {
            unsafe {
                ffi::shake256_flip(&mut self.ctx);
            }
            self.flipped = true;
        }
    }

    /// Extract output bytes from the hash state.
    ///
    /// This can be called multiple times to extract arbitrary amounts of output.
    ///
    /// # Panics
    /// Panics if called before [`flip`](Self::flip) has been called.
    #[inline]
    pub fn squeeze(&mut self, dest: &mut [u8]) {
        assert!(self.flipped, "Must call flip before squeeze");
        unsafe {
            ffi::shake256_extract(&mut self.ctx, dest.as_mut_ptr(), dest.len());
        }
    }

    /// Hash data and return a fixed-size output.
    ///
    /// This is a convenience method that absorbs the data, flips,
    /// and squeezes the requested number of bytes.
    pub fn hash<const N: usize>(data: &[u8]) -> [u8; N] {
        let mut hasher = Self::new();
        hasher.absorb(data);
        hasher.flip();
        let mut output = [0u8; N];
        hasher.squeeze(&mut output);
        output
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_rng_deterministic() {
        let seed = [0x42u8; 48];

        let mut rng1 = Shake256Rng::from_seed(&seed);
        let mut rng2 = Shake256Rng::from_seed(&seed);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_shake256_hash() {
        let data = b"test data";
        let hash1: [u8; 32] = Shake256::hash(data);
        let hash2: [u8; 32] = Shake256::hash(data);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]); // Should not be all zeros
    }

    #[test]
    fn test_shake256_streaming() {
        let mut hasher = Shake256::new();
        hasher.absorb(b"hello ");
        hasher.absorb(b"world");
        hasher.flip();

        let mut output1 = [0u8; 32];
        hasher.squeeze(&mut output1);

        // Compare with single-shot hash
        let output2: [u8; 32] = Shake256::hash(b"hello world");

        assert_eq!(output1, output2);
    }
}
