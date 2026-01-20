//! Key pair types: private key, public key, and expanded private key.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use falcon_sys as ffi;

use crate::{Error, FalconParams, Result, Shake256Rng, Signature, SignatureFormat};

/// A Falcon key pair containing both private and public keys.
///
/// # Example
///
/// ```
/// use falcon::{Falcon512, KeyPair, SignatureFormat};
///
/// // Generate a key pair from a seed
/// let seed = [0x42u8; 48];
/// let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed).unwrap();
///
/// // Sign a message
/// let message = b"Hello, Falcon!";
/// let signature = keypair.sign_with_seed(message, SignatureFormat::Compressed, &seed).unwrap();
///
/// // Verify the signature
/// assert!(keypair.public_key().verify(message, &signature).unwrap());
/// ```
pub struct KeyPair<P: FalconParams> {
    private_key: PrivateKey<P>,
    public_key: PublicKey<P>,
}

impl<P: FalconParams> KeyPair<P> {
    /// Generate a new key pair from a cryptographic RNG.
    ///
    /// The RNG must provide at least 48 bytes of high-quality entropy.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use falcon::{Falcon512, KeyPair};
    ///
    /// let keypair = KeyPair::<Falcon512>::generate(&mut rand::thread_rng()).unwrap();
    /// ```
    #[cfg(feature = "std")]
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);
        let result = Self::generate_from_seed(&seed);
        // Zeroize seed
        seed.iter_mut().for_each(|b| *b = 0);
        result
    }

    /// Generate a key pair from a 48-byte seed.
    ///
    /// This is deterministic: the same seed always produces the same key pair.
    /// This is useful for:
    /// - Reproducible testing
    /// - Key derivation from a master secret
    /// - WASM environments where you inject entropy from JavaScript
    pub fn generate_from_seed(seed: &[u8]) -> Result<Self> {
        let mut shake_rng = Shake256Rng::from_seed(seed);

        let mut privkey = vec![0u8; P::PRIVKEY_SIZE];
        let mut pubkey = vec![0u8; P::PUBKEY_SIZE];
        let mut tmp = vec![0u8; P::TMPSIZE_KEYGEN];

        let result = unsafe {
            ffi::falcon_keygen_make(
                shake_rng.as_mut_ptr(),
                P::LOGN as i32,
                privkey.as_mut_ptr(),
                privkey.len(),
                pubkey.as_mut_ptr(),
                pubkey.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        // Zeroize temporary buffer
        tmp.iter_mut().for_each(|b| *b = 0);

        if let Some(err) = Error::from_code(result) {
            return Err(err);
        }

        Ok(Self {
            private_key: PrivateKey {
                data: privkey,
                _params: PhantomData,
            },
            public_key: PublicKey {
                data: pubkey,
                _params: PhantomData,
            },
        })
    }

    /// Get a reference to the private key.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey<P> {
        &self.private_key
    }

    /// Get a reference to the public key.
    #[inline]
    pub fn public_key(&self) -> &PublicKey<P> {
        &self.public_key
    }

    /// Consume the key pair and return the private key.
    #[inline]
    pub fn into_private_key(self) -> PrivateKey<P> {
        self.private_key
    }

    /// Consume the key pair and return both keys.
    #[inline]
    pub fn into_keys(self) -> (PrivateKey<P>, PublicKey<P>) {
        (self.private_key, self.public_key)
    }

    /// Sign a message using the private key with a seed for randomness.
    ///
    /// The seed provides the randomness needed for signature generation.
    /// Different seeds produce different (but equally valid) signatures.
    #[inline]
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        format: SignatureFormat,
        seed: &[u8],
    ) -> Result<Signature<P>> {
        self.private_key.sign_with_seed(message, format, seed)
    }

    /// Sign a message using the private key with explicit RNG.
    #[cfg(feature = "std")]
    #[inline]
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        format: SignatureFormat,
        rng: &mut R,
    ) -> Result<Signature<P>> {
        self.private_key.sign(message, format, rng)
    }
}

impl<P: FalconParams> Clone for KeyPair<P> {
    fn clone(&self) -> Self {
        Self {
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

/// A Falcon private key.
///
/// Private keys should be kept secret. When dropped, the key material
/// is zeroized to prevent leakage.
pub struct PrivateKey<P: FalconParams> {
    data: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: FalconParams> PrivateKey<P> {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidFormat`] if the bytes don't represent a valid
    /// private key for the parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::PRIVKEY_SIZE {
            return Err(Error::InvalidFormat);
        }

        // Verify header byte: 0x50 + logn for private keys
        let expected_header = 0x50 + P::LOGN as u8;
        if bytes[0] != expected_header {
            return Err(Error::InvalidFormat);
        }

        Ok(Self {
            data: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Get the raw bytes of this private key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Derive the public key from this private key.
    ///
    /// This recomputes the public key from the private key components.
    pub fn public_key(&self) -> Result<PublicKey<P>> {
        let mut pubkey = vec![0u8; P::PUBKEY_SIZE];
        let mut tmp = vec![0u8; P::TMPSIZE_MAKEPUB];

        let result = unsafe {
            ffi::falcon_make_public(
                pubkey.as_mut_ptr(),
                pubkey.len(),
                self.data.as_ptr(),
                self.data.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        tmp.iter_mut().for_each(|b| *b = 0);

        if let Some(err) = Error::from_code(result) {
            return Err(err);
        }

        Ok(PublicKey {
            data: pubkey,
            _params: PhantomData,
        })
    }

    /// Sign a message with randomness from the provided seed.
    ///
    /// The seed is used to initialize a SHAKE256-based PRNG that provides
    /// the randomness needed for signature generation.
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        format: SignatureFormat,
        seed: &[u8],
    ) -> Result<Signature<P>> {
        let mut shake_rng = Shake256Rng::from_seed(seed);

        let max_sig_len = format.max_size::<P>();

        let mut sig = vec![0u8; max_sig_len];
        let mut sig_len = max_sig_len;
        let mut tmp = vec![0u8; P::TMPSIZE_SIGNDYN];

        let result = unsafe {
            ffi::falcon_sign_dyn(
                shake_rng.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len,
                format.to_ffi(),
                self.data.as_ptr(),
                self.data.len(),
                message.as_ptr(),
                message.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        // Zeroize sensitive data
        tmp.iter_mut().for_each(|b| *b = 0);

        if let Some(err) = Error::from_code(result) {
            return Err(err);
        }

        sig.truncate(sig_len);
        Ok(Signature {
            data: sig,
            format,
            _params: PhantomData,
        })
    }

    /// Sign a message with explicit RNG.
    #[cfg(feature = "std")]
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        format: SignatureFormat,
        rng: &mut R,
    ) -> Result<Signature<P>> {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);
        let result = self.sign_with_seed(message, format, &seed);
        seed.iter_mut().for_each(|b| *b = 0);
        result
    }

    /// Expand this private key for faster repeated signing.
    ///
    /// The expanded form precomputes values needed for signing, reducing
    /// the per-signature cost by roughly half. However, it uses significantly
    /// more memory (about 8KB for Falcon-512, 16KB for Falcon-1024).
    pub fn expand(&self) -> Result<ExpandedPrivateKey<P>> {
        let mut expanded = vec![0u8; P::EXPANDEDKEY_SIZE];
        let mut tmp = vec![0u8; P::TMPSIZE_EXPANDPRIV];

        let result = unsafe {
            ffi::falcon_expand_privkey(
                expanded.as_mut_ptr(),
                expanded.len(),
                self.data.as_ptr(),
                self.data.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        tmp.iter_mut().for_each(|b| *b = 0);

        if let Some(err) = Error::from_code(result) {
            return Err(err);
        }

        Ok(ExpandedPrivateKey {
            data: expanded,
            _params: PhantomData,
        })
    }
}

impl<P: FalconParams> Clone for PrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: FalconParams> Drop for PrivateKey<P> {
    fn drop(&mut self) {
        // Zeroize private key on drop
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}

impl<P: FalconParams> core::fmt::Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// A Falcon public key.
///
/// Public keys can be freely shared and are used to verify signatures.
#[derive(Clone)]
pub struct PublicKey<P: FalconParams> {
    data: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: FalconParams> PublicKey<P> {
    /// Create from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidFormat`] if the bytes don't represent a valid
    /// public key for the parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::PUBKEY_SIZE {
            return Err(Error::InvalidFormat);
        }

        // Verify header byte: 0x00 + logn for public keys
        let expected_header = P::LOGN as u8;
        if bytes[0] != expected_header {
            return Err(Error::InvalidFormat);
        }

        Ok(Self {
            data: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Get the raw bytes of this public key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Convert the public key into raw bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Verify a signature over a message.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the signature is valid
    /// - `Ok(false)` if the signature is invalid
    /// - `Err(_)` if there was an error (malformed input, etc.)
    pub fn verify(&self, message: &[u8], signature: &Signature<P>) -> Result<bool> {
        let mut tmp = vec![0u8; P::TMPSIZE_VERIFY];

        let result = unsafe {
            ffi::falcon_verify(
                signature.data.as_ptr(),
                signature.data.len(),
                signature.format.to_ffi(),
                self.data.as_ptr(),
                self.data.len(),
                message.as_ptr(),
                message.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        match result {
            0 => Ok(true),
            -4 => Ok(false), // FALCON_ERR_BADSIG
            code => Err(Error::from_code(code).unwrap_or(Error::Internal)),
        }
    }

    /// Verify a signature, returning an error if invalid.
    ///
    /// This is a convenience method that converts `Ok(false)` to
    /// `Err(Error::BadSignature)`.
    pub fn verify_strict(&self, message: &[u8], signature: &Signature<P>) -> Result<()> {
        if self.verify(message, signature)? {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

impl<P: FalconParams> core::fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey")
            .field("len", &self.data.len())
            .finish()
    }
}

impl<P: FalconParams> AsRef<[u8]> for PublicKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// An expanded private key for faster repeated signing.
///
/// The expanded form precomputes values needed for signing, reducing
/// the per-signature cost by roughly half. However, it uses significantly
/// more memory than the regular private key format.
///
/// # Memory Usage
/// - Falcon-512: ~27,000 bytes (vs 1,281 for regular)
/// - Falcon-1024: ~54,000 bytes (vs 2,305 for regular)
pub struct ExpandedPrivateKey<P: FalconParams> {
    data: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: FalconParams> ExpandedPrivateKey<P> {
    /// Sign a message with randomness from the provided seed.
    pub fn sign_with_seed(
        &self,
        message: &[u8],
        format: SignatureFormat,
        seed: &[u8],
    ) -> Result<Signature<P>> {
        let mut shake_rng = Shake256Rng::from_seed(seed);

        let max_sig_len = format.max_size::<P>();

        let mut sig = vec![0u8; max_sig_len];
        let mut sig_len = max_sig_len;
        let mut tmp = vec![0u8; P::TMPSIZE_SIGNTREE];

        let result = unsafe {
            ffi::falcon_sign_tree(
                shake_rng.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len,
                format.to_ffi(),
                self.data.as_ptr(),
                message.as_ptr(),
                message.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            )
        };

        tmp.iter_mut().for_each(|b| *b = 0);

        if let Some(err) = Error::from_code(result) {
            return Err(err);
        }

        sig.truncate(sig_len);
        Ok(Signature {
            data: sig,
            format,
            _params: PhantomData,
        })
    }

    /// Sign a message with explicit RNG.
    #[cfg(feature = "std")]
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        message: &[u8],
        format: SignatureFormat,
        rng: &mut R,
    ) -> Result<Signature<P>> {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);
        let result = self.sign_with_seed(message, format, &seed);
        seed.iter_mut().for_each(|b| *b = 0);
        result
    }
}

impl<P: FalconParams> Drop for ExpandedPrivateKey<P> {
    fn drop(&mut self) {
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}

impl<P: FalconParams> core::fmt::Debug for ExpandedPrivateKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpandedPrivateKey")
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}
