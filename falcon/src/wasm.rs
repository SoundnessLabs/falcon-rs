//! WASM bindings for Falcon signature scheme.
//!
//! This module provides JavaScript-friendly wrappers around the Falcon API.

use wasm_bindgen::prelude::*;

use crate::{Falcon1024, Falcon512, FalconParams, KeyPair, PublicKey, Signature, SignatureFormat};

/// A Falcon-512 key pair for use in JavaScript.
#[wasm_bindgen]
pub struct Falcon512KeyPair {
    inner: KeyPair<Falcon512>,
}

#[wasm_bindgen]
impl Falcon512KeyPair {
    /// Generate a new key pair from a 48-byte seed.
    ///
    /// The seed should be generated using `crypto.getRandomValues()` in JavaScript:
    /// ```js
    /// const seed = crypto.getRandomValues(new Uint8Array(48));
    /// const keypair = new Falcon512KeyPair(seed);
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> Result<Falcon512KeyPair, JsError> {
        let inner = KeyPair::<Falcon512>::generate_from_seed(seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    /// Get the public key bytes.
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().as_bytes().to_vec()
    }

    /// Get the private key bytes.
    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.private_key().as_bytes().to_vec()
    }

    /// Sign a message with the private key.
    ///
    /// Returns the signature bytes.
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = self
            .inner
            .sign_with_seed(message, SignatureFormat::Compressed, seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Sign a message with padded signature format.
    #[wasm_bindgen(js_name = signPadded)]
    pub fn sign_padded(&self, message: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = self
            .inner
            .sign_with_seed(message, SignatureFormat::Padded, seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Verify a signature over a message.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        let sig = Signature::<Falcon512>::from_bytes(signature)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        self.inner
            .public_key()
            .verify(message, &sig)
            .map_err(|e| JsError::new(&format!("{:?}", e)))
    }
}

/// A Falcon-512 public key for verification only.
#[wasm_bindgen]
pub struct Falcon512PublicKey {
    inner: PublicKey<Falcon512>,
}

#[wasm_bindgen]
impl Falcon512PublicKey {
    /// Create a public key from raw bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Falcon512PublicKey, JsError> {
        let inner = PublicKey::<Falcon512>::from_bytes(bytes)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    /// Verify a signature over a message.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        let sig = Signature::<Falcon512>::from_bytes(signature)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        self.inner
            .verify(message, &sig)
            .map_err(|e| JsError::new(&format!("{:?}", e)))
    }

    /// Get the public key as bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

/// A Falcon-1024 key pair for use in JavaScript.
#[wasm_bindgen]
pub struct Falcon1024KeyPair {
    inner: KeyPair<Falcon1024>,
}

#[wasm_bindgen]
impl Falcon1024KeyPair {
    /// Generate a new key pair from a 48-byte seed.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> Result<Falcon1024KeyPair, JsError> {
        let inner = KeyPair::<Falcon1024>::generate_from_seed(seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    /// Get the public key bytes.
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().as_bytes().to_vec()
    }

    /// Get the private key bytes.
    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.private_key().as_bytes().to_vec()
    }

    /// Sign a message with the private key.
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = self
            .inner
            .sign_with_seed(message, SignatureFormat::Compressed, seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Sign a message with padded signature format.
    #[wasm_bindgen(js_name = signPadded)]
    pub fn sign_padded(&self, message: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig = self
            .inner
            .sign_with_seed(message, SignatureFormat::Padded, seed)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Verify a signature over a message.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        let sig = Signature::<Falcon1024>::from_bytes(signature)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        self.inner
            .public_key()
            .verify(message, &sig)
            .map_err(|e| JsError::new(&format!("{:?}", e)))
    }
}

/// A Falcon-1024 public key for verification only.
#[wasm_bindgen]
pub struct Falcon1024PublicKey {
    inner: PublicKey<Falcon1024>,
}

#[wasm_bindgen]
impl Falcon1024PublicKey {
    /// Create a public key from raw bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<Falcon1024PublicKey, JsError> {
        let inner = PublicKey::<Falcon1024>::from_bytes(bytes)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        Ok(Self { inner })
    }

    /// Verify a signature over a message.
    #[wasm_bindgen]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        let sig = Signature::<Falcon1024>::from_bytes(signature)
            .map_err(|e| JsError::new(&format!("{:?}", e)))?;
        self.inner
            .verify(message, &sig)
            .map_err(|e| JsError::new(&format!("{:?}", e)))
    }

    /// Get the public key as bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

/// Get the public key size for Falcon-512.
#[wasm_bindgen(js_name = falcon512PublicKeySize)]
pub fn falcon512_public_key_size() -> usize {
    Falcon512::PUBKEY_SIZE
}

/// Get the private key size for Falcon-512.
#[wasm_bindgen(js_name = falcon512PrivateKeySize)]
pub fn falcon512_private_key_size() -> usize {
    Falcon512::PRIVKEY_SIZE
}

/// Get the public key size for Falcon-1024.
#[wasm_bindgen(js_name = falcon1024PublicKeySize)]
pub fn falcon1024_public_key_size() -> usize {
    Falcon1024::PUBKEY_SIZE
}

/// Get the private key size for Falcon-1024.
#[wasm_bindgen(js_name = falcon1024PrivateKeySize)]
pub fn falcon1024_private_key_size() -> usize {
    Falcon1024::PRIVKEY_SIZE
}
